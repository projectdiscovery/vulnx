//go:build darwin

package vulnx

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/v4/process"
)

func runtimeSocketCommand(ctx context.Context, args []string) ([]byte, bool, error) {
	return runRuntimeSocketCommand(ctx, "/usr/sbin/lsof", args)
}

func runRuntimeSocketCommand(ctx context.Context, executable string, args []string) ([]byte, bool, error) {
	cmd := newCommand(ctx, executable, args...)
	stdout, stderr := &cappedBuffer{limit: runtimeOutputLimit}, &cappedBuffer{limit: runtimeOutputLimit}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 && stdout.Len() == 0 && stderr.Len() == 0 && ctx.Err() == nil {
		err = nil
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	return stdout.Bytes(), stderr.Len() > 0 || stderr.Truncated() || stdout.Truncated(), err
}

func collectHostRuntime(ctx context.Context, r *HostRuntime) {
	r.Scope = "OS-visible sockets and permitted process metadata; not a complete system or external-reachability assessment"
	r.gap("coverage", 0, "protected or other-account sockets may be omitted by the operating system")
	started, err := time.Parse(time.RFC3339Nano, r.StartedAt)
	if err != nil {
		r.Status = "unavailable"
		r.gap("collection", 0, "invalid collection start time")
		return
	}
	success := false
	for _, selection := range [][]string{{"-iTCP", "-sTCP:LISTEN"}, {"-iUDP"}} {
		args := append([]string{"-b", "-w", "-nP", "-F0pufnPtTd"}, selection...)
		raw, warning, err := runtimeSocketCommand(ctx, args)
		if err != nil {
			r.gap("sockets", 0, fmt.Sprintf("socket enumeration failed: %v", err))
		} else {
			success = true
		}
		if warning {
			r.gap("sockets", 0, "socket enumeration reported warnings or exceeded the output limit")
		}
		endpoints, parseErr := parseRuntimeSockets(raw)
		if parseErr != nil {
			r.gap("sockets", 0, parseErr.Error())
		}
		r.Endpoints = append(r.Endpoints, endpoints...)
		if ctx.Err() != nil {
			break
		}
	}
	if !success && len(r.Endpoints) == 0 {
		r.Status = "unavailable"
	}
	seen := map[int]bool{}
	for _, e := range r.Endpoints {
		for _, pid := range e.Owners {
			if seen[pid] {
				continue
			}
			seen[pid] = true
			if ctx.Err() != nil {
				r.gap("process", pid, "collection deadline reached before process metadata could be read")
				r.Processes = append(r.Processes, HostProcess{PID: pid, Matches: []HostRuntimeMatch{}})
				continue
			}
			p, err := runtimeProcess(ctx, pid, started)
			if err != nil {
				r.gap("process", pid, err.Error())
			}
			r.Processes = append(r.Processes, p)
		}
	}
	verifyRuntimeImages(ctx, r)
	confirmRuntimeOwners(ctx, r)
}

func verifyRuntimeImages(ctx context.Context, r *HostRuntime) {
	for start := 0; start < len(r.Processes); start += 128 {
		end := min(start+128, len(r.Processes))
		var pids []string
		for _, p := range r.Processes[start:end] {
			if p.Executable != "" {
				pids = append(pids, strconv.Itoa(p.PID))
			}
		}
		if len(pids) == 0 {
			continue
		}
		raw, warning, err := runtimeSocketCommand(ctx, []string{"-b", "-w", "-nP", "-a", "-p", strings.Join(pids, ","), "-d", "txt", "-F0pfnDi"})
		if err != nil {
			r.gap("executable_identity", 0, fmt.Sprintf("mapped executable enumeration failed: %v", err))
		}
		if warning {
			r.gap("executable_identity", 0, "mapped executable enumeration reported warnings or exceeded the output limit")
		}
		images := parseRuntimeImages(raw)
		for i := start; i < end; i++ {
			p := &r.Processes[i]
			if p.Executable == "" {
				continue
			}
			valid := false
			if ctx.Err() == nil {
				current := &process.Process{Pid: int32(p.PID)}
				birth, birthErr := current.CreateTimeWithContext(ctx)
				exe, exeErr := current.ExeWithContext(ctx)
				if birthErr == nil && exeErr == nil && strconv.FormatInt(birth, 10) == p.Identity && exe == p.Executable {
					p.image = runtimeImageInfo(p.Executable, images[p.PID])
					valid = p.image != nil
				}
			}
			if !valid {
				p.Executable = ""
				r.gap("executable_identity", p.PID, "running executable could not be matched to the current on-disk file")
			}
		}
	}
}

func runtimeImageInfo(path string, images []runtimeImage) os.FileInfo {
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() {
		return nil
	}
	native, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	for _, image := range images {
		if image.path == path && image.device == uint64(uint32(native.Dev)) && image.inode == native.Ino {
			return st
		}
	}
	return nil
}

func runtimeProcess(ctx context.Context, pid int, started time.Time) (HostProcess, error) {
	out := HostProcess{PID: pid, Matches: []HostRuntimeMatch{}}
	before := &process.Process{Pid: int32(pid)}
	birth, err := before.CreateTimeWithContext(ctx)
	if err != nil {
		return out, fmt.Errorf("process identity unavailable: %w", err)
	}
	if birth > started.UnixMilli() {
		return out, fmt.Errorf("process started during collection; socket attribution not verified")
	}
	exe, exeErr := before.ExeWithContext(ctx)
	uids, uidErr := before.UidsWithContext(ctx)
	after := &process.Process{Pid: int32(pid)}
	endBirth, err := after.CreateTimeWithContext(ctx)
	if err != nil || endBirth != birth {
		return out, fmt.Errorf("process disappeared or identity changed during collection")
	}
	endExe, endErr := after.ExeWithContext(ctx)
	if exeErr == nil && (endErr != nil || endExe != exe) {
		return out, fmt.Errorf("process executable changed during collection")
	}
	out.Identity = strconv.FormatInt(birth, 10)
	if uidErr == nil && len(uids) > 0 {
		effective := uids[0]
		out.EffectiveUID = &effective
	}
	if exeErr == nil {
		if st, statErr := os.Stat(exe); statErr == nil && st.Mode().IsRegular() {
			out.Executable = exe
		} else {
			exeErr = fmt.Errorf("executable no longer resolves to a regular file")
		}
	}
	return out, errors.Join(exeErr, uidErr)
}

func confirmRuntimeOwners(ctx context.Context, r *HostRuntime) {
	var later []HostEndpoint
	for _, selection := range [][]string{{"-iTCP", "-sTCP:LISTEN"}, {"-iUDP"}} {
		raw, warning, err := runtimeSocketCommand(ctx, append([]string{"-b", "-w", "-nP", "-F0pufnPtTd"}, selection...))
		if err != nil || warning {
			r.gap("ownership", 0, "socket ownership confirmation was incomplete")
		}
		endpoints, parseErr := parseRuntimeSockets(raw)
		if parseErr != nil {
			r.gap("ownership", 0, parseErr.Error())
		}
		later = append(later, endpoints...)
	}
	stable := map[int]bool{}
	for _, p := range r.Processes {
		if ctx.Err() != nil {
			break
		}
		current := &process.Process{Pid: int32(p.PID)}
		birth, err := current.CreateTimeWithContext(ctx)
		if err != nil || strconv.FormatInt(birth, 10) != p.Identity {
			continue
		}
		if p.Executable != "" {
			path, err := current.ExeWithContext(ctx)
			if err != nil || path != p.Executable || !sameRuntimeImage(path, p.image) {
				continue
			}
		}
		stable[p.PID] = true
	}
	reconcileRuntimeOwners(r, later, stable)
}

func reconcileRuntimeOwners(r *HostRuntime, later []HostEndpoint, stable map[int]bool) {
	type key struct {
		protocol, family, address, socket string
		port                              uint16
	}
	observed := map[key]map[int]bool{}
	keyFor := func(e HostEndpoint) key { return key{e.Protocol, e.Family, e.Address, e.Socket, e.Port} }
	for _, e := range later {
		k := keyFor(e)
		if observed[k] == nil {
			observed[k] = map[int]bool{}
		}
		for _, pid := range e.Owners {
			observed[k][pid] = true
		}
	}
	kept := map[int]bool{}
	for i := range r.Endpoints {
		e := &r.Endpoints[i]
		owners := []int{}
		for _, pid := range e.Owners {
			if stable[pid] && observed[keyFor(*e)][pid] {
				owners = append(owners, pid)
				kept[pid] = true
			} else {
				r.gap("ownership", pid, "socket or process identity changed during collection")
			}
		}
		e.Owners = owners
	}
	processes := r.Processes[:0]
	for _, p := range r.Processes {
		if kept[p.PID] {
			processes = append(processes, p)
		}
	}
	r.Processes = processes
}
