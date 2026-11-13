package vulnx

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const runtimeProcLimit = 8 << 20
const runtimeProcEntries = 65536

type runtimeProcIO struct {
	readFile func(string) ([]byte, error)
	readlink func(string) (string, error)
	readDir  func(context.Context, string) ([]os.DirEntry, error)
	stat     func(string) (os.FileInfo, error)
}

func runtimeProcFiles() runtimeProcIO {
	return runtimeProcIO{readFile: runtimeProcReadFile, readlink: os.Readlink, readDir: runtimeProcReadDir, stat: os.Stat}
}

func runtimeProcReadFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(f, runtimeProcLimit+1))
	closeErr := f.Close()
	if len(raw) > runtimeProcLimit {
		return nil, errors.New("process file exceeds collection limit")
	}
	return raw, errors.Join(readErr, closeErr)
}

func runtimeProcReadDir(ctx context.Context, path string) ([]os.DirEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	var out []os.DirEntry
	var readErr error
	for {
		if err := ctx.Err(); err != nil {
			readErr = err
			break
		}
		entries, err := f.ReadDir(256)
		out = append(out, entries...)
		if len(out) > runtimeProcEntries {
			out = out[:runtimeProcEntries]
			readErr = errors.New("process directory exceeds collection limit")
			break
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				readErr = err
			}
			break
		}
	}
	return out, errors.Join(readErr, f.Close())
}

func collectRuntimeProc(ctx context.Context, r *HostRuntime, root string, fs runtimeProcIO) {
	r.Scope = "current network namespace; readable process ownership only; no external reachability checked"
	namespace, nsErr := fs.readlink(filepath.Join(root, "self/ns/net"))
	if nsErr != nil {
		r.gap("namespace", 0, nsErr.Error())
	} else {
		r.Scope += "; " + namespace
	}
	readTables := 0
	bySocket := map[string][]int{}
	for _, table := range []struct{ name, protocol, family string }{{"tcp", "tcp", "ipv4"}, {"tcp6", "tcp", "ipv6"}, {"udp", "udp", "ipv4"}, {"udp6", "udp", "ipv6"}} {
		if err := ctx.Err(); err != nil {
			r.gap("collection", 0, err.Error())
			break
		}
		raw, err := fs.readFile(filepath.Join(root, "net", table.name))
		if err != nil {
			r.gap("socket_table", 0, table.name+": "+err.Error())
			continue
		}
		endpoints, parseErr := parseRuntimeProcSockets(ctx, raw, table.protocol, table.family)
		if parseErr != nil {
			r.gap("socket_table", 0, table.name+": "+parseErr.Error())
		} else {
			readTables++
		}
		for _, e := range endpoints {
			index := len(r.Endpoints)
			r.Endpoints = append(r.Endpoints, e)
			if e.Socket != "0" {
				bySocket[e.Socket] = append(bySocket[e.Socket], index)
			}
		}
	}
	if readTables == 0 && len(r.Endpoints) == 0 {
		r.Status = "unavailable"
		return
	}
	if len(bySocket) != 0 {
		processes, err := fs.readDir(ctx, root)
		if err != nil {
			r.gap("processes", 0, err.Error())
		}
		for _, entry := range processes {
			if err := ctx.Err(); err != nil {
				r.gap("collection", 0, err.Error())
				break
			}
			pid, err := strconv.Atoi(entry.Name())
			if err != nil || pid <= 0 || !entry.IsDir() {
				continue
			}
			collectRuntimeProcOwner(ctx, r, filepath.Join(root, entry.Name()), pid, bySocket, fs)
		}
	}
	for _, e := range r.Endpoints {
		if len(e.Owners) == 0 {
			r.gap("ownership", 0, "one or more observed sockets have no readable stable process owner")
			break
		}
	}
	if nsErr == nil {
		after, err := fs.readlink(filepath.Join(root, "self/ns/net"))
		if err != nil || after != namespace {
			r.gap("namespace", 0, "network namespace could not be confirmed stable during collection")
			r.Endpoints = []HostEndpoint{}
			r.Processes = []HostProcess{}
		}
	}
	// Restricted process mounts can hide owners without returning a permission error.
	r.gap("coverage", 0, "ownership is limited to visible processes; hidden processes and other network namespaces were not assessed")
}

func parseRuntimeProcSockets(ctx context.Context, raw []byte, protocol, family string) ([]HostEndpoint, error) {
	if protocol != "tcp" && protocol != "udp" || family != "ipv4" && family != "ipv6" {
		return nil, errors.New("unsupported socket table kind")
	}
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	if !scanner.Scan() || !strings.Contains(scanner.Text(), "local_address") {
		return nil, errors.New("socket table header missing")
	}
	var out []HostEndpoint
	var malformed int
	rows := 0
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		rows++
		if rows > runtimeProcEntries {
			return out, errors.New("socket row limit reached")
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			malformed++
			continue
		}
		state, err := strconv.ParseUint(fields[3], 16, 8)
		if err != nil {
			malformed++
			continue
		}
		if protocol == "tcp" && state != 0x0a {
			continue
		}
		address, port, err := runtimeProcAddress(fields[1], family)
		if err != nil {
			malformed++
			continue
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			malformed++
			continue
		}
		if port == 0 {
			continue
		}
		stateName := "listening"
		if protocol == "udp" {
			stateName = "bound"
		}
		out = append(out, HostEndpoint{Protocol: protocol, Family: family, Address: address, Port: port, State: stateName, Socket: strconv.FormatUint(inode, 10), Owners: []int{}})
	}
	if err := scanner.Err(); err != nil {
		return out, err
	}
	if malformed > 0 {
		return out, fmt.Errorf("%d malformed socket rows", malformed)
	}
	return out, nil
}

func runtimeProcAddress(value, family string) (string, uint16, error) {
	host, portText, ok := strings.Cut(value, ":")
	if !ok {
		return "", 0, errors.New("socket address has no port")
	}
	length := 8
	if family == "ipv6" {
		length = 32
	}
	if len(host) != length || len(portText) != 4 {
		return "", 0, errors.New("invalid socket address length")
	}
	raw, err := hex.DecodeString(host)
	if err != nil {
		return "", 0, err
	}
	// Addresses are printed as native-endian 32-bit words by the kernel.
	for i := 0; i < len(raw); i += 4 {
		word := binary.BigEndian.Uint32(raw[i : i+4])
		binary.NativeEndian.PutUint32(raw[i:i+4], word)
	}
	port, err := strconv.ParseUint(portText, 16, 16)
	if err != nil {
		return "", 0, err
	}
	ip, ok := netip.AddrFromSlice(raw)
	if !ok {
		return "", 0, errors.New("invalid socket address")
	}
	return ip.String(), uint16(port), nil
}

func runtimeProcIdentity(raw []byte, pid int) (string, error) {
	text := strings.TrimSpace(string(raw))
	open, close := strings.IndexByte(text, '('), strings.LastIndexByte(text, ')')
	if open < 1 || close <= open {
		return "", errors.New("malformed process identity")
	}
	actual, err := strconv.Atoi(strings.TrimSpace(text[:open]))
	if err != nil || actual != pid {
		return "", errors.New("process identity does not match PID")
	}
	fields := strings.Fields(text[close+1:])
	if len(fields) < 20 {
		return "", errors.New("truncated process identity")
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return "", errors.New("invalid process start ticks")
	}
	return strconv.Itoa(pid) + ":" + strconv.FormatUint(ticks, 10), nil
}

func runtimeProcUIDs(raw []byte) (uint32, uint32, error) {
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 5 {
			return 0, 0, errors.New("malformed process account IDs")
		}
		ids := make([]uint32, 4)
		for i, value := range fields[1:] {
			id, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return 0, 0, errors.New("invalid process account ID")
			}
			ids[i] = uint32(id)
		}
		return ids[0], ids[1], nil
	}
	return 0, 0, errors.New("process account IDs missing")
}

func collectRuntimeProcOwner(ctx context.Context, r *HostRuntime, dir string, pid int, sockets map[string][]int, fs runtimeProcIO) {
	initial, err := fs.readFile(filepath.Join(dir, "stat"))
	if err != nil {
		r.gap("process_identity", pid, err.Error())
		return
	}
	identity, err := runtimeProcIdentity(initial, pid)
	if err != nil {
		r.gap("process_identity", pid, err.Error())
		return
	}
	fds, err := fs.readDir(ctx, filepath.Join(dir, "fd"))
	if err != nil {
		r.gap("process_sockets", pid, err.Error())
	}
	owned := map[string]string{}
	for _, fd := range fds {
		if err := ctx.Err(); err != nil {
			r.gap("collection", 0, err.Error())
			return
		}
		path := filepath.Join(dir, "fd", fd.Name())
		link, err := fs.readlink(path)
		if err != nil {
			r.gap("process_sockets", pid, err.Error())
			continue
		}
		if !strings.HasPrefix(link, "socket:[") || !strings.HasSuffix(link, "]") {
			continue
		}
		inode := link[len("socket:[") : len(link)-1]
		if len(sockets[inode]) != 0 {
			owned[path] = inode
		}
	}
	if len(owned) == 0 {
		return
	}
	p := HostProcess{PID: pid, Identity: identity, Matches: []HostRuntimeMatch{}}
	status, err := fs.readFile(filepath.Join(dir, "status"))
	if err != nil {
		r.gap("process_account", pid, err.Error())
	} else if uid, effective, err := runtimeProcUIDs(status); err != nil {
		r.gap("process_account", pid, err.Error())
	} else {
		p.UID, p.EffectiveUID = &uid, &effective
	}
	exeLink := filepath.Join(dir, "exe")
	executable, err := fs.readlink(exeLink)
	if err != nil {
		r.gap("process_executable", pid, err.Error())
	} else if !filepath.IsAbs(executable) || strings.HasSuffix(executable, " (deleted)") {
		r.gap("process_executable", pid, "executable has no stable on-disk path")
	} else {
		live, liveErr := fs.stat(exeLink)
		disk, diskErr := fs.stat(executable)
		if liveErr != nil || diskErr != nil {
			r.gap("process_executable", pid, errors.Join(liveErr, diskErr).Error())
		} else if !live.Mode().IsRegular() || !disk.Mode().IsRegular() || !os.SameFile(live, disk) {
			r.gap("process_executable", pid, "running executable differs from its current on-disk path")
		} else {
			p.Executable = executable
			p.image = disk
		}
	}
	end, err := fs.readFile(filepath.Join(dir, "stat"))
	if err != nil {
		r.gap("process_identity", pid, "process disappeared before ownership could be confirmed")
		return
	}
	after, err := runtimeProcIdentity(end, pid)
	if err != nil || after != identity {
		r.gap("process_identity", pid, "process identity changed during collection")
		return
	}
	if p.Executable != "" {
		afterExe, err := fs.readlink(exeLink)
		if err != nil || afterExe != executable {
			p.Executable = ""
			r.gap("process_executable", pid, "executable changed during collection")
		}
	}
	confirmed := false
	for path, inode := range owned {
		link, err := fs.readlink(path)
		if err != nil || link != "socket:["+inode+"]" {
			r.gap("process_sockets", pid, "socket ownership changed during collection")
			continue
		}
		confirmed = true
		for _, index := range sockets[inode] {
			r.Endpoints[index].Owners = append(r.Endpoints[index].Owners, pid)
		}
	}
	if confirmed {
		r.Processes = append(r.Processes, p)
	}
}
