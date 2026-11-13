package vulnx

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const procSocketHeader = "  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"

func procSocketLine(address string, port uint16, state, inode string) string {
	ip := netip.MustParseAddr(address)
	raw := ip.AsSlice()
	for i := 0; i < len(raw); i += 4 {
		word := binary.NativeEndian.Uint32(raw[i : i+4])
		binary.BigEndian.PutUint32(raw[i:i+4], word)
	}
	return fmt.Sprintf(" 0: %s:%04X 00000000:0000 %s 00000000:00000000 00:00000000 00000000 501 0 %s 1 00000000\n", strings.ToUpper(hex.EncodeToString(raw)), port, state, inode)
}

func TestParseRuntimeProcSockets(t *testing.T) {
	for _, test := range []struct {
		name, protocol, family, address, state string
		port                                   uint16
		want                                   int
	}{
		{"tcp loopback", "tcp", "ipv4", "127.0.0.1", "0A", 1234, 1},
		{"tcp wildcard", "tcp", "ipv4", "0.0.0.0", "0A", 80, 1},
		{"tcp established", "tcp", "ipv4", "192.0.2.1", "01", 443, 0},
		{"udp bound", "udp", "ipv4", "192.0.2.1", "07", 5353, 1},
		{"udp connected", "udp", "ipv4", "192.0.2.1", "01", 5353, 1},
		{"udp unbound", "udp", "ipv4", "0.0.0.0", "07", 0, 0},
		{"ipv6 loopback", "tcp", "ipv6", "::1", "0A", 8080, 1},
		{"ipv6 wildcard", "udp", "ipv6", "::", "07", 5353, 1},
		{"ipv6 specific", "tcp", "ipv6", "2001:db8:1234::abcd", "0A", 65535, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := procSocketHeader + procSocketLine(test.address, test.port, test.state, "123456")
			got, err := parseRuntimeProcSockets(context.Background(), []byte(raw), test.protocol, test.family)
			if err != nil || len(got) != test.want {
				t.Fatalf("endpoints=%+v error=%v", got, err)
			}
			if test.want != 0 {
				e := got[0]
				if e.Address != test.address || e.Port != test.port || e.Socket != "123456" || len(e.Owners) != 0 {
					t.Fatalf("endpoint %+v", e)
				}
				wantState := "listening"
				if test.protocol == "udp" {
					wantState = "bound"
				}
				if e.State != wantState {
					t.Fatalf("state %q", e.State)
				}
			}
		})
	}
	valid := procSocketLine("127.0.0.1", 80, "0A", "12")
	for name, raw := range map[string]string{
		"truncated": "", "header": "garbage\n", "row": procSocketHeader + "missing fields\n",
		"address": procSocketHeader + strings.ReplaceAll(valid, strings.Fields(valid)[1], "ZZ00007F:0050"),
		"inode":   procSocketHeader + strings.ReplaceAll(valid, "501 0 12", "501 0 none"),
		"state":   procSocketHeader + strings.ReplaceAll(valid, " 0A ", " ZZ "),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseRuntimeProcSockets(context.Background(), []byte(raw), "tcp", "ipv4"); err == nil {
				t.Fatal("malformed table accepted")
			}
		})
	}
	got, err := parseRuntimeProcSockets(context.Background(), []byte(procSocketHeader+valid+"bad row\n"), "tcp", "ipv4")
	if len(got) != 1 || err == nil {
		t.Fatalf("valid observations lost: %+v %v", got, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := parseRuntimeProcSockets(ctx, []byte(procSocketHeader+valid), "tcp", "ipv4"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel error %v", err)
	}
}

func procStat(pid int, name, ticks string) string {
	return fmt.Sprintf("%d (%s) S %s %s 0\n", pid, name, strings.Repeat("0 ", 18), ticks)
}

func TestRuntimeProcIdentity(t *testing.T) {
	for _, name := range []string{"program", "program with spaces", "name ) strange ( name"} {
		got, err := runtimeProcIdentity([]byte(procStat(123, name, "7654321")), 123)
		if err != nil || got != "123:7654321" {
			t.Fatalf("%q: %q %v", name, got, err)
		}
	}
	for _, raw := range []string{"", "123 no parentheses", "123 (name) S 0", procStat(124, "name", "1"), procStat(123, "name", "bad")} {
		if _, err := runtimeProcIdentity([]byte(raw), 123); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
}

func TestRuntimeProcUIDs(t *testing.T) {
	u, e, err := runtimeProcUIDs([]byte("Name:\tprogram\nUid:\t501\t0\t0\t501\n"))
	if err != nil || u != 501 || e != 0 {
		t.Fatalf("ids %d %d %v", u, e, err)
	}
	for _, raw := range []string{"", "Uid: 1 2", "Uid: -1 2 3 4", "Uid: 1 2 bad 4", "Uid: 4294967296 2 3 4"} {
		if _, _, err := runtimeProcUIDs([]byte(raw)); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
}

func runtimeProcFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"net", "self/ns", "123/fd", "124/fd"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("net:[12345]", filepath.Join(root, "self/ns/net")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tcp", "tcp6", "udp", "udp6"} {
		body := procSocketHeader
		if name == "tcp" {
			body += procSocketLine("127.0.0.1", 8080, "0A", "100")
			body += procSocketLine("0.0.0.0", 9090, "0A", "101")
		}
		if name == "udp" {
			body += procSocketLine("127.0.0.1", 5353, "07", "102")
		}
		if err := os.WriteFile(filepath.Join(root, "net", name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	executable := filepath.Join(root, "executable")
	if err := os.WriteFile(executable, []byte("fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, pid := range []int{123, 124} {
		dir := filepath.Join(root, fmt.Sprint(pid))
		for name, body := range map[string]string{"stat": procStat(pid, "program", "100"), "status": "Uid:\t501\t501\t501\t501\n"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		for name, target := range map[string]string{"exe": executable, "fd/3": "socket:[100]", "fd/4": "socket:[102]", "fd/5": "socket:[100]"} {
			if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
		}
	}
	return root, executable
}

func runtimeProcResult(root string, fs runtimeProcIO) *HostRuntime {
	r := &HostRuntime{Status: "collected", Endpoints: []HostEndpoint{}, Processes: []HostProcess{}, Gaps: []HostRuntimeGap{}}
	collectRuntimeProc(context.Background(), r, root, fs)
	r.normalize()
	return r
}

func TestCollectRuntimeProc(t *testing.T) {
	root, executable := runtimeProcFixture(t)
	fs := runtimeProcFiles()
	readFile := fs.readFile
	fs.readFile = func(path string) ([]byte, error) {
		if strings.HasSuffix(path, "cmdline") || strings.HasSuffix(path, "environ") {
			t.Fatalf("sensitive file read: %s", path)
		}
		return readFile(path)
	}
	r := runtimeProcResult(root, fs)
	if r.Status != "partial" || len(r.Endpoints) != 3 || len(r.Processes) != 2 || !strings.Contains(r.Scope, "net:[12345]") {
		t.Fatalf("snapshot %+v", r)
	}
	for _, e := range r.Endpoints {
		want := []int{123, 124}
		if e.Socket == "101" {
			want = []int{}
		}
		if !reflect.DeepEqual(e.Owners, want) {
			t.Fatalf("owners %+v", e)
		}
	}
	for _, p := range r.Processes {
		if p.Executable != executable || p.UID == nil || *p.UID != 501 || p.EffectiveUID == nil || *p.EffectiveUID != 501 || p.Identity != fmt.Sprintf("%d:100", p.PID) {
			t.Fatalf("process %+v", p)
		}
	}
}

func TestRuntimeProcOwnerGaps(t *testing.T) {
	for _, test := range []string{"permission", "pid_reuse", "disappeared", "socket_changed", "deleted_exe", "replaced_exe", "exec_changed", "uid_missing"} {
		t.Run(test, func(t *testing.T) {
			root, executable := runtimeProcFixture(t)
			fs := runtimeProcFiles()
			readFile, readlink, readDir, stat := fs.readFile, fs.readlink, fs.readDir, fs.stat
			statReads, socketReads, exeReads := 0, 0, 0
			fs.readFile = func(path string) ([]byte, error) {
				if path == filepath.Join(root, "123/stat") {
					statReads++
					if statReads == 2 && test == "pid_reuse" {
						return []byte(procStat(123, "replacement", "200")), nil
					}
					if statReads == 2 && test == "disappeared" {
						return nil, os.ErrNotExist
					}
				}
				if path == filepath.Join(root, "123/status") && test == "uid_missing" {
					return nil, os.ErrPermission
				}
				return readFile(path)
			}
			fs.readDir = func(ctx context.Context, path string) ([]os.DirEntry, error) {
				if path == filepath.Join(root, "123/fd") && test == "permission" {
					return nil, os.ErrPermission
				}
				return readDir(ctx, path)
			}
			fs.readlink = func(path string) (string, error) {
				if strings.HasPrefix(path, filepath.Join(root, "123/fd")+string(filepath.Separator)) {
					socketReads++
					if socketReads > 3 && test == "socket_changed" {
						return "socket:[999]", nil
					}
				}
				if path == filepath.Join(root, "123/exe") {
					exeReads++
					if test == "deleted_exe" {
						return executable + " (deleted)", nil
					}
					if test == "exec_changed" && exeReads == 2 {
						return executable + "-replacement", nil
					}
				}
				return readlink(path)
			}
			fs.stat = func(path string) (os.FileInfo, error) {
				if path == executable && test == "replaced_exe" {
					return stat(filepath.Join(root, "123/status"))
				}
				return stat(path)
			}
			r := runtimeProcResult(root, fs)
			if len(r.Endpoints) != 3 || len(r.Gaps) < 3 {
				t.Fatalf("observations or gaps lost: %+v", r)
			}
			var process *HostProcess
			for i := range r.Processes {
				if r.Processes[i].PID == 123 {
					process = &r.Processes[i]
				}
			}
			switch test {
			case "permission", "pid_reuse", "disappeared", "socket_changed":
				if process != nil {
					t.Fatalf("unstable or unreadable owner retained: %+v", process)
				}
			case "deleted_exe", "replaced_exe", "exec_changed":
				if process == nil || process.Executable != "" {
					t.Fatalf("unreliable executable retained: %+v", process)
				}
			case "uid_missing":
				if process == nil || process.UID != nil || process.EffectiveUID != nil {
					t.Fatalf("unknown account represented as known: %+v", process)
				}
			}
		})
	}
}

func TestRuntimeProcCollectionFailures(t *testing.T) {
	root, _ := runtimeProcFixture(t)
	fs := runtimeProcFiles()
	fs.readFile = func(string) ([]byte, error) { return nil, os.ErrPermission }
	r := runtimeProcResult(root, fs)
	if r.Status != "unavailable" || len(r.Endpoints) != 0 || len(r.Gaps) == 0 {
		t.Fatalf("unavailable snapshot %+v", r)
	}
	fs = runtimeProcFiles()
	readlink := fs.readlink
	reads := 0
	fs.readlink = func(path string) (string, error) {
		if path == filepath.Join(root, "self/ns/net") {
			reads++
			if reads == 2 {
				return "net:[different]", nil
			}
		}
		return readlink(path)
	}
	r = runtimeProcResult(root, fs)
	if r.Status != "partial" || len(r.Endpoints) != 0 || len(r.Processes) != 0 {
		t.Fatalf("mixed namespace snapshot retained: %+v", r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r = &HostRuntime{Status: "collected"}
	collectRuntimeProc(ctx, r, root, runtimeProcFiles())
	if r.Status != "unavailable" || len(r.Endpoints) != 0 {
		t.Fatalf("cancelled snapshot %+v", r)
	}
}

func TestRuntimeProcFileBounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large")
	if err := os.WriteFile(path, make([]byte, runtimeProcLimit+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runtimeProcReadFile(path); err == nil {
		t.Fatal("oversized file accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := runtimeProcReadDir(ctx, filepath.Dir(path)); !errors.Is(err, context.Canceled) {
		t.Fatalf("directory cancellation %v", err)
	}
}
