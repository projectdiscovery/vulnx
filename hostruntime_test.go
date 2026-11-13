package vulnx

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRuntimeBind(t *testing.T) {
	for address, want := range map[string]string{"127.0.0.1": "loopback", "::1": "loopback", "::ffff:127.0.0.1": "loopback", "0.0.0.0": "wildcard", "::": "wildcard", "192.168.1.2": "specific_address", "8.8.8.8": "specific_address", "fe80::1%en0": "specific_address", "invalid": "unknown"} {
		if got := runtimeBind(address); got != want {
			t.Errorf("%s: %s", address, got)
		}
	}
}

func TestCollectRuntimeScope(t *testing.T) {
	var inv HostInventory
	called := false
	inv.collectRuntime(context.Background(), t.TempDir(), func(context.Context, *HostRuntime) { called = true })
	if called || inv.Runtime.Status != "skipped" {
		t.Fatal("mounted root inspected live runtime")
	}
	inv.collectRuntime(context.Background(), "", func(ctx context.Context, r *HostRuntime) {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("unbounded collector")
		}
		r.Endpoints = append(r.Endpoints, HostEndpoint{Protocol: "tcp", Family: "ipv4", Address: "127.0.0.1", Port: 80, State: "listening"})
		r.gap("process", 10, "permission denied")
	})
	if inv.Runtime.Status != "partial" || len(inv.Runtime.Endpoints) != 1 || inv.Runtime.StartedAt == "" || inv.Runtime.FinishedAt == "" {
		t.Fatalf("%+v", inv.Runtime)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	inv.collectRuntime(ctx, "/", func(context.Context, *HostRuntime) {})
	if inv.Runtime.Status != "partial" || len(inv.Runtime.Gaps) != 1 {
		t.Fatal("cancellation not recorded")
	}
	inv.collectRuntime(context.Background(), "/", func(context.Context, *HostRuntime) {})
	if inv.Runtime.Status != "collected" || len(inv.Runtime.Gaps) != 0 || inv.Runtime.Endpoints == nil {
		t.Fatal("empty result not distinct from failure")
	}
}

func TestRuntimeMatches(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "tool")
	if err := os.WriteFile(tool, []byte("fixture"), 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(tool, alias); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(other, []byte("different"), 0700); err != nil {
		t.Fatal(err)
	}
	inv := HostInventory{Paths: map[string]string{"tool": alias, "bundle": dir}, FoundIn: map[string][]string{"pkg:a@1": {"tool"}, "pkg:b@2": {"bundle"}}, GoBinaries: map[string][]HostBinary{"pkg:c@3": {{Path: tool, Name: "tool"}}}}
	r := HostRuntime{Processes: []HostProcess{{PID: 1, Executable: tool}, {PID: 2, Executable: other}, {PID: 3, Executable: tool + " (deleted)"}, {PID: 4, Executable: dir}, {PID: 5, Executable: "tool"}}}
	for i := range r.Processes {
		if st, err := os.Stat(r.Processes[i].Executable); err == nil {
			r.Processes[i].image = st
		}
	}
	inv.matchRuntime(context.Background(), &r)
	want := []HostRuntimeMatch{{Place: "tool", Components: []string{"pkg:a@1", "pkg:c@3"}}}
	if !reflect.DeepEqual(r.Processes[0].Matches, want) {
		t.Fatalf("%+v", r.Processes[0])
	}
	for _, p := range r.Processes[1:] {
		if len(p.Matches) > 0 {
			t.Fatalf("false match: %+v", p)
		}
	}
}

func TestRuntimeNormalize(t *testing.T) {
	r := HostRuntime{Endpoints: []HostEndpoint{{Protocol: "tcp", Family: "ipv4", Address: "0.0.0.0", Port: 80, Owners: []int{2, 1}}, {Protocol: "tcp", Family: "ipv4", Address: "0.0.0.0", Port: 80, Owners: []int{2, 3}}, {Protocol: "udp", Family: "ipv6", Address: "::1", Port: 53}}, Processes: []HostProcess{{PID: 3}, {PID: 1}}}
	r.normalize()
	if len(r.Endpoints) != 2 || !reflect.DeepEqual(r.Endpoints[0].Owners, []int{1, 2, 3}) || r.Endpoints[0].Bind != "wildcard" || r.Processes[0].PID != 1 {
		t.Fatalf("%+v", r)
	}
	if r.Endpoints[1].Owners == nil {
		t.Fatal("unknown owner must be an empty list")
	}
	r.gap("process", 1, "gone")
	r.gap("process", 1, "gone")
	if len(r.Gaps) != 1 {
		t.Fatal("duplicate gap")
	}
}

func TestRuntimePrivacyShape(t *testing.T) {
	raw, err := json.Marshal(HostRuntime{Processes: []HostProcess{{PID: 1, Executable: "/bin/tool"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"cmdline", "command_line", "environment", "environ", "password", "username"} {
		if strings.Contains(string(raw), key) {
			t.Fatalf("unexpected field %s", key)
		}
	}
}
