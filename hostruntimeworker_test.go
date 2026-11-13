package vulnx

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestRuntimeWorkerChild(t *testing.T) {
	index := slices.Index(os.Args, "--runtime-worker-fixture")
	if index < 0 {
		return
	}
	mode := os.Args[index+1]
	switch mode {
	case "real":
		if err := RunHostRuntimeWorker(os.Stdin, os.Stdout); err != nil {
			if _, writeErr := fmt.Fprintln(os.Stderr, err); writeErr != nil {
				os.Exit(5)
			}
			os.Exit(1)
		}
	case "hang":
		var request runtimeWire
		if err := json.NewDecoder(os.Stdin).Decode(&request); err != nil {
			os.Exit(2)
		}
		inv := request.inventory()
		inv.Runtime = &HostRuntime{Status: "partial", Endpoints: []HostEndpoint{{Protocol: "tcp", Address: "127.0.0.1", Port: 1234}}, Processes: []HostProcess{}, Gaps: []HostRuntimeGap{}}
		if err := json.NewEncoder(os.Stdout).Encode(inv.runtimeWire("observed")); err != nil {
			os.Exit(3)
		}
		time.Sleep(time.Minute)
	case "invalid":
		if _, err := fmt.Fprintln(os.Stdout, "not JSON"); err != nil {
			os.Exit(4)
		}
	}
	os.Exit(0)
}

func TestRuntimeWorkerTimeout(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var inv HostInventory
	start := time.Now()
	inv.collectRuntimeWorker(ctx, executable, []string{"-test.run=^TestRuntimeWorkerChild$", "--", "--runtime-worker-fixture", "hang"})
	if time.Since(start) > 5*time.Second {
		t.Fatal("worker exceeded hard deadline")
	}
	if inv.Runtime.Status != "partial" || len(inv.Runtime.Endpoints) != 1 || len(inv.Runtime.Gaps) == 0 {
		t.Fatalf("partial observations lost: %+v", inv.Runtime)
	}
}

func TestRuntimeWorkerInvalid(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var inv HostInventory
	inv.collectRuntimeWorker(context.Background(), executable, []string{"-test.run=^TestRuntimeWorkerChild$", "--", "--runtime-worker-fixture", "invalid"})
	if inv.Runtime.Status != "unavailable" || len(inv.Runtime.Gaps) == 0 {
		t.Fatalf("invalid worker output accepted: %+v", inv.Runtime)
	}
}

func TestRuntimeWirePreservesParentState(t *testing.T) {
	inv := HostInventory{Pending: []HostPending{{Name: "pending"}}, Extensions: []string{"extension"}, Entries: []string{"old"}, Runtime: &HostRuntime{Status: "partial"}}
	update := HostInventory{Entries: []string{"old", "new"}, runtimePlaces: map[string]bool{"private": true}, Runtime: &HostRuntime{Status: "partial"}}
	inv.applyRuntimeWire(update.runtimeWire("enriched"))
	if len(inv.Pending) != 1 || len(inv.Extensions) != 1 || len(inv.Entries) != 2 || !inv.runtimePlaces["private"] {
		t.Fatal("worker merge lost parent-only fields")
	}
}

func TestRuntimeWorkerEndToEnd(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("runtime collection unsupported on this platform")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := listener.Close(); err != nil {
			t.Error(err)
		}
	})
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	var inv HostInventory
	inv.collectRuntimeWorker(ctx, executable, []string{"-test.run=^TestRuntimeWorkerChild$", "--", "--runtime-worker-fixture", "real"})
	found := false
	for _, endpoint := range inv.Runtime.Endpoints {
		if endpoint.Port == uint16(listener.Addr().(*net.TCPAddr).Port) && slices.Contains(endpoint.Owners, os.Getpid()) {
			found = true
		}
	}
	if !found {
		t.Fatalf("worker lost parent listener: %+v", inv.Runtime.Gaps)
	}
	for _, p := range inv.Runtime.Processes {
		if p.PID == os.Getpid() {
			if len(p.Matches) == 0 || !slices.ContainsFunc(p.Matches[0].Components, func(e string) bool { return strings.HasPrefix(e, "pkg:golang/stdlib@") }) {
				t.Fatalf("worker lost verified component evidence: %+v; gaps=%+v", p, inv.Runtime.Gaps)
			}
			return
		}
	}
	t.Fatal("worker lost parent process")
}

func TestRuntimeWorkerMountedRoot(t *testing.T) {
	var inv HostInventory
	inv.CollectRuntimeIsolated(context.Background(), t.TempDir())
	if inv.Runtime.Status != "skipped" {
		t.Fatal("mounted root invoked worker")
	}
}
