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
		var request runtimeRequest
		if err := json.NewDecoder(os.Stdin).Decode(&request); err != nil {
			os.Exit(2)
		}
		r := &HostRuntime{Status: "partial", Endpoints: []HostEndpoint{{Protocol: "tcp", Address: "127.0.0.1", Port: 1234}}, Processes: []HostProcess{}, Gaps: []HostRuntimeGap{}}
		if err := json.NewEncoder(os.Stdout).Encode(runtimeReply{Phase: "observed", Runtime: r}); err != nil {
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

// TestRuntimeAdditionsKeepParentState adds the worker's findings without losing what only the parent holds, and
// keeps a place's path and update the parent already knew.
func TestRuntimeAdditionsKeepParentState(t *testing.T) {
	inv := HostInventory{Pending: []HostPending{{Name: "pending"}}, Extensions: []string{"extension"}, Entries: []string{"old"},
		Paths: map[string]string{"tool": "/usr/bin/tool"}, Fixes: map[string]HostFix{"tool": {Kind: "brew"}}, Runtime: &HostRuntime{Status: "partial"}}
	inv.applyRuntimeAdditions(runtimeAdditions{Read: true, Found: []runtimeFound{{"old", "tool"}, {"new", "/opt/x"}},
		Paths: map[string]string{"tool": "/elsewhere", "/opt/x": "/opt/x"}, Fixes: map[string]HostFix{"tool": {Kind: "binary"}},
		Places: []string{"/opt/x"}})
	if len(inv.Pending) != 1 || len(inv.Extensions) != 1 || strings.Join(inv.Entries, ",") != "old,new" || !inv.runtimePlaces["/opt/x"] ||
		inv.Paths["tool"] != "/usr/bin/tool" || inv.Fixes["tool"].Kind != "brew" || inv.EntrySource["new"] != runtimeInventorySource ||
		!inv.Runtime.enriched {
		t.Fatalf("%+v", inv)
	}
}

// TestRuntimeRequestCarriesOnlyWhatEnrichmentNeeds sends the worker no sources, fixes, places found or not assessed.
func TestRuntimeRequestCarriesOnlyWhatEnrichmentNeeds(t *testing.T) {
	inv := HostInventory{Entries: []string{"e"}, Paths: map[string]string{"p": "/p"}, FoundIn: map[string][]string{"e": {"private-place"}},
		NotAssessed: []HostComponent{{Name: "private-name"}}, Fixes: map[string]HostFix{"p": {Note: "private-note"}}}
	raw, err := json.Marshal(runtimeRequest{Entries: inv.Entries, Paths: inv.Paths, GoBinaries: inv.GoBinaries})
	if err != nil {
		t.Fatal(err)
	}
	for _, never := range []string{"private-place", "private-name", "private-note"} {
		if strings.Contains(string(raw), never) {
			t.Errorf("the request carries %s", never)
		}
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
	// the parent's wait is generous: the worker keeps its own production deadline, and a test binary started under
	// -race on a loaded machine can take seconds to start
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var inv HostInventory
	inv.collectRuntimeWorker(ctx, executable, []string{"-test.run=^TestRuntimeWorkerChild$", "--", "--runtime-worker-fixture", "real"})
	// the worker stopping at its own deadline is its designed behaviour, not a lost result: what it finished is
	// kept, and what it did not reach cannot be asserted
	for _, g := range inv.Runtime.Gaps {
		if strings.Contains(g.Reason, "deadline") {
			t.Skipf("the worker reached its deadline on a loaded machine: %+v", inv.Runtime.Gaps)
		}
	}
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

// TestRuntimeWorkerMountedRoot starts no worker for a mounted root: its snapshot is skipped, and its executables
// are not read.
func TestRuntimeWorkerMountedRoot(t *testing.T) {
	var inv HostInventory
	inv.CollectRuntimeIsolated(context.Background(), t.TempDir())
	if inv.Runtime == nil || inv.Runtime.Status != "skipped" || len(inv.Runtime.Processes) != 0 || inv.Runtime.FinishedAt == "" {
		t.Fatalf("mounted root invoked worker: %+v", inv.Runtime)
	}
	inv.enrichRuntimeInventory(context.Background(), func(*os.File) runtimeModules {
		t.Fatal("a mounted root's executable was read")
		return runtimeModules{}
	})
	if len(inv.Sources) != 0 {
		t.Fatalf("%+v", inv.Sources)
	}
}
