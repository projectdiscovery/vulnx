package vulnx

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func runtimeInventoryProcess(t *testing.T, pid int, path string) HostProcess {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return HostProcess{PID: pid, Executable: path, image: st, Matches: []HostRuntimeMatch{}}
}

func runtimeInventoryFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("metadata fixture"), 0700); err != nil {
		t.Fatal(err)
	}
}

func TestEnrichRuntimeInventory(t *testing.T) {
	root := t.TempDir()
	one, two := filepath.Join(root, "one/tool"), filepath.Join(root, "two/tool")
	runtimeInventoryFile(t, one)
	runtimeInventoryFile(t, two)
	inv := HostInventory{Entries: []string{"pkg:golang/example.org/shared@v1.0.0"}, EntrySource: map[string]string{"pkg:golang/example.org/shared@v1.0.0": "go binaries"}, Runtime: &HostRuntime{Status: "partial", Processes: []HostProcess{runtimeInventoryProcess(t, 1, one), runtimeInventoryProcess(t, 2, one), runtimeInventoryProcess(t, 3, two)}}}
	calls := 0
	inv.enrichRuntimeInventory(context.Background(), func(file *os.File) runtimeModules {
		calls++
		return runtimeModules{entries: []string{"pkg:golang/example.org/shared@v1.0.0", "pkg:golang/example.org/renamed@v2.0.0"}, renamed: map[string]bool{"pkg:golang/example.org/renamed@v2.0.0": true}, goBinary: true}
	})
	if calls != 2 || len(inv.Entries) != 2 || len(inv.Sources) != 1 || inv.Sources[0].Sent != 1 {
		t.Fatalf("calls=%d inventory=%+v", calls, inv)
	}
	if inv.EntrySource[inv.Entries[0]] != "go binaries" || inv.EntrySource[inv.Entries[1]] != runtimeInventorySource {
		t.Fatal("source attribution changed")
	}
	if !reflect.DeepEqual(inv.FoundIn[inv.Entries[0]], []string{one, two}) {
		t.Fatalf("colliding places: %+v", inv.FoundIn)
	}
	if len(inv.GoBinaries[inv.Entries[0]]) != 2 || len(inv.GoBinaries[inv.Entries[1]]) != 0 {
		t.Fatalf("Go linkage: %+v", inv.GoBinaries)
	}
	for _, p := range inv.Runtime.Processes {
		if p.Inventory != "identified" || len(p.Matches) != 1 || p.Matches[0].Place != p.Executable {
			t.Fatalf("%+v", p)
		}
	}
	inv.enrichRuntimeInventory(context.Background(), func(*os.File) runtimeModules { t.Fatal("repeat enrichment read binary"); return runtimeModules{} })
	if len(inv.Sources) != 1 {
		t.Fatal("duplicate runtime source")
	}
	raw, err := inv.CycloneDX(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), root) || !strings.Contains(string(raw), "example.org/shared") {
		t.Fatal("runtime locations leaked or identifiers missing from shared inventory")
	}
	private, err := json.Marshal(inv)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(private), "runtimePlaces") || strings.Contains(string(private), "\"image\"") {
		t.Fatal("private identity state leaked")
	}
}

func TestRuntimeInventoryMixedGenerations(t *testing.T) {
	// os.SameFile on Windows reads a stat's file ID through its path when first asked, so after the rename the
	// old generation's identity is the new file's: telling generations apart needs a Unix inode
	skipOnWindows(t)
	path := filepath.Join(t.TempDir(), "tool")
	runtimeInventoryFile(t, path)
	old := runtimeInventoryProcess(t, 1, path)
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	runtimeInventoryFile(t, path)
	current := runtimeInventoryProcess(t, 2, path)
	inv := HostInventory{Runtime: &HostRuntime{Processes: []HostProcess{old, current}}}
	calls := 0
	inv.enrichRuntimeInventory(context.Background(), func(*os.File) runtimeModules {
		calls++
		return runtimeModules{entries: []string{"pkg:cargo/example@1.0.0"}}
	})
	if calls != 1 || inv.Runtime.Processes[0].Inventory != "unassessed" || inv.Runtime.Processes[1].Inventory != "identified" || len(inv.Runtime.Processes[0].Matches) != 0 || len(inv.Runtime.Processes[1].Matches) != 1 {
		t.Fatalf("generations conflated: %+v", inv.Runtime.Processes)
	}
}

func TestRuntimeInventoryKnownAndSkipped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tool")
	runtimeInventoryFile(t, path)
	p := runtimeInventoryProcess(t, 1, path)
	p.Matches = []HostRuntimeMatch{{Place: "old", Components: []string{"pkg:golang/example.org/old@v1.0.0"}}}
	inv := HostInventory{Runtime: &HostRuntime{Processes: []HostProcess{p}}}
	calls := 0
	inv.enrichRuntimeInventory(context.Background(), func(*os.File) runtimeModules {
		calls++
		return runtimeModules{entries: []string{"pkg:golang/example.org/new@v2.0.0"}}
	})
	if calls != 1 || inv.Runtime.Processes[0].Matches[0].Components[0] != "pkg:golang/example.org/new@v2.0.0" {
		t.Fatal("stale inventory reused")
	}
	inv = HostInventory{Runtime: &HostRuntime{Status: "skipped", Processes: []HostProcess{p}}}
	inv.enrichRuntimeInventory(context.Background(), func(*os.File) runtimeModules { t.Fatal("mounted filesystem inspected"); return runtimeModules{} })
	if len(inv.Entries) != 0 || len(inv.Sources) != 0 {
		t.Fatal("mounted root enriched")
	}
}

func TestRuntimeInventoryFailures(t *testing.T) {
	skipOnWindows(t)
	for _, kind := range []string{"unsupported", "unverified", "replaced", "deleted", "changed_during_read", "cancelled", "too_large", "permission"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "tool")
			runtimeInventoryFile(t, path)
			p := runtimeInventoryProcess(t, 1, path)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "permission":
				if runtime.GOOS == "windows" || os.Geteuid() == 0 {
					t.Skip("privileged process can read permission fixture")
				}
				if err := os.Chmod(path, 0); err != nil {
					t.Fatal(err)
				}
				p = runtimeInventoryProcess(t, 1, path)
			case "unverified":
				p.image = nil
			case "replaced":
				if err := os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
				runtimeInventoryFile(t, path)
			case "deleted":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "cancelled":
				cancel()
			case "too_large":
				if err := os.Truncate(path, runtimeExecutableSize+1); err != nil {
					t.Fatal(err)
				}
				p = runtimeInventoryProcess(t, 1, path)
			}
			inv := HostInventory{Runtime: &HostRuntime{Processes: []HostProcess{p}}}
			calls := 0
			inv.enrichRuntimeInventory(ctx, func(*os.File) runtimeModules {
				calls++
				if kind == "unsupported" {
					return runtimeModules{}
				}
				if kind == "changed_during_read" {
					if err := os.Rename(path, path+".old"); err != nil {
						t.Fatal(err)
					}
					runtimeInventoryFile(t, path)
				}
				return runtimeModules{entries: []string{"pkg:cargo/example@1.0.0"}}
			})
			if len(inv.Entries) != 0 || len(inv.NotAssessed) != 1 || inv.Runtime.Processes[0].Inventory != "unassessed" {
				t.Fatalf("%+v", inv)
			}
			if kind != "unsupported" && kind != "changed_during_read" && calls != 0 {
				t.Fatal("unsafe binary read")
			}
		})
	}
}

func TestRuntimeInventoryFileLimit(t *testing.T) {
	inv := HostInventory{Runtime: &HostRuntime{}}
	for i := 0; i < runtimeExecutableLimit+1; i++ {
		path := filepath.Join(t.TempDir(), fmt.Sprintf("tool-%d", i))
		runtimeInventoryFile(t, path)
		inv.Runtime.Processes = append(inv.Runtime.Processes, runtimeInventoryProcess(t, i+1, path))
	}
	calls := 0
	inv.enrichRuntimeInventory(context.Background(), func(*os.File) runtimeModules { calls++; return runtimeModules{} })
	if calls != runtimeExecutableLimit || !strings.Contains(inv.Runtime.Processes[len(inv.Runtime.Processes)-1].InventoryReason, "count limit") {
		t.Fatalf("calls=%d", calls)
	}
}

func TestRuntimeContainment(t *testing.T) {
	root := t.TempDir()
	app := filepath.Join(root, "App.app")
	nested := filepath.Join(app, "Contents/Helpers/Helper.app")
	inside := filepath.Join(nested, "Contents/MacOS/helper")
	outside := filepath.Join(root, "App.app-other/tool")
	runtimeInventoryFile(t, inside)
	runtimeInventoryFile(t, outside)
	link := filepath.Join(app, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	inv := HostInventory{Paths: map[string]string{"App.app": app, "Helper.app": nested}, FoundIn: map[string][]string{"pkg:npm/not-proven-loaded@1": {"App.app"}}}
	r := &HostRuntime{Processes: []HostProcess{runtimeInventoryProcess(t, 1, inside), runtimeInventoryProcess(t, 2, outside), runtimeInventoryProcess(t, 3, link)}}
	inv.Runtime = r
	inv.matchRuntime(context.Background(), r)
	if len(r.Processes[0].Installations) != 2 || len(r.Processes[0].Matches) != 0 {
		t.Fatalf("containment became an exact match: %+v", r.Processes[0])
	}
	for _, i := range r.Processes[0].Installations {
		if i.Relation != "contained_in" {
			t.Fatalf("%+v", i)
		}
	}
	if len(r.Processes[1].Installations) != 0 || len(r.Processes[2].Installations) != 0 {
		t.Fatal("prefix or symlink escape treated as containment")
	}
}

func TestReadRuntimeModules(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	mods := readRuntimeModules(file)
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if !mods.goBinary || !slices.ContainsFunc(mods.entries, func(s string) bool { return strings.HasPrefix(s, "pkg:golang/stdlib@") }) {
		t.Fatalf("test executable metadata: %+v", mods)
	}
	path := filepath.Join(t.TempDir(), "script")
	marker := path + ".executed"
	if err := os.WriteFile(path, []byte("#!/bin/sh\ntouch '"+marker+"'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	inv := HostInventory{Runtime: &HostRuntime{Processes: []HostProcess{runtimeInventoryProcess(t, 1, path)}}}
	inv.enrichRuntimeInventoryHere(context.Background())
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("executable was started")
	}
	if len(inv.NotAssessed) != 1 {
		t.Fatal("script identity guessed")
	}
}

func TestRuntimeMetadataUsesVerifiedDescriptor(t *testing.T) {
	skipOnWindows(t)
	path := filepath.Join(t.TempDir(), "tool")
	runtimeInventoryFile(t, path)
	p := runtimeInventoryProcess(t, 1, path)
	inv := HostInventory{Runtime: &HostRuntime{Processes: []HostProcess{p}}}
	inv.enrichRuntimeInventory(context.Background(), func(file *os.File) runtimeModules {
		if err := os.Rename(path, path+".old"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("replacement"), 0700); err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(file)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != "metadata fixture" {
			t.Fatal("read replacement instead of verified descriptor")
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(path+".old", path); err != nil {
			t.Fatal(err)
		}
		return runtimeModules{entries: []string{"pkg:cargo/original@1.0.0"}}
	})
	if len(inv.Entries) != 1 || inv.Entries[0] != "pkg:cargo/original@1.0.0" {
		t.Fatal("original metadata lost")
	}
}

func TestRuntimeDoesNotTrustDisplayNameJoins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tool")
	runtimeInventoryFile(t, path)
	inv := HostInventory{Paths: map[string]string{"tool": path}, FoundIn: map[string][]string{"pkg:golang/other@v1.0.0": {"tool"}}, Entries: []string{"pkg:golang/other@v1.0.0"}, Runtime: &HostRuntime{Processes: []HostProcess{runtimeInventoryProcess(t, 1, path)}}}
	inv.matchRuntime(context.Background(), inv.Runtime)
	if len(inv.Runtime.Processes[0].Matches) != 0 {
		t.Fatal("display label was treated as evidence")
	}
	inv.enrichRuntimeInventory(context.Background(), func(*os.File) runtimeModules { return runtimeModules{entries: []string{"pkg:golang/actual@v2.0.0"}} })
	matches := inv.Runtime.Processes[0].Matches
	if len(matches) != 1 || len(matches[0].Components) != 1 || matches[0].Components[0] != "pkg:golang/actual@v2.0.0" {
		t.Fatalf("false exact association: %+v", matches)
	}
}

// TestRefreshRuntimeMatches keeps, of each process's matches, only the components still in the inventory (one
// dropped as an unknown product is gone), and a match left with none is dropped.
func TestRefreshRuntimeMatches(t *testing.T) {
	inv := HostInventory{Entries: []string{"pkg:golang/a@v1", "pkg:golang/b@v1"}, Runtime: &HostRuntime{Status: "collected", Processes: []HostProcess{
		{PID: 1, Matches: []HostRuntimeMatch{{Place: "x", Components: []string{"pkg:golang/a@v1", "cpe:2.3:a:gone:gone:1:*:*:*:*:*:*:*"}},
			{Place: "y", Components: []string{"cpe:2.3:a:gone:gone:1:*:*:*:*:*:*:*"}}}},
		{PID: 2, Matches: []HostRuntimeMatch{}}}}}
	inv.RefreshRuntimeMatches(context.Background())
	p := inv.Runtime.Processes
	if len(p[0].Matches) != 1 || p[0].Matches[0].Place != "x" || strings.Join(p[0].Matches[0].Components, ",") != "pkg:golang/a@v1" ||
		p[1].Matches == nil {
		t.Fatalf("%+v", p)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	inv.RefreshRuntimeMatches(ctx)
	if len(inv.Runtime.Gaps) == 0 {
		t.Error("a cancelled refresh is not recorded as a gap")
	}
}
