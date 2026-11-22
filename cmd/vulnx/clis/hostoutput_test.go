package clis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/vulnx/v2"
	"github.com/projectdiscovery/vulnx/v2/pkg/tools/renderer"
)

func TestFailsOn(t *testing.T) {
	inv, res := hostFixture()
	for level, want := range map[string]bool{"kev": true, "critical": true, "high": true, "": false} {
		if failsOn(level, inv, res) != want {
			t.Errorf("%q: want %v", level, want)
		}
	}
	res.Items = res.Items[4:5] // lxml only: high, no exploit
	if failsOn("kev", inv, res) || failsOn("critical", inv, res) || !failsOn("high", inv, res) {
		t.Error("a high finding fails only --fail-on high")
	}
}

// TestWriteHostReportJSON writes the full result, inventory included, as the day's JSON file.
func TestWriteHostReportJSON(t *testing.T) {
	t.Chdir(t.TempDir())
	inv, res := hostFixture()
	path, err := writeHostReportJSON(inv, res)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Host struct {
			OS          string                   `json:"os"`
			Fixes       map[string]vulnx.HostFix `json:"fixes"`
			NotAssessed []vulnx.HostComponent    `json:"not_assessed"`
		} `json:"host"`
		Items []vulnx.StackItem `json:"items"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(filepath.Base(path), "vulnx-host-") || !strings.HasSuffix(path, ".json") || doc.Host.OS != "macOS 26.4" ||
		len(doc.Items) != len(res.Items) || doc.Host.Fixes["caddy"].Target != "caddy" || len(doc.Host.NotAssessed) != 1 {
		t.Errorf("%s: %+v, %d items", path, doc.Host, len(doc.Items))
	}
}

func TestHostRuntimeLocalOnly(t *testing.T) {
	inv, res := hostFixture()
	before := renderHost("grid", inv, res, time.Second, false, renderer.NoColorConfig())
	now := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	graphBefore, err := json.Marshal(buildHostGraph(inv, res, now))
	if err != nil {
		t.Fatal(err)
	}
	sbomBefore, err := inv.CycloneDX(now)
	if err != nil {
		t.Fatal(err)
	}
	inv.Runtime = &vulnx.HostRuntime{Status: "partial", Scope: "test-visible sockets", Endpoints: []vulnx.HostEndpoint{{Protocol: "tcp", Family: "ipv4", Address: "127.0.0.1", Port: 1234, State: "listening", Owners: []int{42}}}, Processes: []vulnx.HostProcess{{PID: 42, Executable: "/runtime-only-secret-path", Inventory: "unassessed", Installations: []vulnx.HostRuntimeInstallation{{Place: "containing app", Path: "/runtime-only-container", Relation: "contained_in"}}}}, Gaps: []vulnx.HostRuntimeGap{{Stage: "process", PID: 43, Reason: "permission denied"}}}
	raw, err := hostJSON(inv, res)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Host struct {
			Runtime *vulnx.HostRuntime `json:"runtime"`
		} `json:"host"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Host.Runtime == nil || doc.Host.Runtime.Status != "partial" || len(doc.Host.Runtime.Endpoints) != 1 || len(doc.Host.Runtime.Gaps) != 1 {
		t.Fatalf("runtime missing: %s", raw)
	}
	if len(doc.Host.Runtime.Processes[0].Installations) != 1 || doc.Host.Runtime.Processes[0].Installations[0].Relation != "contained_in" || doc.Host.Runtime.Processes[0].Inventory != "unassessed" {
		t.Fatal("runtime evidence type lost in JSON")
	}
	if after := renderHost("grid", inv, res, time.Second, false, renderer.NoColorConfig()); after != before {
		t.Fatal("runtime changed terminal output")
	}
	graphAfter, err := json.Marshal(buildHostGraph(inv, res, now))
	if err != nil {
		t.Fatal(err)
	}
	if string(graphAfter) != string(graphBefore) {
		t.Fatal("runtime leaked into graph")
	}
	sbomAfter, err := inv.CycloneDX(now)
	if err != nil {
		t.Fatal(err)
	}
	if string(sbomBefore) != string(sbomAfter) {
		t.Fatal("runtime leaked into shared inventory")
	}
}
