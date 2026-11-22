package clis

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/vulnx/v2"
)

func TestBuildHostGraph(t *testing.T) {
	inv := vulnx.HostInventory{OS: "macOS 26.4", Entries: []string{"pkg:npm/a@1.0.0", "pkg:npm/b@2.0.0", "pkg:npm/c@3.0.0"},
		EntrySource: map[string]string{"pkg:npm/a@1.0.0": "npm", "pkg:npm/b@2.0.0": "applications"},
		FoundIn:     map[string][]string{"pkg:npm/a@1.0.0": {"App.app", "~/.nvm"}, "pkg:npm/b@2.0.0": {"App.app"}},
		Fixes:       map[string]vulnx.HostFix{"App.app": {Kind: "app", Note: "update App"}, "~/.nvm": {Kind: "npm", Command: "npm update -g"}},
		Paths:       map[string]string{"App.app": "/Applications/App.app"}}
	res := vulnx.StackResult{Items: []vulnx.StackItem{
		{Input: "pkg:npm/a@1.0.0", Status: "affected", WorstSeverity: "critical", FixedVersion: "1.2.0",
			AdvisoryRows: []vulnx.StackAdvisory{{CVE: "CVE-1", Severity: "critical", Name: "</script> RCE"}, {AdvisoryID: "GHSA-x", Severity: "low"}}},
		{Input: "pkg:npm/b@2.0.0", Status: "affected", WorstSeverity: "high", AdvisoryRows: []vulnx.StackAdvisory{{CVE: "CVE-1", Severity: "critical"}}},
		{Input: "pkg:npm/c@3.0.0", Status: "clean"}}}
	g := buildHostGraph(inv, res, time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC))
	if len(g.Comps) != 2 || len(g.Advs) != 2 || len(g.Places) != 2 || g.Checked != 3 || g.Date != "2026-11-13" {
		t.Fatalf("graph %+v", g)
	}
	a := g.Comps[0]
	if a.Name != "a" || a.Fixed != "1.2.0" || len(a.Places) != 2 || len(a.Advs) != 2 || g.Comps[1].Advs[0] != a.Advs[0] {
		t.Fatalf("an advisory two components share is one node: %+v %+v", a, g.Comps[1])
	}
	if g.Places[a.Places[0]].Path != "/Applications/App.app" || g.Places[a.Places[1]].Path != "" {
		t.Fatalf("paths %+v", g.Places)
	}
	if g.Places[a.Places[0]].Fix != "update App" || g.Places[a.Places[1]].Fix != "npm update -g" {
		t.Fatalf("places %+v", g.Places)
	}
	dir := t.TempDir()
	t.Chdir(dir)
	path, err := writeHostGraph(inv, res)
	if err != nil {
		t.Fatal(err)
	}
	page, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(page), "/*DATA*/") || strings.Contains(string(page), "</script> RCE") || !strings.Contains(string(page), `\u003c/script\u003e RCE`) {
		t.Fatal("the data is embedded, and cannot close its script element")
	}
}
