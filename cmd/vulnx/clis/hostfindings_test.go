package clis

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/projectdiscovery/vulnx/v2"
)

func TestComponentParts(t *testing.T) {
	for _, c := range []struct{ in, kind, name, version string }{
		{"pkg:golang/golang.org/x/net@v0.17.0", "go", "golang.org/x/net", "v0.17.0"},
		{"pkg:npm/%40scope/tool@1.2.3", "npm", "@scope/tool", "1.2.3"},
		{"pkg:deb/debian/libc6@2.36-9%2Bdeb12u7?arch=arm64&distro=debian-12", "deb", "libc6", "2.36-9+deb12u7"},
		{"pkg:cargo/hyper@0.14.10", "crate", "hyper", "0.14.10"},
		{`cpe:2.3:a:zoom:zoom:7.1.9\ \(88375\):*:*:*:*:*:*:*`, "product", "zoom:zoom", "7.1.9 (88375)"},
	} {
		k, n, v := componentParts(c.in)
		if k != c.kind || n != c.name || v != c.version {
			t.Errorf("%s: %s %s %s", c.in, k, n, v)
		}
	}
}

// hostFixture is a small host scan: macOS with a known exploited CVE, Chrome, two formulae (one reached through its
// Go binary), a Go tool from ~/go/bin, a pip site with two packages, and a module version no binary reaches.
func hostFixture() (vulnx.HostInventory, vulnx.StackResult) {
	exploited := func(sev string, known, poc bool) []vulnx.StackAdvisory {
		var rows []vulnx.StackAdvisory
		raw := fmt.Sprintf(`[{"advisory_id": "A", "severity": %q, "exploitation": {"known_exploited": %v, "public_exploit": %v}}]`, sev, known, poc)
		if err := json.Unmarshal([]byte(raw), &rows); err != nil {
			panic(err)
		}
		return rows
	}
	inv := vulnx.HostInventory{
		OS:      "macOS 26.4",
		Entries: make([]string, 9),
		FoundIn: map[string][]string{
			"cpe:macos":                          {"macOS"},
			"cpe:2.3:a:google:chrome:1.0:*":      {"Google Chrome.app"},
			"cpe:2.3:a:php:php:8.5.2:*":          {"php (formula)"},
			"pkg:golang/golang.org/x/net@v0.7.0": {"caddy", "air"},
			"pkg:pypi/lxml@4.9.3":                {"/opt/homebrew (python3.12)"},
			"pkg:pypi/wheel@0.41.2":              {"/opt/homebrew (python3.12)"},
			"pkg:golang/github.com/a/b@v1.0.0":   {"caddy"},
		},
		Fixes: map[string]vulnx.HostFix{
			"macOS":                      {Kind: "macos", Note: "Software Update (softwareupdate --install --all)"},
			"Google Chrome.app":          {Kind: "app", Target: "Google Chrome", Note: "update Google Chrome"},
			"php (formula)":              {Kind: "brew", Command: "brew upgrade", Target: "php"},
			"caddy":                      {Kind: "brew", Command: "brew upgrade", Target: "caddy"},
			"air":                        {Kind: "go-install", Command: "go install", Target: "github.com/air-verse/air@latest"},
			"/opt/homebrew (python3.12)": {Kind: "pip", Command: "/opt/homebrew/bin/python3.12 -m pip install -U"},
		},
		Sources: []vulnx.HostSource{{Name: "macOS", Sent: 1}, {Name: "python", Sent: 2}, {Name: "go binaries", Sent: 2},
			{Name: "rust binaries"}, {Name: "homebrew", Sent: 1, NotAssessed: 1}, {Name: "applications", Sent: 3}},
		EntrySource: map[string]string{
			"cpe:2.3:o:apple:macos:26.4": "macOS", "cpe:2.3:a:google:chrome:1.0:*": "applications", "cpe:2.3:a:php:php:8.5.2:*": "homebrew",
			"pkg:golang/golang.org/x/net@v0.7.0": "go binaries", "pkg:golang/github.com/a/b@v1.0.0": "go binaries",
			"pkg:pypi/lxml@4.9.3": "python", "pkg:pypi/wheel@0.41.2": "python",
		},
		NotAssessed: []vulnx.HostComponent{{Name: "cairo", Version: "1.18.4", Source: "homebrew"}},
	}
	res := vulnx.StackResult{Summary: vulnx.StackSummary{Affected: 7}, Items: []vulnx.StackItem{
		{Input: "cpe:2.3:o:apple:macos:26.4", Status: "affected", WorstSeverity: "critical", FixedVersion: "26.7.3", AdvisoryRows: exploited("critical", true, true)},
		{Input: "cpe:2.3:a:google:chrome:1.0:*", Status: "affected", WorstSeverity: "high", FixedVersion: "1.1", AdvisoryRows: exploited("high", true, false)},
		{Input: "cpe:2.3:a:php:php:8.5.2:*", Status: "affected", WorstSeverity: "critical", FixedVersion: "8.5.12", AdvisoryRows: exploited("critical", false, true)},
		{Input: "pkg:golang/golang.org/x/net@v0.7.0", Package: "go/golang.org/x/net", Status: "affected", WorstSeverity: "critical",
			AdvisoryRows: exploited("critical", true, false), Reachability: &vulnx.ItemReachability{Reachable: []string{"caddy", "air"}}},
		{Input: "pkg:pypi/lxml@4.9.3", Status: "affected", WorstSeverity: "high", FixedVersion: "6.1.0", AdvisoryRows: exploited("high", false, false)},
		{Input: "pkg:pypi/wheel@0.41.2", Status: "affected", WorstSeverity: "medium", FixedVersion: "0.46.2", AdvisoryRows: exploited("medium", false, false)},
		{Input: "pkg:golang/github.com/a/b@v1.0.0", Package: "go/github.com/a/b", Status: "affected", WorstSeverity: "critical",
			AdvisoryRows: []vulnx.StackAdvisory{{AdvisoryID: "B", Severity: "critical", Reachability: "not_reachable"}},
			Reachability: &vulnx.ItemReachability{NotReachable: []string{"caddy"}}},
	}}
	inv.FoundIn["cpe:2.3:o:apple:macos:26.4"] = inv.FoundIn["cpe:macos"]
	return inv, res
}

func TestHostActions(t *testing.T) {
	inv, res := hostFixture()
	var got []string
	for _, a := range hostActions(inv, findings(inv, res)) {
		got = append(got, fmt.Sprintf("%d %s", a.tier, a.line()))
	}
	want := []string{
		"0 Software Update (softwareupdate --install --all)",
		"0 update Google Chrome",
		"0 brew upgrade caddy",                         // x/net, known exploited, reached in caddy
		"0 go install github.com/air-verse/air@latest", // and in air
		"1 brew upgrade php",                           // critical with a public exploit
		"2 /opt/homebrew/bin/python3.12 -m pip install -U lxml",
		"3 /opt/homebrew/bin/python3.12 -m pip install -U wheel",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("actions:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestHostActionLine quotes what a command names, so a name read from disk is one word to the shell.
func TestHostActionLine(t *testing.T) {
	a := hostAction{fix: vulnx.HostFix{Kind: "brew", Command: "brew upgrade"}, targets: []string{"php", "x; rm -rf ~", "it's"}}
	if got := a.line(); got != `brew upgrade php 'x; rm -rf ~' 'it'\''s'` {
		t.Errorf("%s", got)
	}
	note := hostAction{fix: vulnx.HostFix{Kind: "app", Note: "update Evil\x1b[31m"}}
	if got := note.line(); got != "update Evil[31m" {
		t.Errorf("%q", got)
	}
}
