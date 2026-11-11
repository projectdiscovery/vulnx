package clis

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/vulnx/v2"
	"github.com/projectdiscovery/vulnx/v2/pkg/tools/renderer"
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

func TestVersionLess(t *testing.T) {
	for _, c := range []struct {
		a, b string
		less bool
	}{
		{"v1.9.2", "v1.10.0", true},
		{"0.62.0", "0.38.0", false},
		{"0.58.1-0.20250101-abc", "0.58.1", true}, // the release wins over its pseudo-version
	} {
		if versionLess(c.a, c.b) != c.less {
			t.Errorf("%s < %s should be %v", c.a, c.b, c.less)
		}
	}
}

// TestRenderHostText groups a component found at several versions into one row, names where it was found, and
// lists what was not assessed by source.
func TestRenderHostText(t *testing.T) {
	net1, net2 := "pkg:golang/golang.org/x/net@v0.7.0", "pkg:golang/golang.org/x/net@v0.15.0"
	inv := vulnx.HostInventory{
		OS:      "macOS 26.4",
		Entries: []string{net1, net2, "pkg:pypi/requests@2.31.0"},
		FoundIn: map[string][]string{net1: {"caddy"}, net2: {"act", "gh"}, "pkg:pypi/requests@2.31.0": {"/opt/homebrew"}},
		Sources: []vulnx.HostSource{{Name: "go binaries", Sent: 2, Detail: "3 binaries"}, {Name: "python", Sent: 1, Detail: "1 site-packages dir"},
			{Name: "homebrew", NotAssessed: 1, Detail: "1 formula"}},
		NotAssessed: []vulnx.HostComponent{{Name: "cairo", Version: "1.18.4", Source: "homebrew"}},
		NotRead:     []string{"virtualenvs"},
	}
	res := vulnx.StackResult{
		Summary: vulnx.StackSummary{Packages: 3, Affected: 2, Clean: 1, BySeverity: map[string]int{"high": 2}},
		Items: []vulnx.StackItem{
			{Input: net1, Status: "affected", WorstSeverity: "high", Advisories: 9, FixedVersion: "0.38.0"},
			{Input: net2, Status: "affected", WorstSeverity: "medium", Advisories: 4, FixedVersion: "0.36.0"},
			{Input: "pkg:pypi/requests@2.31.0", Status: "clean"},
		},
	}
	out := renderHostText(inv, res, false, renderer.NoColorConfig())
	for _, want := range []string{
		"macOS 26.4 · 3 components checked · 1 not assessed",
		"go binaries           2             -  3 binaries",
		"Not read: virtualenvs",
		"2 affected · 0 undetermined · 1 clean",
		"Fix first · 1 affected component\n",
		"high         go      golang.org/x/net                 2 versions            9 0.38.0       -       caddy, act, gh",
		"high         caddy                                       1 golang.org/x/net",
		"homebrew (1): cairo",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "requests") {
		t.Errorf("a clean component is listed:\n%s", out)
	}
}

// TestRenderHostReachability leaves out a module version no binary can run, counts only the binaries that link an
// affected function, and drops a binary that links none from the places to update.
func TestRenderHostReachability(t *testing.T) {
	gone, part, open := "pkg:golang/github.com/a/b@v1.0.0", "pkg:golang/golang.org/x/net@v0.7.0", "pkg:golang/github.com/c/d@v2.0.0"
	inv := vulnx.HostInventory{OS: "macOS 26.4", Entries: []string{gone, part, open},
		FoundIn: map[string][]string{gone: {"tool1"}, part: {"caddy", "act"}, open: {"tool2", "tool3"}}}
	res := vulnx.StackResult{
		Summary: vulnx.StackSummary{Packages: 2, Affected: 2},
		Items: []vulnx.StackItem{
			{Input: gone, Package: "go/github.com/a/b", Status: "affected", WorstSeverity: "critical", Advisories: 1,
				AdvisoryRows: []vulnx.StackAdvisory{{AdvisoryID: "GO-1", Severity: "critical", Reachability: "not_reachable"}},
				Reachability: &vulnx.ItemReachability{NotReachable: []string{"tool1"}}},
			{Input: part, Package: "go/golang.org/x/net", Status: "affected", WorstSeverity: "critical", Advisories: 2,
				AdvisoryRows: []vulnx.StackAdvisory{{AdvisoryID: "GO-2", Severity: "critical", Reachability: "not_reachable"},
					{AdvisoryID: "GO-3", Severity: "medium", Reachability: "reachable"}},
				Reachability: &vulnx.ItemReachability{Reachable: []string{"caddy"}, NotReachable: []string{"act"}}},
			{Input: open, Package: "go/github.com/c/d", Status: "affected", WorstSeverity: "medium", Advisories: 1,
				AdvisoryRows: []vulnx.StackAdvisory{{AdvisoryID: "GO-4", Severity: "medium"}},
				Reachability: &vulnx.ItemReachability{NotReachable: []string{"tool2"}, Unknown: []string{"tool3"}}},
		},
	}
	out := renderHostText(inv, res, false, renderer.NoColorConfig())
	for _, want := range []string{
		"Go reachability: of 5 affected module copies in binaries, 1 link an affected function, 3 link none, 1 unknown",
		// the critical row no binary runs no longer sets the severity; one of two binaries links the medium one, and
		// it comes before an equally severe one no binary is shown to link
		"medium       go      golang.org/x/net                 v0.7.0                1              1/2     caddy\n" +
			"  medium       go      github.com/c/d                   v2.0.0                1              0/2?    tool3",
		"left out: 1 Go module versions whose binaries link none of the affected functions",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	for _, unwanted := range []string{"github.com/a/b", "tool1", "act  "} {
		if strings.Contains(out, unwanted) {
			t.Errorf("unexpected %q in\n%s", unwanted, out)
		}
	}
}

// TestRenderHostTextColorAligns pads the sources header before coloring it, so it lines up with its rows.
func TestRenderHostTextColorAligns(t *testing.T) {
	inv := vulnx.HostInventory{OS: "macOS", Sources: []vulnx.HostSource{{Name: "python", Sent: 1, Detail: "1 dir"}}}
	out := renderHostText(inv, vulnx.StackResult{}, false, renderer.DefaultColorConfig())
	plain := regexp.MustCompile("\x1b\\[[0-9;]*m").ReplaceAllString(out, "")
	if !strings.Contains(plain, "  SOURCE          CHECKED  NOT ASSESSED  READ FROM\n") {
		t.Errorf("header misaligned:\n%s", plain)
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

func TestHostReports(t *testing.T) {
	inv, res := hostFixture()
	c := renderer.NoColorConfig()
	for view, wants := range map[string][]string{
		"actions": {"macOS 26.4 · 9 components · 7 affected (6 a program can reach) · 3 known exploited",
			"Update now · known exploited\n  Software Update (softwareupdate --install --all)\n      macOS 26.4 → 26.7.3\n",
			"  go install github.com/air-verse/air@latest\n      air: x/net\n",
			"Later: 1 more update for medium and low findings", "Skipped: 1 Go module versions no binary can reach",
			"Not checked: 1 without an exact identifier (1 homebrew"},
		"brief": {"Update now: Software Update, Google Chrome, 1 Homebrew formula, 1 Go tool",
			"Next:       1 Homebrew formula", "Then:       1 Python package"},
		"programs": {"critical caddy KEV  brew upgrade caddy\n    critical x/net v0.7.0\n",
			"high     /opt/homebrew (python3.12)  /opt/homebrew/bin/python3.12 -m pip install -U"},
		"markdown": {"### Update now · known exploited", "- [ ] `brew upgrade caddy`\n  - caddy: x/net\n",
			"- [ ] `/opt/homebrew/bin/python3.12 -m pip install -U lxml`: lxml 4.9.3 → 6.1.0"},
	} {
		out := renderHost(view, inv, res, 0, false, c)
		for _, w := range wants {
			if !strings.Contains(out, w) {
				t.Errorf("%s: missing %q in\n%s", view, w, out)
			}
		}
		if strings.Contains(out, "a/b") {
			t.Errorf("%s: lists a module version no binary reaches:\n%s", view, out)
		}
	}
}

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

// TestRenderHostGrid is the default view: the headline, one row per source that checked something, and totals.
func TestRenderHostGrid(t *testing.T) {
	inv, res := hostFixture()
	out := renderHost("grid", inv, res, 7*time.Second, false, renderer.NoColorConfig())
	for _, want := range []string{
		"macOS 26.4: 9 components scanned in 7s\n",
		"  7 affected   6 reachable   3 known exploited   1 public exploit\n",
		"  SOURCE        CRITICAL     HIGH         MEDIUM       LOW          EXPLOITED   CHECKED\n",
		"  macOS            1 ▆▆▆▆▆▆     -            -            -                 1         1\n",
		"  python           -            1 ▆▆▆▆▆▆     1 ▆▆▆▆▆▆     -                 -         2\n",
		"  go binaries      1 ▆▆▆▆▆▆     -            -            -                 1         2\n",
		"  total            3            2            1            0                 3         9\n",
		"Not checked: 1 with no exact identifier (1 homebrew)",
		"Not counted: 1 Go module versions no program can reach",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "rust binaries") || strings.Contains(out, "·") {
		t.Errorf("an empty source or a dot separator:\n%s", out)
	}
}

// TestHostReportHTML writes the report as one HTML file with every section and escaped content.
func TestHostReportHTML(t *testing.T) {
	inv, res := hostFixture()
	inv.NotAssessed[0].Name = "cairo <b>"
	path, err := writeHostReport(filepath.Join(t.TempDir(), "r.html"), inv, res, 7*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, want := range []string{
		"<h1>macOS 26.4</h1>", "9 components scanned in 7s", "<h2>By source</h2>", "<h2>Where to fix</h2>",
		`data-copy="brew upgrade caddy php"`, "<h2>Affected versions</h2>",
		`<span class="nm">x/net<span class="kind">go</span></span>`,
		// one block: a kind of update with its count and how urgent its items are
		`<span class="gt">Homebrew formulae</span><span class="gc">2</span><span class="gu"><span class="badge kev">1 known exploited</span><span class="badge poc">1 public exploit</span></span>`,
		// an interpreter updated at two urgencies is one row, its command naming both packages
		`<span class="gt">Python packages</span><span class="gc">2</span>`, `<span class="dim mono"> in /opt/homebrew</span>`,
		`data-copy="/opt/homebrew/bin/python3.12 -m pip install -U lxml wheel"`,
		"2 of 2 programs reach it",
		// left out: collapsed lines with their lists and a Copy of the identifiers
		`<span class="gt">Not reachable</span><span class="gc">1</span>`, `data-copy="pkg:golang/github.com/a/b@v1.0.0"`,
		`<span class="iname mono">github.com/a/b</span> <span class="badge">1</span> <span class="dim mono">v1.0.0</span>`,
		`<span class="gt">Not checked</span><span class="gc">1</span><span class="plain">no exact identifier to check (1 homebrew)</span>`, "cairo &lt;b&gt;",
		// the filters read these
		`data-severity="critical" data-exploit="known exploited" data-source="go binaries" data-type="go"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("missing %q", want)
		}
	}
	if !filepath.IsAbs(path) || strings.Contains(html, "<b>\"") {
		t.Errorf("path %s", path)
	}
}

// TestRenderHostGridColors colors each bar by its column's severity.
func TestRenderHostGridColors(t *testing.T) {
	inv, res := hostFixture()
	out := renderHost("grid", inv, res, 0, false, renderer.DefaultColorConfig())
	for sev, color := range gridColors {
		if sev != "low" && !strings.Contains(out, color+gridBar) { // the fixture has no low finding
			t.Errorf("no %s bar in its color", sev)
		}
	}
}
