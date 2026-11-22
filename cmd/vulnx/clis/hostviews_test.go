package clis

import (
	"regexp"
	"strings"
	"testing"

	"github.com/projectdiscovery/vulnx/v2"
	"github.com/projectdiscovery/vulnx/v2/pkg/tools/renderer"
)

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
		"macOS 26.4 · 3 components checked · 1 not checked",
		"go binaries           2             -  3 binaries",
		"Not read: virtualenvs",
		"2 affected · 0 undetermined · 1 clean · 0 not in the index",
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
		"Go reachability: of 5 affected module copies in programs, 1 link an affected function, 3 link none, 1 unknown",
		// the critical row no binary runs no longer sets the severity; one of two binaries links the medium one, and
		// it comes before an equally severe one no binary is shown to link
		"medium       go      golang.org/x/net                 v0.7.0                1              1/2     caddy\n" +
			"  medium       go      github.com/c/d                   v2.0.0                1              0/2?    tool3",
		"Not counted: 1 Go module versions no program can reach",
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
	if !strings.Contains(plain, "  SOURCE          CHECKED   NOT CHECKED  READ FROM\n") {
		t.Errorf("header misaligned:\n%s", plain)
	}
}

func TestHostReports(t *testing.T) {
	inv, res := hostFixture()
	c := renderer.NoColorConfig()
	for view, wants := range map[string][]string{
		"actions": {"macOS 26.4 · 9 components · 7 affected (6 a program can reach) · 3 known exploited",
			"Update now · known exploited\n  Software Update (softwareupdate --install --all)\n      macOS 26.4 → 26.7.3\n",
			"  go install github.com/air-verse/air@latest\n      air: x/net\n",
			"Later: 1 more update for medium and low findings", "Not counted: 1 Go module versions no program can reach",
			"Not checked: 1 with no exact identifier (1 homebrew"},
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

// TestFit cleans a name for the terminal before cutting it, so a control or bidi character counts for nothing.
func TestFit(t *testing.T) {
	if got := fit("a\u202eb\x1bcdef", 4); got != "abc…" {
		t.Errorf("fit %q", got)
	}
}
