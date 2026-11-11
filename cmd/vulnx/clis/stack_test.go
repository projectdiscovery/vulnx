package clis

import (
	"strings"
	"testing"

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
		"high         go      golang.org/x/net                 2 versions            9 0.38.0       caddy, act, gh",
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
