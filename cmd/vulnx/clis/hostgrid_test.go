package clis

import (
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/vulnx/v2"
	"github.com/projectdiscovery/vulnx/v2/pkg/tools/renderer"
)

// TestRenderHostGrid is the default view: the headline, one row per source that checked something, and totals.
func TestRenderHostGrid(t *testing.T) {
	inv, res := hostFixture()
	out := renderHost("grid", inv, res, 7*time.Second, false, renderer.NoColorConfig())
	for _, want := range []string{
		"  7 affected   6 reachable   3 known exploited   1 public exploit\n",
		"  SOURCE        CRITICAL     HIGH         MEDIUM       LOW          EXPLOITED   CHECKED\n",
		"  macOS            1 ▆▆▆▆▆▆     -            -            -                 1         1\n",
		"  python           -            1 ▆▆▆▆▆▆     1 ▆▆▆▆▆▆     -                 -         2\n",
		"  go binaries      1 ▆▆▆▆▆▆     -            -            -                 1         2\n",
		"  total            3            2            1            0                 3         9\n",
		"\n  Not checked    1 with no exact identifier: 1 homebrew\n",
		"\n  Not counted    1 Go module version no program links\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "rust binaries") {
		t.Errorf("an empty source:\n%s", out)
	}
}

func TestHostFooter(t *testing.T) {
	inv, _ := hostFixture()
	if got := hostFooter(inv, 7*time.Second, renderer.NoColorConfig()); got != "\n  Scanned        macOS 26.4 · 9 components · 7s\n" {
		t.Errorf("%q", got)
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

func TestAgentSetup(t *testing.T) {
	c := renderer.NoColorConfig()
	if got := agentSetup(vulnx.HostInventory{}, c); got != "" {
		t.Fatalf("nothing read: %q", got)
	}
	inv := vulnx.HostInventory{AgentSurface: []vulnx.HostAgentItem{{Kind: "extension"}, {Kind: "extension"}, {Kind: "skill"}, {Kind: "mcp_server"}}}
	if got, want := agentSetup(inv, c), "  Agent setup    2 editor extensions · 1 skill · 1 MCP server · no risky setup found\n"; got != want {
		t.Fatalf("got %q", got)
	}
	inv.Risks = []vulnx.HostRisk{{Risk: "unpinned", Kind: "mcp_server", Name: "files"}, {Risk: "unpinned", Kind: "mcp_server", Name: "files"},
		{Risk: "unpinned", Kind: "mcp_server", Name: "web"}, {Risk: "lookalike", Kind: "extension", Name: "evil.python"}}
	inv.Risks = append(inv.Risks, vulnx.HostRisk{Risk: "pickle_format", Kind: "model", Name: "llama"}, vulnx.HostRisk{Risk: "pipe_to_shell", Kind: "skill", Name: "slack-cli"},
		vulnx.HostRisk{Risk: "pipe_to_shell", Kind: "skill", Name: "origin"}, vulnx.HostRisk{Risk: "plaintext", Kind: "mcp_server", Name: "pulse"})
	want := "  Agent setup    2 editor extensions · 1 skill · 1 MCP server\n" +
		"                 ! 1 extension is named like a well-known extension from another publisher: evil.python\n" +
		"                 ! 2 skills download and run code: slack-cli, origin\n" +
		"                 ! 2 MCP servers run the newest version at every start: files, web\n" +
		"                 ! 1 MCP server is reached over unencrypted HTTP: pulse\n" +
		"                 · 1 local model uses a format that can run code when loaded (pickle): llama\n"
	if got := agentSetup(inv, c); got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}
