package clis

// vulnx scan --host's default view: one screen of findings per source and severity, and the agent setup under it.

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/projectdiscovery/vulnx/v2"
	"github.com/projectdiscovery/vulnx/v2/pkg/tools/renderer"
)

// gridRow is one source of a host scan: what it checked and its reachable findings by worst severity.
type gridRow struct {
	Name      string
	Checked   int
	Severity  [4]int // critical, high, medium, low
	Exploited int    // with a known exploited CVE
}

var gridSeverities = []string{"critical", "high", "medium", "low"}

// gridBar draws a grid bar: a block a little short of the line's height, so bars in adjacent rows stay apart.
const gridBar = "▆"

// gridColors are the bars' colors: red, orange, yellow, green, as the report's.
var gridColors = map[string]string{"critical": "\033[38;5;203m", "high": "\033[38;5;208m", "medium": "\033[38;5;178m", "low": "\033[38;5;71m"}

// hostCounts are a host scan's headline numbers.
type hostCounts struct {
	Checked, Affected, Reachable, Exploited, PublicExploit, NotLinked int
}

// hostGrid counts a host scan per source (in the order they were read; a source that checked nothing is left
// out), with the totals and headline numbers.
func hostGrid(inv vulnx.HostInventory, res vulnx.StackResult) (rows []gridRow, total gridRow, counts hostCounts) {
	byName := map[string]*gridRow{}
	for _, s := range inv.Sources {
		if s.Sent == 0 {
			continue
		}
		rows = append(rows, gridRow{Name: s.Name, Checked: s.Sent})
	}
	for i := range rows {
		byName[rows[i].Name] = &rows[i]
	}
	fs := findings(inv, res)
	for _, f := range fs {
		sev := slices.Index(gridSeverities, f.worst)
		row := byName[inv.EntrySource[f.item.Input]]
		if f.tier == tierKEV {
			counts.Exploited++
		} else if f.mark == "POC" {
			counts.PublicExploit++
		}
		if row == nil || sev < 0 {
			continue
		}
		row.Severity[sev]++
		if f.tier == tierKEV {
			row.Exploited++
		}
	}
	total.Name = "total"
	for _, r := range rows {
		total.Checked += r.Checked
		total.Exploited += r.Exploited
		for i, n := range r.Severity {
			total.Severity[i] += n
		}
	}
	for _, it := range res.Items {
		if it.Status == "affected" && unreachable(it) {
			counts.NotLinked++
		}
	}
	counts.Checked, counts.Affected, counts.Reachable = len(inv.Entries), res.Summary.Affected, len(fs)
	return rows, total, counts
}

// hostFooter is the last line of the grid view, after any report links: what was scanned and how long it took.
func hostFooter(inv vulnx.HostInventory, elapsed time.Duration, c *renderer.ColorConfig) string {
	line := fmt.Sprintf("%s: %s components scanned", termClean(inv.OS), thousands(len(inv.Entries)))
	if elapsed > 0 {
		line += " in " + elapsed.Round(time.Second).String()
	}
	return "\n  " + c.Colorize(line, renderer.Gray) + "\n"
}

// renderHostGrid is the default view, one screen: the headline numbers and, per source, its findings by severity.
func renderHostGrid(inv vulnx.HostInventory, res vulnx.StackResult, elapsed time.Duration, c *renderer.ColorConfig) string {
	var b strings.Builder
	dim := func(t string) string { return c.Colorize(t, renderer.Gray) }
	rows, total, n := hostGrid(inv, res)
	fmt.Fprintf(&b, "\n  %s affected   %s reachable   %s known exploited   %s public exploit\n\n",
		c.Colorize(thousands(n.Affected), renderer.Bold), c.Colorize(thousands(n.Reachable), renderer.Bold),
		c.Colorize(thousands(n.Exploited), renderer.Bold+renderer.BrightRed), c.Colorize(thousands(n.PublicExploit), renderer.Bold))

	width := len("SOURCE")
	peak := 1
	for _, r := range rows {
		width = max(width, len(r.Name))
		for _, v := range r.Severity {
			peak = max(peak, v)
		}
	}
	const bar = 6
	cell := func(v int, sev string) string {
		// the number first, so numbers line up and every bar starts at the same column
		if v == 0 {
			return dim(fmt.Sprintf("%4s ", "-")) + strings.Repeat(" ", bar)
		}
		blocks := max(1, (v*bar+peak-1)/peak)
		return fmt.Sprintf("%4d ", v) + c.Colorize(strings.Repeat(gridBar, blocks), gridColors[sev]) + strings.Repeat(" ", bar-blocks)
	}
	b.WriteString("  " + dim(fmt.Sprintf("%-*s  %-11s  %-11s  %-11s  %-11s  %9s  %8s", width, "SOURCE", "CRITICAL", "HIGH", "MEDIUM", "LOW",
		"EXPLOITED", "CHECKED")) + "\n")
	line := func(r gridRow, bars bool) {
		fmt.Fprintf(&b, "  %-*s", width, r.Name)
		for i, v := range r.Severity {
			if bars {
				b.WriteString("  " + cell(v, gridSeverities[i]))
			} else {
				fmt.Fprintf(&b, "  %4s%7s", thousands(v), "")
			}
		}
		exploited := fmt.Sprintf("%9s", "-")
		if r.Exploited > 0 {
			exploited = c.Colorize(fmt.Sprintf("%9d", r.Exploited), renderer.Bold+renderer.BrightRed)
		} else {
			exploited = dim(exploited)
		}
		fmt.Fprintf(&b, "  %s  %8s\n", exploited, thousands(r.Checked))
	}
	for _, r := range rows {
		line(r, true)
	}
	b.WriteString("  " + dim(strings.Repeat("─", width+2+4*13+9+2+8-2)) + "\n")
	line(total, false)
	b.WriteString("\n")
	b.WriteString(agentSetup(inv, c))
	if len(inv.NotAssessed) > 0 {
		var parts []string
		for _, s := range inv.Sources {
			if s.NotAssessed > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", s.NotAssessed, s.Name))
			}
		}
		b.WriteString(dim(fmt.Sprintf("  Not checked: %s with no exact identifier (%s)", thousands(len(inv.NotAssessed)), strings.Join(parts, ", "))) + "\n")
	}
	if n.NotLinked > 0 {
		b.WriteString(dim(fmt.Sprintf("  Not counted: %s Go module versions no program can reach", thousands(n.NotLinked))) + "\n")
	}
	if res.FunctionsUnavailable {
		b.WriteString(dim("  Go reachability was not checked (the API does not serve affected functions yet)") + "\n")
	}
	return b.String()
}

var agentKinds = []struct{ kind, one, many string }{
	{"extension", "editor extension", "editor extensions"}, {"skill", "skill", "skills"}, {"plugin", "plugin", "plugins"},
	{"hook", "hook", "hooks"}, {"mcp_server", "MCP server", "MCP servers"}, {"model", "local model", "local models"},
}

// infoRisks are true of most machines that run local models: said, in grey, without the mark of a finding.
var infoRisks = map[string]bool{"pickle_format": true, "custom_code": true}

var agentRisks = []string{"model_runs_commands", "exposed", "removed_malware", "removed", "lookalike", "sideloaded", "pipe_to_shell", "hidden_text", "unverified_source", "unpinned", "plaintext", "approvals_off", "pickle_format", "custom_code"}

var riskSubject = map[string][2]string{
	"extension": {"extension", "extensions"}, "skill": {"skill", "skills"}, "hook": {"hook", "hooks"},
	"mcp_server": {"MCP server", "MCP servers"}, "agent": {"agent", "agents"}, "plugin": {"plugin", "plugins"},
	"model": {"local model", "local models"}, "runtime": {"model runtime", "model runtimes"},
}

// agentSetup is the block under the grid for what agents and editors load: what was read, then one line per kind
// of risk with the names it applies to. These are risks in how things are set up, not known vulnerabilities, so
// they stay out of the severity columns.
func agentSetup(inv vulnx.HostInventory, c *renderer.ColorConfig) string {
	if len(inv.AgentSurface) == 0 && len(inv.Risks) == 0 {
		return ""
	}
	dim := func(t string) string { return c.Colorize(t, renderer.Gray) }
	n := map[string]int{}
	for _, it := range inv.AgentSurface {
		n[it.Kind]++
	}
	var parts []string
	for _, k := range agentKinds {
		if n[k.kind] == 1 {
			parts = append(parts, "1 "+k.one)
		} else if n[k.kind] > 1 {
			parts = append(parts, fmt.Sprintf("%d %s", n[k.kind], k.many))
		}
	}
	var b strings.Builder
	head := "  Agent setup: " + strings.Join(parts, ", ")
	findings := 0
	for _, r := range inv.Risks {
		if !infoRisks[r.Risk] {
			findings++
		}
	}
	if len(inv.Risks) == 0 {
		return dim(head+", no risky setup found") + "\n"
	}
	if findings == 0 {
		head += ", no risky setup found"
	}
	b.WriteString(head + "\n")
	for _, risk := range agentRisks {
		var names []string
		kind := ""
		for _, r := range inv.Risks {
			if r.Risk == risk {
				kind = r.Kind
				if name := termClean(r.Name); !slices.Contains(names, name) {
					names = append(names, name)
				}
			}
		}
		if len(names) == 0 {
			continue
		}
		subject := riskSubject[kind][1]
		if len(names) == 1 {
			subject = riskSubject[kind][0]
		}
		shown := names
		if len(shown) > 4 {
			shown = append(slices.Clone(names[:4]), fmt.Sprintf("+%d", len(names)-4))
		}
		text := fmt.Sprintf("%d %s %s: %s", len(names), subject, vulnx.RiskText[risk], strings.Join(shown, ", "))
		if infoRisks[risk] {
			b.WriteString(dim("      "+text) + "\n")
			continue
		}
		b.WriteString("    " + c.Colorize("!", gridColors["high"]) + " " + text + "\n")
	}
	return b.String()
}
