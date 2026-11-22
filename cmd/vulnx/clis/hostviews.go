package clis

// vulnx scan --host's other terminal views (--view): actions, brief, programs, details and markdown.

import (
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/projectdiscovery/vulnx/v2"
	"github.com/projectdiscovery/vulnx/v2/pkg/tools/renderer"
	"golang.org/x/term"
)

func colorConfig() *renderer.ColorConfig {
	if noColor || !renderer.IsTerminal() {
		return renderer.NoColorConfig()
	}
	return renderer.DefaultColorConfig()
}

// thousands formats n with comma separators.
func thousands(n int) string {
	s := fmt.Sprint(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// hostFixFirst is how many affected components a host report lists before --show-all.
const hostFixFirst = 25

// hostNotAssessedNames is how many not-assessed names per source a host report lists before --show-all.
const hostNotAssessedNames = 12

// termClean drops control characters (newline and tab kept) and Unicode format characters (bidi overrides,
// zero-width marks, tag characters) from text read from disk or the API, so a name cannot move the cursor,
// recolour the terminal or reorder what the reader sees. Every such text passes it before it is printed.
func termClean(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == unicode.ReplacementChar {
			return -1
		}
		return r
	}, s)
}

// fit cleans s for the terminal and cuts it to n runes, an ellipsis last.
func fit(s string, n int) string {
	s = termClean(s)
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

// renderHostText is a host scan for a person: what was read, the components to fix first, and what was not
// checked. --json has every row.
func renderHostText(inv vulnx.HostInventory, res vulnx.StackResult, all bool, c *renderer.ColorConfig) string {
	var b strings.Builder
	title := func(t string) { b.WriteString("\n" + c.Colorize(t, renderer.Bold+renderer.BrightWhite) + "\n") }
	dim := func(t string) string { return c.Colorize(t, renderer.Gray) }

	notAssessed := len(inv.NotAssessed)
	title(fmt.Sprintf("%s · %s components checked · %s not assessed", termClean(inv.OS), thousands(len(inv.Entries)), thousands(notAssessed)))
	b.WriteString("  " + dim(fmt.Sprintf("%-14s %8s %13s  %s", "SOURCE", "CHECKED", "NOT ASSESSED", "READ FROM")) + "\n")
	for _, s := range inv.Sources {
		na := "-"
		if s.NotAssessed > 0 {
			na = thousands(s.NotAssessed)
		}
		detail := s.Detail
		if detail == "" {
			detail = s.Name
		}
		fmt.Fprintf(&b, "  %-14s %8s %13s  %s\n", s.Name, thousands(s.Sent), na, termClean(detail))
	}
	if len(inv.NotRead) > 0 {
		b.WriteString(dim("  Not read: "+termClean(strings.Join(inv.NotRead, "; "))) + "\n")
	}

	// counted from the rows: the API's summary counts these for packages, not for products (CPE entries)
	kev, poc := 0, 0
	exploit := map[string]string{}
	for _, it := range res.Items {
		if unreachable(it) {
			continue
		}
		for _, a := range it.AdvisoryRows {
			if a.Exploit == nil || a.Reachability == "not_reachable" {
				continue
			}
			if a.Exploit.KnownExploited {
				exploit[it.Input] = "KEV"
			} else if a.Exploit.PublicExploit && exploit[it.Input] == "" {
				exploit[it.Input] = "POC"
			}
		}
		switch exploit[it.Input] {
		case "KEV":
			kev++
		case "POC":
			poc++
		}
	}
	s := res.Summary
	title("Result")
	fmt.Fprintf(&b, "  %s affected · %s undetermined · %s clean\n",
		c.Colorize(thousands(s.Affected), renderer.Bold+renderer.Red), thousands(s.Undetermined), thousands(s.Clean))
	if kev > 0 || poc > 0 {
		fmt.Fprintf(&b, "  %s with a known exploited CVE · %s more with a public exploit\n",
			c.Colorize(thousands(kev), renderer.Bold+renderer.BrightRed), thousands(poc))
	}
	var sev []string
	for _, k := range []string{"critical", "high", "medium", "low"} {
		if n := s.BySeverity[k]; n > 0 {
			sev = append(sev, c.ColorSeverity(k)+" "+thousands(n))
		}
	}
	if len(sev) > 0 {
		b.WriteString("  worst severity: " + strings.Join(sev, " · ") + "\n")
	}
	if line := reachabilityLine(res); line != "" {
		b.WriteString("  " + line + "\n")
	}

	// one row per component (a module vendored at many versions by many binaries is one thing to fix)
	type group struct {
		kind, name, worst, mark, fix string
		versions, in                 []string
		cves, linked, carriers, open int
	}
	exploitRank := map[string]int{"KEV": 0, "POC": 1, "": 2}
	groups := map[string]*group{}
	var order []*group
	byKind := map[string]int{}
	// per place found: what to update
	type place struct {
		name, worst, mark string
		components        map[string]bool
	}
	places := map[string]*place{}
	var placeOrder []*place
	notLinked := 0
	for _, it := range res.Items {
		if it.Status != "affected" {
			continue
		}
		if unreachable(it) {
			notLinked++
			continue
		}
		worst, cves := liveSeverity(it)
		kind, name, version := componentParts(it.Input)
		key := kind + " " + name
		g := groups[key]
		if g == nil {
			g = &group{kind: kind, name: name, worst: worst}
			groups[key] = g
			order = append(order, g)
			byKind[kind]++
		}
		g.versions = append(g.versions, version)
		if r := it.Reachability; r != nil {
			g.linked += len(r.Reachable)
			g.open += len(r.Unknown)
			g.carriers += len(r.Reachable) + len(r.NotReachable) + len(r.Unknown)
		}
		if severityRank[worst] < severityRank[g.worst] {
			g.worst = worst
		}
		if m := exploit[it.Input]; exploitRank[m] < exploitRank[g.mark] {
			g.mark = m
		}
		g.cves = max(g.cves, cves)
		if g.fix == "" || versionLess(g.fix, it.FixedVersion) {
			g.fix = it.FixedVersion
		}
		for _, in := range inv.FoundIn[it.Input] {
			if it.Reachability != nil && slices.Contains(it.Reachability.NotReachable, in) {
				continue // this binary links none of the affected functions
			}
			if !slices.Contains(g.in, in) {
				g.in = append(g.in, in)
			}
			p := places[in]
			if p == nil {
				p = &place{name: in, worst: worst, components: map[string]bool{}}
				places[in] = p
				placeOrder = append(placeOrder, p)
			}
			p.components[name] = true
			if severityRank[worst] < severityRank[p.worst] {
				p.worst = worst
			}
			if m := exploit[it.Input]; exploitRank[m] < exploitRank[p.mark] {
				p.mark = m
			}
		}
	}
	urgent := func(m1, w1 string, n1 int, m2, w2 string, n2 int) bool {
		if exploitRank[m1] != exploitRank[m2] {
			return exploitRank[m1] < exploitRank[m2]
		}
		if severityRank[w1] != severityRank[w2] {
			return severityRank[w1] < severityRank[w2]
		}
		return n1 > n2
	}
	// at equal exploit and severity, a component a binary is known to link comes before one no binary is shown to
	sort.SliceStable(order, func(i, j int) bool {
		a, z := order[i], order[j]
		if a.mark == z.mark && a.worst == z.worst && (a.linked > 0) != (z.linked > 0) && a.carriers > 0 && z.carriers > 0 {
			return a.linked > 0
		}
		return urgent(a.mark, a.worst, a.cves, z.mark, z.worst, z.cves)
	})
	sort.SliceStable(placeOrder, func(i, j int) bool {
		a, z := placeOrder[i], placeOrder[j]
		return urgent(a.mark, a.worst, len(a.components), z.mark, z.worst, len(z.components))
	})
	markCol := func(m string) string {
		switch m {
		case "KEV":
			return c.Colorize("KEV", renderer.Bold+renderer.BrightRed)
		case "POC":
			return "POC"
		}
		return "   "
	}
	list := func(items []string, n int) string {
		if len(items) > n {
			return strings.Join(items[:n], ", ") + fmt.Sprintf(" +%d", len(items)-n)
		}
		return strings.Join(items, ", ")
	}
	if len(order) > 0 {
		shown := order
		if !all && len(shown) > hostFixFirst {
			shown = shown[:hostFixFirst]
		}
		head := "Fix first · " + plural(len(order), "affected component", "affected components")
		if len(shown) < len(order) {
			head += fmt.Sprintf(", top %d (--show-all lists every one)", len(shown))
		}
		title(head)
		fmt.Fprintf(&b, "  %s %s %s %s %s %s %s %s %s\n", dim(fmt.Sprintf("%-8s", "SEVERITY")), dim("   "),
			dim(fmt.Sprintf("%-7s", "TYPE")), dim(fmt.Sprintf("%-32s", "COMPONENT")), dim(fmt.Sprintf("%-18s", "VERSION")),
			dim(fmt.Sprintf("%4s", "CVES")), dim(fmt.Sprintf("%-12s", "FIXED IN")), dim(fmt.Sprintf("%-7s", "LINKED")), dim("FOUND IN"))
		for _, g := range shown {
			version := g.versions[0]
			if len(g.versions) > 1 {
				version = fmt.Sprintf("%d versions", len(g.versions))
			}
			linked := "-"
			if g.carriers > 0 {
				linked = fmt.Sprintf("%d/%d", g.linked, g.carriers)
				if g.open > 0 {
					linked += "?"
				}
			}
			fmt.Fprintf(&b, "  %s %s %-7s %-32s %-18s %4d %-12s %-7s %s\n",
				c.ColorSeverity(fmt.Sprintf("%-8s", g.worst)), markCol(g.mark), g.kind, fit(g.name, 32), fit(version, 18),
				g.cves, fit(g.fix, 12), linked, dim(fit(list(g.in, 3), 48)))
		}
		var kinds []string
		for k := range byKind {
			kinds = append(kinds, k)
		}
		sort.Slice(kinds, func(i, j int) bool { return byKind[kinds[i]] > byKind[kinds[j]] })
		for i, k := range kinds {
			kinds[i] = fmt.Sprintf("%s %d", k, byKind[k])
		}
		b.WriteString(dim("  by type: "+strings.Join(kinds, " · ")) + "\n")
		b.WriteString(dim("  LINKED: binaries that link a function the advisories name as affected, of those carrying it; ? some are "+
			"unknown (no function list, or the package is linked but no listed function by name: it may be inlined)") + "\n")
		if notLinked > 0 {
			b.WriteString(dim(fmt.Sprintf("  left out: %s Go module versions whose binaries link none of the affected functions", thousands(notLinked))) + "\n")
		}
	}
	if len(placeOrder) > 0 {
		shown := placeOrder
		if !all && len(shown) > hostFixFirst/2 {
			shown = shown[:hostFixFirst/2]
		}
		head := "Update · " + plural(len(placeOrder), "program or directory carries", "programs and directories carry") + " affected components"
		if len(shown) < len(placeOrder) {
			head += fmt.Sprintf(", top %d", len(shown))
		}
		title(head)
		fmt.Fprintf(&b, "  %s %s %s %s %s\n", dim(fmt.Sprintf("%-8s", "SEVERITY")), dim("   "),
			dim(fmt.Sprintf("%-36s", "WHERE")), dim(fmt.Sprintf("%8s", "AFFECTED")), dim("COMPONENTS"))
		for _, p := range shown {
			names := make([]string, 0, len(p.components))
			for n := range p.components {
				names = append(names, n)
			}
			sort.Strings(names)
			fmt.Fprintf(&b, "  %s %s %-36s %8d %s\n", c.ColorSeverity(fmt.Sprintf("%-8s", p.worst)), markCol(p.mark),
				fit(p.name, 36), len(names), dim(fit(list(names, 3), 60)))
		}
	}
	if s.Undetermined > 0 {
		title(fmt.Sprintf("Undetermined · %s", thousands(s.Undetermined)))
		// answers merged from several requests repeat a reason once per request
		counts, why := map[string]int{}, map[string]string{}
		var reasons []string
		for _, r := range s.UndeterminedReasons {
			if _, ok := counts[r.Reason]; !ok {
				reasons = append(reasons, r.Reason)
			}
			counts[r.Reason] += r.Count
			why[r.Reason] = r.Why
		}
		for _, r := range reasons {
			fmt.Fprintf(&b, "  %d %s: %s\n", counts[r], termClean(r), dim(termClean(why[r])))
		}
	}
	if notAssessed > 0 {
		title(fmt.Sprintf("Not assessed · %s with no exact identifier, so not checked", thousands(notAssessed)))
		var order []string
		bySource := map[string][]string{}
		for _, na := range inv.NotAssessed {
			if _, ok := bySource[na.Source]; !ok {
				order = append(order, na.Source)
			}
			bySource[na.Source] = append(bySource[na.Source], na.Name)
		}
		for _, src := range order {
			names := bySource[src]
			more := ""
			if !all && len(names) > hostNotAssessedNames {
				more = fmt.Sprintf(" +%d more", len(names)-hostNotAssessedNames)
				names = names[:hostNotAssessedNames]
			}
			fmt.Fprintf(&b, "  %s (%d): %s%s\n", src, len(bySource[src]), termClean(strings.Join(names, ", ")), dim(more))
		}
	}
	b.WriteString(dim("\n  --json writes every component with its CVEs; --show-all lists everything here") + "\n")
	return b.String()
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return thousands(n) + " " + many
}

// reachabilityLine counts Go module versions by binary: how many copies link an affected function.
func reachabilityLine(res vulnx.StackResult) string {
	if res.FunctionsUnavailable {
		return "Go reachability: not checked (the API does not serve affected functions yet)"
	}
	reach, not, unknown := 0, 0, 0
	for _, it := range res.Items {
		if r := it.Reachability; r != nil {
			reach, not, unknown = reach+len(r.Reachable), not+len(r.NotReachable), unknown+len(r.Unknown)
		}
	}
	if reach+not+unknown == 0 {
		return ""
	}
	return fmt.Sprintf("Go reachability: of %s affected module copies in binaries, %s link an affected function, %s link none, %s unknown",
		thousands(reach+not+unknown), thousands(reach), thousands(not), thousands(unknown))
}

// hostViews are the --view terminal views of a host scan.
var hostViews = []string{"grid", "actions", "brief", "programs", "details", "markdown"}

// renderHost renders a host scan in one of hostReports.
func renderHost(view string, inv vulnx.HostInventory, res vulnx.StackResult, elapsed time.Duration, all bool, c *renderer.ColorConfig) string {
	switch view {
	case "brief":
		return renderHostBrief(inv, res, c)
	case "programs":
		return renderHostPrograms(inv, res, all, c)
	case "details":
		return renderHostText(inv, res, all, c)
	case "markdown":
		return renderHostMarkdown(inv, res)
	case "actions":
		return renderHostActions(inv, res, all, c)
	}
	return renderHostGrid(inv, res, elapsed, c)
}

// hostProgress shows what a host scan is doing on one line of the terminal, replaced by the next message and
// cleared by an empty one; nothing when stderr is not a terminal.
func hostProgress(msg string) {
	if silent || !term.IsTerminal(int(os.Stderr.Fd())) {
		return
	}
	fmt.Fprint(os.Stderr, "\r\033[K"+msg)
}

// headline is a host scan's first line: what was checked and what needs doing.
func headline(inv vulnx.HostInventory, res vulnx.StackResult, fs []finding) string {
	kev := 0
	for _, f := range fs {
		if f.tier == tierKEV {
			kev++
		}
	}
	reach := ""
	if len(fs) != res.Summary.Affected {
		reach = fmt.Sprintf(" (%s a program can reach)", thousands(len(fs)))
	}
	return fmt.Sprintf("%s · %s components · %s affected%s · %s known exploited", termClean(inv.OS), thousands(len(inv.Entries)),
		thousands(res.Summary.Affected), reach, thousands(kev))
}

// wrapWords joins words into lines of at most width runes, the first prefixed by first and the rest by rest.
func wrapWords(words []string, first, rest string, width int) []string {
	var lines []string
	line := first
	for i, w := range words {
		sep := " "
		if i == 0 {
			sep = ""
		}
		if i > 0 && len([]rune(line+sep+w)) > width {
			lines = append(lines, line)
			line, sep = rest, ""
		}
		line += sep + w
	}
	return append(lines, line)
}

const hostWidth = 110

// renderHostActions is the default view: the updates to make, most urgent first, as commands where one exists.
func renderHostActions(inv vulnx.HostInventory, res vulnx.StackResult, all bool, c *renderer.ColorConfig) string {
	var b strings.Builder
	dim := func(t string) string { return c.Colorize(t, renderer.Gray) }
	fs := findings(inv, res)
	b.WriteString("\n" + c.Colorize(headline(inv, res, fs), renderer.Bold+renderer.BrightWhite) + "\n")
	if line := reachabilityLine(res); line != "" {
		b.WriteString(dim("  "+line) + "\n")
	}
	actions := hostActions(inv, fs)
	if len(actions) == 0 {
		b.WriteString("\n  Nothing to update: no affected component a program can reach.\n")
	}
	later := 0
	for tier := tierKEV; tier <= tierRest; tier++ {
		var these []hostAction
		for _, a := range actions {
			if a.tier == tier {
				these = append(these, a)
			}
		}
		if len(these) == 0 {
			continue
		}
		if tier == tierRest && !all {
			later = len(these)
			break
		}
		color := map[int]string{tierKEV: renderer.Bold + renderer.BrightRed, tierExploit: renderer.Bold + renderer.Red,
			tierSevere: renderer.Bold + renderer.Yellow, tierRest: renderer.Bold}[tier]
		b.WriteString("\n" + c.Colorize(tierTitles[tier], color) + "\n")
		for _, a := range these {
			var why []string
			for _, t := range a.targets {
				reasons := a.why[t]
				if len(reasons) > 2 {
					reasons = append(reasons[:2:2], fmt.Sprintf("+%d", len(a.why[t])-2))
				}
				r := strings.Join(reasons, ", ")
				if p := a.program(t); p != "" {
					r = p + ": " + r
				}
				why = append(why, r)
			}
			for _, l := range wrapWords(strings.Fields(a.line()), "  ", "      ", hostWidth) {
				b.WriteString(c.Colorize(l, renderer.BrightWhite) + "\n")
			}
			shown := why
			if !all && len(shown) > 4 {
				shown = append(shown[:4:4], fmt.Sprintf("+%d more", len(why)-4))
			}
			b.WriteString(dim("      "+strings.Join(shown, " · ")) + "\n")
		}
	}
	b.WriteString("\n")
	if later > 0 {
		b.WriteString(dim(fmt.Sprintf("  Later: %s for medium and low findings (--show-all lists them)", plural(later, "more update", "more updates"))) + "\n")
	}
	notLinked := 0
	for _, it := range res.Items {
		if it.Status == "affected" && unreachable(it) {
			notLinked++
		}
	}
	if notLinked > 0 {
		b.WriteString(dim(fmt.Sprintf("  Skipped: %s Go module versions no binary can reach (it links none of the affected code)", thousands(notLinked))) + "\n")
	}
	b.WriteString(dim("  "+notCheckedLine(inv)) + "\n")
	b.WriteString(dim("  More: --view programs | details | brief | markdown · --json for everything") + "\n")
	return b.String()
}

// notCheckedLine counts what was read but could not be checked, by source.
func notCheckedLine(inv vulnx.HostInventory) string {
	if len(inv.NotAssessed) == 0 {
		return "Not checked: nothing (every component read has an exact identifier)"
	}
	var parts []string
	for _, s := range inv.Sources {
		if s.NotAssessed > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", s.NotAssessed, s.Name))
		}
	}
	return fmt.Sprintf("Not checked: %s without an exact identifier (%s; --view details names them)",
		thousands(len(inv.NotAssessed)), strings.Join(parts, ", "))
}

// renderHostBrief is a few lines: what was checked and, per tier, what kind of updates it takes.
func renderHostBrief(inv vulnx.HostInventory, res vulnx.StackResult, c *renderer.ColorConfig) string {
	var b strings.Builder
	fs := findings(inv, res)
	b.WriteString(c.Colorize(headline(inv, res, fs), renderer.Bold+renderer.BrightWhite) + "\n")
	actions := hostActions(inv, fs)
	for tier := tierKEV; tier <= tierRest; tier++ {
		var parts []string
		counts := map[string]int{}
		var kinds []string
		for _, a := range actions {
			if a.tier != tier {
				continue
			}
			switch a.fix.Kind {
			case "macos", "npm":
				parts = append(parts, strings.SplitN(a.line(), " (", 2)[0])
			case "system": // "comes with the Command Line Tools: ..." -> "Command Line Tools"
				what, _, _ := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(a.fix.Note, "comes with "), "the "), ":")
				parts = append(parts, what)
			case "app":
				parts = append(parts, strings.TrimPrefix(a.fix.Note, "update "))
			default:
				if counts[a.fix.Kind] == 0 {
					kinds = append(kinds, a.fix.Kind)
				}
				counts[a.fix.Kind] += len(a.targets)
			}
		}
		names := map[string][2]string{"brew": {"Homebrew formula", "Homebrew formulae"}, "pip": {"Python package", "Python packages"},
			"gem": {"gem", "gems"}, "go-install": {"Go tool", "Go tools"}, "cargo": {"Rust tool", "Rust tools"},
			"binary": {"other program", "other programs"}, "apt": {"package", "packages"}, "dnf": {"package", "packages"},
			"apk": {"package", "packages"}, "other": {"other place", "other places"}}
		for _, k := range kinds {
			n := names[k]
			parts = append(parts, plural(counts[k], n[0], n[1]))
		}
		if len(parts) == 0 {
			continue
		}
		title, _, _ := strings.Cut(tierTitles[tier], " · ")
		fmt.Fprintf(&b, "  %-11s %s\n", title+":", strings.Join(parts, ", "))
	}
	b.WriteString(c.Colorize("  vulnx scan --host shows the commands", renderer.Gray) + "\n")
	return b.String()
}

// renderHostPrograms lists, per program or directory, how to update it and what it carries, most urgent first.
func renderHostPrograms(inv vulnx.HostInventory, res vulnx.StackResult, all bool, c *renderer.ColorConfig) string {
	var b strings.Builder
	dim := func(t string) string { return c.Colorize(t, renderer.Gray) }
	fs := findings(inv, res)
	b.WriteString("\n" + c.Colorize(headline(inv, res, fs), renderer.Bold+renderer.BrightWhite) + "\n\n")
	type place struct {
		name  string
		tier  int
		worst string
		items []finding
	}
	places := map[string]*place{}
	var order []*place
	for _, f := range fs {
		for _, p := range f.places {
			pl := places[p]
			if pl == nil {
				pl = &place{name: p, tier: f.tier, worst: f.worst}
				places[p] = pl
				order = append(order, pl)
			}
			pl.items = append(pl.items, f)
		}
	}
	sort.SliceStable(order, func(i, j int) bool {
		a, z := order[i], order[j]
		if a.tier != z.tier {
			return a.tier < z.tier
		}
		if severityRank[a.worst] != severityRank[z.worst] {
			return severityRank[a.worst] < severityRank[z.worst]
		}
		return len(a.items) > len(z.items)
	})
	shown := order
	if !all && len(shown) > 30 {
		shown = shown[:30]
	}
	for _, p := range shown {
		how := inv.Fixes[p.name].Line()
		mark := map[int]string{tierKEV: c.Colorize(" KEV", renderer.Bold+renderer.BrightRed)}[p.tier]
		fmt.Fprintf(&b, "%s %s%s  %s\n", c.ColorSeverity(fmt.Sprintf("%-8s", p.worst)), c.Colorize(termClean(p.name), renderer.Bold),
			mark, dim(termClean(how)))
		items := p.items
		if !all && len(items) > 5 {
			items = items[:5]
		}
		for _, f := range items {
			fmt.Fprintf(&b, "    %s %s\n", c.ColorSeverity(fmt.Sprintf("%-8s", f.worst)), f.short())
		}
		if len(items) < len(p.items) {
			b.WriteString(dim(fmt.Sprintf("    +%d more", len(p.items)-len(items))) + "\n")
		}
	}
	if len(shown) < len(order) {
		b.WriteString(dim(fmt.Sprintf("\n%d more programs and directories (--show-all lists them)", len(order)-len(shown))) + "\n")
	}
	return b.String()
}

// renderHostMarkdown is the action view as a Markdown checklist, to paste into an issue or a chat.
func renderHostMarkdown(inv vulnx.HostInventory, res vulnx.StackResult) string {
	var b strings.Builder
	fs := findings(inv, res)
	fmt.Fprintf(&b, "## Host scan: %s\n\n", headline(inv, res, fs))
	if line := reachabilityLine(res); line != "" {
		b.WriteString(line + ".\n")
	}
	actions := hostActions(inv, fs)
	for tier := tierKEV; tier <= tierRest; tier++ {
		header := false
		for _, a := range actions {
			if a.tier != tier {
				continue
			}
			if !header {
				fmt.Fprintf(&b, "\n### %s\n\n", tierTitles[tier])
				header = true
			}
			line := "`" + a.line() + "`"
			if a.fix.Command == "" {
				line = a.line()
			}
			if a.program(a.targets[0]) == "" { // the components themselves: on the line
				var why []string
				for _, t := range a.targets {
					why = append(why, strings.Join(a.why[t], ", "))
				}
				fmt.Fprintf(&b, "- [ ] %s: %s\n", line, strings.Join(why, "; "))
				continue
			}
			fmt.Fprintf(&b, "- [ ] %s\n", line)
			for _, t := range a.targets {
				reasons := a.why[t]
				if len(reasons) > 6 {
					reasons = append(reasons[:6:6], fmt.Sprintf("+%d more", len(a.why[t])-6))
				}
				fmt.Fprintf(&b, "  - %s: %s\n", a.program(t), strings.Join(reasons, ", "))
			}
		}
	}
	fmt.Fprintf(&b, "\n%s.\n", notCheckedLine(inv))
	return b.String()
}
