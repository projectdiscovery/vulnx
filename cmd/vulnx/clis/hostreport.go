package clis

// vulnx scan --host's report: what to update first (the default), or the same findings briefly, per component,
// per program or as Markdown (--report). Every view leaves out what no binary can reach (Go reachability).

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/vulnx/v2"
	"github.com/projectdiscovery/vulnx/v2/pkg/tools/renderer"
	"golang.org/x/term"
)

// writeHostJSON writes a host scan as the stack result with the inventory beside it, or as VEX.
func writeHostJSON(inv vulnx.HostInventory, res vulnx.StackResult, vex string) {
	if vex != "" {
		writeStackOutput(res, vex, 0)
		return
	}
	data, err := json.MarshalIndent(struct {
		Host vulnx.HostInventory `json:"host"`
		vulnx.StackResult
	}{inv, res}, "", "  ")
	if err != nil {
		gologger.Fatal().Msgf("Failed to render output: %s", err)
	}
	if outputFile != "" {
		if err := writeNewFile(outputFile, data); err != nil {
			gologger.Fatal().Msgf("%s", err)
		}
		gologger.Info().Msgf("Wrote %s", outputFile)
		return
	}
	_, _ = os.Stdout.Write(append(data, '\n'))
}

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

// componentParts splits a check entry into a kind, a name and a version for display.
func componentParts(entry string) (kind, name, version string) {
	if strings.HasPrefix(entry, "cpe:2.3:") {
		f := strings.Split(entry, ":")
		if len(f) > 5 {
			return "product", f[3] + ":" + f[4], strings.ReplaceAll(f[5], "\\", "")
		}
		return "product", entry, ""
	}
	body, _, _ := strings.Cut(strings.TrimPrefix(entry, "pkg:"), "?")
	typ, rest, _ := strings.Cut(body, "/")
	at := strings.LastIndex(rest, "@")
	if at < 0 {
		return typ, rest, ""
	}
	name, version = rest[:at], rest[at+1:]
	if u, err := url.PathUnescape(name); err == nil {
		name = u
	}
	if u, err := url.PathUnescape(version); err == nil {
		version = u
	}
	switch typ {
	case "golang":
		typ = "go"
	case "cargo":
		typ = "crate"
	case "deb", "rpm", "apk":
		name = name[strings.LastIndex(name, "/")+1:]
	}
	return typ, name, version
}

func fit(s string, n int) string {
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
	title(fmt.Sprintf("%s · %s components checked · %s not assessed", inv.OS, thousands(len(inv.Entries)), thousands(notAssessed)))
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
		fmt.Fprintf(&b, "  %-14s %8s %13s  %s\n", s.Name, thousands(s.Sent), na, detail)
	}
	if len(inv.NotRead) > 0 {
		b.WriteString(dim("  Not read: "+strings.Join(inv.NotRead, "; ")) + "\n")
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
			fmt.Fprintf(&b, "  %d %s: %s\n", counts[r], r, dim(why[r]))
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
			fmt.Fprintf(&b, "  %s (%d): %s%s\n", src, len(bySource[src]), strings.Join(names, ", "), dim(more))
		}
	}
	b.WriteString(dim("\n  --json writes every component with its CVEs; --show-all lists everything here") + "\n")
	return b.String()
}

func advisoryCount(it vulnx.StackItem) int {
	if it.AdvisoryRowsTotal > it.Advisories {
		return it.AdvisoryRowsTotal
	}
	return it.Advisories
}

var versionNumbers = regexp.MustCompile(`\d+`)

// versionLess orders versions by their first three numbers (v1.10.0 after v1.9.2), and on a tie puts the longer
// one first, so a release wins over a pseudo-version of it: close enough to show a component's highest fix.
func versionLess(a, b string) bool {
	x, y := versionNumbers.FindAllString(a, 3), versionNumbers.FindAllString(b, 3)
	for i := 0; i < len(x) && i < len(y); i++ {
		xi, _ := strconv.Atoi(x[i])
		yi, _ := strconv.Atoi(y[i])
		if xi != yi {
			return xi < yi
		}
	}
	if len(x) != len(y) {
		return len(x) < len(y)
	}
	return len(a) > len(b)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return thousands(n) + " " + many
}

// unreachable is a host scan's Go item that no binary carrying it can run: each one was checked and links none of
// the functions its advisories name.
func unreachable(it vulnx.StackItem) bool {
	r := it.Reachability
	return r != nil && len(r.NotReachable) > 0 && len(r.Reachable) == 0 && len(r.Unknown) == 0
}

// liveSeverity is an item's worst severity and advisory count over the rows a binary can run (rows not marked
// not_reachable); without reachability marks, the API's own.
func liveSeverity(it vulnx.StackItem) (string, int) {
	worst, n, marked := "", 0, false
	for _, a := range it.AdvisoryRows {
		if a.Reachability == "not_reachable" {
			marked = true
			continue
		}
		n++
		if worst == "" || severityRank[a.Severity] < severityRank[worst] {
			worst = a.Severity
		}
	}
	if !marked {
		return it.WorstSeverity, advisoryCount(it)
	}
	return worst, n
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

// openFile opens a file with the desktop's default application.
func openFile(path string) {
	opener := "xdg-open"
	if runtime.GOOS == "darwin" {
		opener = "open"
	}
	if err := exec.Command(opener, path).Start(); err != nil {
		gologger.Warning().Msgf("could not open %s: %s", path, err)
	}
}

// gridRow is one source of a host scan: what it checked and its reachable findings by worst severity.
type gridRow struct {
	Name      string
	Checked   int
	Severity  [4]int // critical, high, medium, low
	Exploited int    // with a known exploited CVE
}

var gridSeverities = []string{"critical", "high", "medium", "low"}

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

// renderHostGrid is the default view, one screen: the headline numbers and, per source, its findings by severity.
func renderHostGrid(inv vulnx.HostInventory, res vulnx.StackResult, elapsed time.Duration, c *renderer.ColorConfig) string {
	var b strings.Builder
	dim := func(t string) string { return c.Colorize(t, renderer.Gray) }
	rows, total, n := hostGrid(inv, res)
	head := fmt.Sprintf("%s: %s components scanned", inv.OS, thousands(n.Checked))
	if elapsed > 0 {
		head += " in " + elapsed.Round(time.Second).String()
	}
	b.WriteString("\n" + c.Colorize(head, renderer.Bold+renderer.BrightWhite) + "\n\n")
	fmt.Fprintf(&b, "  %s affected   %s reachable   %s known exploited   %s public exploit\n\n",
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
		return fmt.Sprintf("%4d ", v) + c.ColorSeverity(strings.Repeat("█", blocks)) + strings.Repeat(" ", bar-blocks)
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

// Tiers of what to update, most urgent first.
const (
	tierKEV     = iota // a known exploited CVE
	tierExploit        // critical or high, with a public exploit
	tierSevere         // critical or high
	tierRest           // medium and low
)

var tierTitles = []string{"Update now · known exploited", "Next · critical or high, public exploit",
	"Then · critical or high", "Later · medium and low"}

// finding is one affected component that some place carries and some binary can reach.
type finding struct {
	item                vulnx.StackItem
	kind, name, version string
	worst, mark         string
	tier                int
	places              []string // where it was found, less the binaries that link none of its affected code
}

// findings are a host scan's affected components, most urgent first.
func findings(inv vulnx.HostInventory, res vulnx.StackResult) []finding {
	var out []finding
	for _, it := range res.Items {
		if it.Status != "affected" || unreachable(it) {
			continue
		}
		f := finding{item: it}
		f.kind, f.name, f.version = componentParts(it.Input)
		f.worst, _ = liveSeverity(it)
		for _, a := range it.AdvisoryRows {
			if a.Exploit == nil || a.Reachability == "not_reachable" {
				continue
			}
			if a.Exploit.KnownExploited {
				f.mark = "KEV"
			} else if a.Exploit.PublicExploit && f.mark == "" {
				f.mark = "POC"
			}
		}
		severe := f.worst == "critical" || f.worst == "high"
		switch {
		case f.mark == "KEV":
			f.tier = tierKEV
		case severe && f.mark == "POC":
			f.tier = tierExploit
		case severe:
			f.tier = tierSevere
		default:
			f.tier = tierRest
		}
		for _, p := range inv.FoundIn[it.Input] {
			if it.Reachability == nil || !slices.Contains(it.Reachability.NotReachable, p) {
				f.places = append(f.places, p)
			}
		}
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].tier != out[j].tier {
			return out[i].tier < out[j].tier
		}
		return severityRank[out[i].worst] < severityRank[out[j].worst]
	})
	return out
}

// label is a component's name as a report says it: a product without its vendor, a Go module without its host,
// the Go standard library by name.
func (f finding) label() string {
	switch {
	case f.kind == "product":
		if f.name == "apple:macos" {
			return "macOS"
		}
		_, name, _ := strings.Cut(f.name, ":")
		return strings.ReplaceAll(name, "_", " ")
	case f.kind == "go" && f.name == "stdlib":
		return "Go stdlib"
	case f.kind == "go":
		for _, host := range []string{"github.com/", "golang.org/", "google.golang.org/", "gopkg.in/"} {
			if strings.HasPrefix(f.name, host) {
				return strings.TrimPrefix(f.name, host)
			}
		}
	}
	return f.name
}

// short is the component with its version and fix ("lxml 4.9.3 → 6.1.0"); a pseudo-version is cut.
func (f finding) short() string {
	s := f.label() + " " + fit(f.version, 20)
	if f.item.FixedVersion != "" {
		s += " → " + fit(f.item.FixedVersion, 20)
	}
	return s
}

// hostAction is one thing to do: a command and the names it takes (brew upgrade php mitmproxy), or a note.
type hostAction struct {
	tier    int
	fix     vulnx.HostFix
	targets []string            // what the command names, in urgency order; one note target with no command
	why     map[string][]string // target -> the components that make it urgent
	worst   string
}

// program is the name a reason line starts with: the formula or tool a target updates (none for a note naming it).
func (a hostAction) program(target string) string {
	switch a.fix.Kind {
	case "brew", "cargo":
		return target
	case "go-install":
		return path.Base(strings.TrimSuffix(target, "@latest"))
	}
	return ""
}

// line is the action as typed or read: the command with its names, or the note.
func (a hostAction) line() string {
	if a.fix.Command == "" {
		return a.fix.Note
	}
	if a.fix.Kind == "npm" { // a global tool's dependency is updated with the tool: npm update -g takes no names
		return a.fix.Command
	}
	return a.fix.Command + " " + strings.Join(a.targets, " ")
}

// hostActions turns findings into updates: each place's fix, named once at its most urgent tier.
func hostActions(inv vulnx.HostInventory, fs []finding) []hostAction {
	type key struct{ kind, command, note string }
	type target struct {
		key  key
		fix  vulnx.HostFix
		name string
	}
	tierOf := map[target]int{}
	why := map[target][]string{}
	worst := map[target]string{}
	var order []target
	for _, f := range fs {
		for _, p := range f.places {
			fix, ok := inv.Fixes[p]
			if !ok {
				fix = vulnx.HostFix{Kind: "other", Note: "update what is in " + p}
			}
			name := fix.Target
			if name == "" {
				name = f.name
			}
			k := key{fix.Kind, fix.Command, ""}
			switch {
			case fix.Kind == "go-install" || (fix.Command == "" && fix.Target != ""): // one program a line
				k.note = fix.Note + "|" + name
			case fix.Command == "": // a note naming no program (Software Update): its components together
				k.note = fix.Note
			}
			t := target{k, fix, name}
			if prev, seen := tierOf[t]; !seen {
				tierOf[t] = f.tier
				worst[t] = f.worst
				order = append(order, t)
			} else if f.tier < prev {
				tierOf[t] = f.tier
			}
			if severityRank[f.worst] < severityRank[worst[t]] {
				worst[t] = f.worst
			}
			reason := f.short()
			if fix.Kind == "brew" || fix.Kind == "go-install" || fix.Kind == "cargo" || fix.Kind == "binary" {
				reason = f.label() // a formula or tool: which of its components
			}
			if !slices.Contains(why[t], reason) {
				why[t] = append(why[t], reason)
			}
		}
	}
	// an update that names nothing (Software Update, npm update -g) is made once, at its most urgent tier
	once := map[key]int{}
	for _, t := range order {
		if t.fix.Kind == "npm" || (t.fix.Command == "" && t.fix.Target == "") {
			if prev, ok := once[t.key]; !ok || tierOf[t] < prev {
				once[t.key] = tierOf[t]
			}
		}
	}
	for _, t := range order {
		if tier, ok := once[t.key]; ok {
			tierOf[t] = tier
		}
	}
	type group struct {
		tier int
		key  key
	}
	byGroup := map[group]*hostAction{}
	var out []*hostAction
	for _, t := range order {
		g := group{tierOf[t], t.key}
		a := byGroup[g]
		if a == nil {
			a = &hostAction{tier: g.tier, fix: t.fix, why: map[string][]string{}, worst: worst[t]}
			byGroup[g] = a
			out = append(out, a)
		}
		a.targets = append(a.targets, t.name)
		a.why[t.name] = why[t]
		if severityRank[worst[t]] < severityRank[a.worst] {
			a.worst = worst[t]
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].tier != out[j].tier {
			return out[i].tier < out[j].tier
		}
		return actionRank(out[i].fix.Kind) < actionRank(out[j].fix.Kind)
	})
	actions := make([]hostAction, len(out))
	for i, a := range out {
		actions[i] = *a
	}
	return actions
}

// actionRank orders a tier's actions: the system first, then package managers, then programs one by one.
func actionRank(kind string) int {
	return slices.Index([]string{"macos", "apt", "dnf", "apk", "app", "brew", "pip", "npm", "gem", "go-install", "cargo",
		"binary", "system", "other"}, kind)
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
	return fmt.Sprintf("%s · %s components · %s affected%s · %s known exploited", inv.OS, thousands(len(inv.Entries)),
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
	b.WriteString(dim("  More: --report programs | details | brief | markdown · --json for everything") + "\n")
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
	return fmt.Sprintf("Not checked: %s without an exact identifier (%s; --report details names them)",
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
		fix := inv.Fixes[p.name]
		how := fix.Note
		if fix.Command != "" {
			how = fix.Command
			if fix.Target != "" {
				how += " " + fix.Target
			}
		}
		mark := map[int]string{tierKEV: c.Colorize(" KEV", renderer.Bold+renderer.BrightRed)}[p.tier]
		fmt.Fprintf(&b, "%s %s%s  %s\n", c.ColorSeverity(fmt.Sprintf("%-8s", p.worst)), c.Colorize(p.name, renderer.Bold),
			mark, dim(how))
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

// failOnLevels are --fail-on's values.
var failOnLevels = []string{"kev", "critical", "high"}

// failsOn is whether a host scan has a finding a program can reach at --fail-on's level or worse.
func failsOn(level string, inv vulnx.HostInventory, res vulnx.StackResult) bool {
	for _, f := range findings(inv, res) {
		switch {
		case level == "kev" && f.tier == tierKEV,
			level == "critical" && (f.tier == tierKEV || f.worst == "critical"),
			level == "high" && (f.tier == tierKEV || f.worst == "critical" || f.worst == "high"):
			return true
		}
	}
	return false
}

// since is a step's duration as the progress lines print it.
func since(t time.Time) string {
	return time.Since(t).Round(100 * time.Millisecond).String()
}

//go:embed hostreport.html.tmpl
var hostReportHTML string

var hostReportTemplate = template.Must(template.New("host").Funcs(template.FuncMap{"thousands": thousands}).Parse(hostReportHTML))

// advisoryPage is where a CVE's page is.
const advisoryPage = "https://securitycontext.com/cve/"

type reportCell struct {
	Severity string
	N, Width int
}

type reportGridRow struct {
	Name               string
	Cells              []reportCell
	Exploited, Checked int
}

// reportGroup is one kind of update ("Homebrew formulae", 102): a line to read, opened for its rows.
type reportGroup struct {
	Title, Command string
	Count          int
	Urgency        []reportUrgency // how many of Count at each urgency, most urgent first
	Rows           []reportGroupRow
}

// reportUrgency is a count at one urgency tier.
type reportUrgency struct {
	Label, Class string
	N            int
}

// reportGroupRow is one thing to update: a formula, a tool, an interpreter's packages.
type reportGroupRow struct {
	Name, Detail, Command, Urgency, Class string
	Why                                   []string
	More                                  int
}

type reportAdvisory struct {
	ID, URL, Name, Severity, Score, Mark string
	NotReachable                         bool
}

// reportComponent is one affected component, every version of it found on the machine together.
type reportComponent struct {
	Severity, Mark, Kind, Name, Version, Fixed, Found, Linked, Search string
	FoundMore, More                                                   int
	Advisories                                                        []reportAdvisory
	Versions                                                          []reportVersion
}

type reportVersion struct{ Version, Fixed, Found string }

// groupTitles name a tier's kinds of update, by HostFix kind.
var groupTitles = map[string]string{"macos": "System", "system": "System", "app": "Apps", "brew": "Homebrew formulae",
	"pip": "Python packages", "npm": "npm global packages", "gem": "Ruby gems", "go-install": "Go tools", "cargo": "Rust tools",
	"binary": "Other programs", "apt": "OS packages", "dnf": "OS packages", "apk": "OS packages", "other": "Other places"}

// urgencyLabels name the tiers on a report line, with their style class.
var urgencyLabels = [][2]string{{"known exploited", "kev"}, {"public exploit", "poc"}, {"critical or high", "sevhigh"}, {"medium or low", "no"}}

// reportGroups turns the actions (most urgent first) into one list of kinds of update. A place updated at several
// urgencies (an interpreter with an exploited package and a low one) is one row at its most urgent, its command
// naming everything.
func reportGroups(actions []hostAction) []reportGroup {
	type row struct {
		name, detail string
		fix          vulnx.HostFix
		tier         int
		targets, why []string
	}
	type group struct {
		title   string
		rows    []*row
		byName  map[string]*row
		units   [4]int
		targets []string // a one-command kind's names, most urgent first
		fix     vulnx.HostFix
	}
	var order []*group
	byTitle := map[string]*group{}
	for _, a := range actions {
		title := groupTitles[a.fix.Kind]
		g := byTitle[title]
		if g == nil {
			g = &group{title: title, byName: map[string]*row{}, fix: a.fix}
			byTitle[title] = g
			order = append(order, g)
		}
		add := func(name, detail string, targets, why []string) {
			r := g.byName[name+"|"+detail]
			if r == nil {
				r = &row{name: name, detail: detail, fix: a.fix, tier: a.tier}
				g.byName[name+"|"+detail] = r
				g.rows = append(g.rows, r)
			}
			r.targets = append(r.targets, targets...)
			r.why = append(r.why, why...)
		}
		var all []string
		for _, t := range a.targets {
			all = append(all, a.why[t]...)
		}
		units := 1
		switch a.fix.Kind {
		case "brew", "apt", "dnf", "apk", "cargo": // one command, a row per name it takes
			for _, t := range a.targets {
				add(t, "", nil, a.why[t])
			}
			g.targets = append(g.targets, a.targets...)
			units = len(a.targets)
		case "pip", "gem": // a row per interpreter, its packages the reasons
			name, detail := "gems", ""
			if a.fix.Kind == "pip" { // "/opt/homebrew/bin/python3.12" -> python3.12, in /opt/homebrew
				interpreter := strings.Fields(a.fix.Command)[0]
				name = path.Base(interpreter)
				if dir := strings.TrimSuffix(path.Dir(interpreter), "/bin"); dir != "." {
					detail = "in " + dir
				}
			}
			add(name, detail, a.targets, all)
			units = len(a.targets)
		case "go-install":
			add(a.program(a.targets[0]), "", a.targets, all)
		case "binary":
			add(a.fix.Target, strings.TrimSuffix(strings.TrimPrefix(a.fix.Note, "update "+a.fix.Target+" ("), ")"), nil, all)
		case "app":
			add(a.fix.Target, "", nil, all)
		case "npm":
			add("global packages", "", nil, all)
			units = len(a.targets)
		default: // Software Update and what ships with the system
			name, detail := strings.SplitN(a.fix.Note, " (", 2)[0], ""
			if rest, ok := strings.CutPrefix(a.fix.Note, "comes with "); ok { // "comes with macOS: updated with it"
				what, how, _ := strings.Cut(strings.TrimPrefix(rest, "the "), ": ")
				name, detail = "Shipped with "+what, how
			}
			add(name, detail, nil, all)
			units = len(all)
		}
		g.units[a.tier] += units
	}
	var out []reportGroup
	for _, g := range order {
		rg := reportGroup{Title: g.title}
		if len(g.targets) > 0 {
			rg.Command = g.fix.Command + " " + strings.Join(g.targets, " ")
		}
		for tier, n := range g.units {
			rg.Count += n
			if n > 0 {
				rg.Urgency = append(rg.Urgency, reportUrgency{urgencyLabels[tier][0], urgencyLabels[tier][1], n})
			}
		}
		for _, r := range g.rows {
			row := reportGroupRow{Name: r.name, Detail: r.detail, Urgency: urgencyLabels[r.tier][0], Class: urgencyLabels[r.tier][1], Why: r.why}
			if len(r.why) > 3 {
				row.Why, row.More = r.why[:3], len(r.why)-3
			}
			switch r.fix.Kind {
			case "pip", "gem", "go-install":
				row.Command = r.fix.Command + " " + strings.Join(r.targets, " ")
			case "npm":
				row.Command = r.fix.Command
			}
			rg.Rows = append(rg.Rows, row)
		}
		out = append(out, rg)
	}
	return out
}

// reportComponents groups findings (most urgent first) by component: its versions, where they are, its advisories.
func reportComponents(fs []finding) []reportComponent {
	var out []reportComponent
	index := map[string]int{}
	seenAdv := map[string]map[string]bool{}
	places := map[string][]string{}
	reach := map[string][2]int{}
	for _, f := range fs {
		key := f.kind + " " + f.name
		i, ok := index[key]
		if !ok {
			i = len(out)
			index[key] = i
			out = append(out, reportComponent{Severity: f.worst, Mark: f.mark, Kind: f.kind, Name: f.label()})
			seenAdv[key] = map[string]bool{}
		}
		c := &out[i]
		if severityRank[f.worst] < severityRank[c.Severity] {
			c.Severity = f.worst
		}
		if c.Mark != "KEV" && f.mark != "" && (f.mark == "KEV" || c.Mark == "") {
			c.Mark = f.mark
		}
		if c.Fixed == "" || versionLess(c.Fixed, f.item.FixedVersion) {
			c.Fixed = f.item.FixedVersion
		}
		c.Versions = append(c.Versions, reportVersion{f.version, f.item.FixedVersion, strings.Join(f.places, ", ")})
		for _, p := range f.places {
			if !slices.Contains(places[key], p) {
				places[key] = append(places[key], p)
			}
		}
		if r := f.item.Reachability; r != nil {
			n := reach[key]
			reach[key] = [2]int{n[0] + len(r.Reachable), n[1] + len(r.Reachable) + len(r.NotReachable) + len(r.Unknown)}
		}
		for _, a := range f.item.AdvisoryRows {
			id := a.CVE
			if id == "" {
				id = a.AdvisoryID
			}
			if seenAdv[key][id] {
				continue
			}
			seenAdv[key][id] = true
			if len(c.Advisories) >= 12 {
				c.More++
				continue
			}
			adv := reportAdvisory{ID: id, Name: a.Name, Severity: a.Severity, NotReachable: a.Reachability == "not_reachable"}
			if a.CVE != "" {
				adv.URL = advisoryPage + a.CVE
			}
			if a.CvssScore > 0 {
				adv.Score = fmt.Sprintf("%.1f", a.CvssScore)
			}
			if a.Exploit != nil && a.Exploit.KnownExploited {
				adv.Mark = "KEV"
			} else if a.Exploit != nil && a.Exploit.PublicExploit {
				adv.Mark = "POC"
			}
			c.Advisories = append(c.Advisories, adv)
		}
		c.More += max(0, advisoryCount(f.item)-len(f.item.AdvisoryRows))
	}
	for key, i := range index {
		c := &out[i]
		c.Version = c.Versions[0].Version
		if len(c.Versions) > 1 {
			c.Version = fmt.Sprintf("%d versions", len(c.Versions))
		} else {
			c.Versions = nil
		}
		ps := places[key]
		search := append([]string{c.Name, key}, ps...)
		if len(ps) > 2 {
			c.FoundMore, ps = len(ps)-2, ps[:2]
		}
		c.Found = strings.Join(ps, ", ")
		if n := reach[key]; n[1] > 0 {
			c.Linked = fmt.Sprintf("%d of %d programs reach it", n[0], n[1])
		}
		for _, a := range c.Advisories {
			search = append(search, a.ID, a.Name)
		}
		c.Search = strings.ToLower(strings.Join(search, " "))
	}
	return out
}

type reportUnmatched struct{ Name, Version, Why string }

type hostReport struct {
	OS, Generated, Elapsed, NotRead string
	Counts                          hostCounts
	Undetermined, Clean             int
	Grid                            []reportGridRow
	Total                           reportGridRow
	Groups                          []reportGroup
	Components                      []reportComponent
	NotLinked                       []string
	CouldNotMatch                   []reportUnmatched
	NotChecked                      []vulnx.HostComponent
}

// hostReportData is a host scan as the HTML report shows it: the production stack report's sections (the verdict,
// where to fix, affected versions, couldn't match) and what only the machine knows (per source, where each
// component was found, reachability, what was not checked).
func hostReportData(inv vulnx.HostInventory, res vulnx.StackResult, elapsed time.Duration, now time.Time) hostReport {
	rows, total, counts := hostGrid(inv, res)
	d := hostReport{OS: inv.OS, Generated: now.Format("2006-01-02 15:04"), Counts: counts, Undetermined: res.Summary.Undetermined,
		Clean: res.Summary.Clean, NotChecked: inv.NotAssessed, NotRead: strings.Join(inv.NotRead, "; ")}
	if elapsed > 0 {
		d.Elapsed = elapsed.Round(time.Second).String()
	}
	peak := 1
	for _, r := range rows {
		for _, v := range r.Severity {
			peak = max(peak, v)
		}
	}
	gridRow := func(r gridRow) reportGridRow {
		out := reportGridRow{Name: r.Name, Exploited: r.Exploited, Checked: r.Checked}
		for i, v := range r.Severity {
			out.Cells = append(out.Cells, reportCell{Severity: gridSeverities[i], N: v, Width: max(3, v*72/peak)})
		}
		return out
	}
	for _, r := range rows {
		d.Grid = append(d.Grid, gridRow(r))
	}
	d.Total = gridRow(total)

	fs := findings(inv, res)
	actions := hostActions(inv, fs)
	d.Groups = reportGroups(actions)
	d.Components = reportComponents(fs)
	for _, it := range res.Items {
		switch {
		case it.Status == "affected" && unreachable(it):
			_, name, version := componentParts(it.Input)
			d.NotLinked = append(d.NotLinked, name+" "+version)
		case it.Status == "undetermined":
			_, name, version := componentParts(it.Input)
			why := it.Reason
			if why == "" && len(it.Undetermined) > 0 {
				why = it.Undetermined[0].Reason
			}
			d.CouldNotMatch = append(d.CouldNotMatch, reportUnmatched{name, version, strings.ReplaceAll(why, "_", " ")})
		}
	}
	return d
}

// writeHostReport writes the report as one self-contained HTML file and returns its absolute path. path "auto"
// (or empty) names it vulnx-host-<date>.html in the working directory, replacing the same day's.
func writeHostReport(path string, inv vulnx.HostInventory, res vulnx.StackResult, elapsed time.Duration) (string, error) {
	now := time.Now()
	if path == "" || path == "auto" {
		path = "vulnx-host-" + now.Format("2006-01-02") + ".html"
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := hostReportTemplate.Execute(&buf, hostReportData(inv, res, elapsed, now)); err != nil {
		return "", err
	}
	return abs, os.WriteFile(abs, buf.Bytes(), 0o644)
}
