package clis

// The bare `vulnx` screen: the index's headline numbers and its breakdowns by severity, vendor, weakness,
// exploitation and EPSS, drawn with the host grid's bars, colors and label column.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/projectdiscovery/vulnx/v2"
	"github.com/projectdiscovery/vulnx/v2/internal/termtext"
	"github.com/projectdiscovery/vulnx/v2/pkg/tools/analyze"
	"github.com/projectdiscovery/vulnx/v2/pkg/tools/renderer"
	"golang.org/x/term"
)

// dashboardData is what the dashboard shows, fetched before anything is drawn.
type dashboardData struct {
	Total      int
	Severity   map[string]int
	Vendors    []bucket
	Weaknesses []bucket
	Exploit    map[string]int
	// EPSS counts the CVEs with an EPSS score of at least 0.7, 0.3 and 0.1; nil when it could not be read
	EPSS *[3]int
	// Unavailable names the sections that could not be read, with why
	Unavailable []string
}

// showDashboard displays the index's headline numbers and breakdowns.
func showDashboard() error {
	if silent {
		return showDashboardJSON()
	}
	d, err := fetchDashboard()
	if errors.Is(err, vulnx.ErrTooManyRequests) {
		out := &stdoutText{}
		out.print("\n  The dashboard is unavailable: rate limited (anonymous callers get a few requests a minute); try again shortly.\n\n")
		out.print(renderQuickStart(colorConfig()))
		return out.err
	}
	if err != nil {
		return fmt.Errorf("failed to fetch dashboard data: %w", err)
	}
	width := 0
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil {
		width = w
	}
	c := colorConfig()
	out := &stdoutText{}
	out.print(renderDashboard(d, width, c) + renderQuickStart(c))
	return out.err
}

// fetchDashboard reads the dashboard's numbers: one facet request for severity, vendors and exploitation (anonymous
// callers are rate limited), one for weaknesses and three EPSS counts. A section that cannot be read is left out
// and named in Unavailable; only the first request failing fails the dashboard.
func fetchDashboard() (dashboardData, error) {
	handler := analyze.NewHandler(vulnxClient)
	resp, err := handler.Analyze(analyze.Params{
		Fields:    []string{"severity=8", "affected_products.vendor=5", "exploit=10"},
		FacetSize: vulnx.Ptr(10),
	})
	if err != nil {
		return dashboardData{}, err
	}
	d := dashboardData{Total: resp.Total, Severity: map[string]int{}, Exploit: map[string]int{}}
	for _, b := range extractBuckets(resp.Facets, "severity") {
		d.Severity[strings.ToLower(strings.TrimSpace(b.key))] += b.count
	}
	d.Vendors = extractBuckets(resp.Facets, "affected_products.vendor")
	for _, b := range extractBuckets(resp.Facets, "exploit") {
		d.Exploit[b.key] = b.count
	}
	unavailable := func(section string, err error) {
		if !errors.Is(err, vulnx.ErrTooManyRequests) {
			d.Unavailable = append(d.Unavailable, fmt.Sprintf("%s: %v", section, err))
		}
	}
	if cwe, err := handler.Analyze(analyze.Params{Fields: []string{"cwe=8"}, FacetSize: vulnx.Ptr(8)}); err != nil {
		unavailable("weaknesses", err)
	} else {
		for _, b := range extractBuckets(cwe.Facets, "cwe") {
			if cweLabel.MatchString(b.key) {
				d.Weaknesses = append(d.Weaknesses, b)
			}
		}
	}
	var epss [3]int
	for i, score := range []string{"0.7", "0.3", "0.1"} {
		r, err := vulnxClient.SearchVulnerabilities(context.Background(), vulnx.SearchParams{
			Query: vulnx.Ptr("epss_score:>=" + score), Limit: vulnx.Ptr(1)})
		if err != nil {
			unavailable("EPSS", err)
			return d, nil
		}
		epss[i] = r.Total
	}
	// separate counts: if the index changed between them, the bands would not add up
	if epss[0] <= epss[1] && epss[1] <= epss[2] && epss[2] <= d.Total {
		d.EPSS = &epss
	}
	return d, nil
}

// dashRow is one row of a dashboard section: a label, its count, and its bar color ("" for none).
type dashRow struct {
	label string
	count int
	color string
}

// dashSection is a dashboard section: a caps title over a label column, counts, each count's share of base, and
// bars scaled to the section's largest count.
type dashSection struct {
	title string
	rows  []dashRow
	base  int
	note  string // a line under the rows, dim
}

// dashBar is the width of a dashboard bar.
const dashBar = 16

// share is a count's share of base with one decimal: "<0.1%" for a share above zero that would show as 0.0%.
func share(n, base int) string {
	if base <= 0 {
		return "-"
	}
	p := float64(n) * 100 / float64(base)
	if n > 0 && p < 0.05 {
		return "<0.1%"
	}
	return fmt.Sprintf("%.1f%%", p)
}

// lines draws the section, every line padded to the same visible width, which it returns.
func (s dashSection) lines(c *renderer.ColorConfig) ([]string, int) {
	dim := func(t string) string { return c.Colorize(t, renderer.Gray) }
	label, count, peak := len(s.title), len("CVES"), 0
	for _, r := range s.rows {
		label = max(label, len([]rune(r.label)))
		count = max(count, len(formatNumber(r.count)))
		peak = max(peak, r.count)
	}
	width := 2 + label + 2 + count + 2 + len("SHARE") + 2 + dashBar
	head := fmt.Sprintf("  %-*s  %*s  %5s", label, s.title, count, "CVES", "SHARE")
	out := []string{dim(head) + strings.Repeat(" ", width-len(head))}
	for _, r := range s.rows {
		pad := label - len([]rune(r.label))
		out = append(out, fmt.Sprintf("  %s%s  %*s  %5s  %s", r.label, strings.Repeat(" ", pad), count, formatNumber(r.count),
			share(r.count, s.base), barCells(r.count, peak, dashBar, "▏", r.color, c)))
	}
	if s.note != "" {
		note := "  " + s.note
		out = append(out, dim(note)+strings.Repeat(" ", max(0, width-len([]rune(note)))))
	}
	return out, width
}

// renderDashboard draws the dashboard for a terminal width columns wide (0: unknown): vendors and weaknesses side
// by side when both fit, else one under the other.
func renderDashboard(d dashboardData, columns int, c *renderer.ColorConfig) string {
	var b strings.Builder
	bold := func(n int) string { return c.Colorize(formatNumber(n), renderer.Bold) }
	fmt.Fprintf(&b, "\n  %s CVEs   %s known exploited (CISA)   %s known exploited (VulnCheck)   %s public exploit\n",
		bold(d.Total), c.Colorize(formatNumber(d.Exploit["known_exploited"]), renderer.Bold+renderer.BrightRed),
		c.Colorize(formatNumber(d.Exploit["vulncheck_known_exploited"]), renderer.Bold+renderer.BrightRed), bold(d.Exploit["public_exploit"]))

	severity := dashSection{title: "SEVERITY"}
	for _, sev := range gridSeverities {
		if n := d.Severity[sev]; n > 0 {
			severity.rows = append(severity.rows, dashRow{sev, n, gridColors[sev]})
			severity.base += n
		}
	}
	vendors := dashSection{title: "TOP VENDORS", base: d.Total}
	for _, v := range d.Vendors[:min(5, len(d.Vendors))] {
		vendors.rows = append(vendors.rows, dashRow{termtext.Clean(v.key), v.count, ""})
	}
	weaknesses := dashSection{title: "TOP WEAKNESSES", base: d.Total}
	for _, w := range d.Weaknesses[:min(5, len(d.Weaknesses))] {
		label := w.key
		if name := cweNames[w.key]; name != "" {
			label += " " + name
		}
		weaknesses.rows = append(weaknesses.rows, dashRow{label, w.count, ""})
	}
	exploitation := dashSection{title: "EXPLOITATION", base: d.Total, note: "VulnCheck KEV includes every CISA KEV entry"}
	for _, r := range []struct{ key, label string }{
		{"known_exploited", "CISA KEV"}, {"vulncheck_known_exploited", "VulnCheck KEV"}, {"ransomware", "ransomware use"},
		{"initial_access", "initial access"}, {"nuclei_template", "nuclei template"}, {"public_exploit", "public exploit"},
	} {
		if n := d.Exploit[r.key]; n > 0 {
			exploitation.rows = append(exploitation.rows, dashRow{r.label, n, gridColors["high"]})
		}
	}
	slices.SortStableFunc(exploitation.rows, func(a, b dashRow) int { return b.count - a.count })
	epss := dashSection{title: "EPSS", base: d.Total}
	if e := d.EPSS; e != nil {
		for i, band := range []struct {
			label string
			n     int
		}{
			{"0.7–1.0 (critical)", e[0]}, {"0.3–0.7 (high)", e[1] - e[0]}, {"0.1–0.3 (medium)", e[2] - e[1]}, {"under 0.1 or none", d.Total - e[2]},
		} {
			epss.rows = append(epss.rows, dashRow{band.label, band.n, gridColors[gridSeverities[i]]})
		}
	}

	section := func(s dashSection) {
		if len(s.rows) == 0 {
			return
		}
		lines, _ := s.lines(c)
		b.WriteString("\n")
		for _, l := range lines {
			b.WriteString(strings.TrimRight(l, " ") + "\n") // the padding is only for side by side
		}
	}
	section(severity)
	left, lw := vendors.lines(c)
	right, rw := weaknesses.lines(c)
	const gap = "  "
	if len(vendors.rows) > 0 && len(weaknesses.rows) > 0 && columns >= lw+len(gap)+rw {
		b.WriteString("\n")
		for i := range max(len(left), len(right)) {
			l, r := strings.Repeat(" ", lw), ""
			if i < len(left) {
				l = left[i]
			}
			if i < len(right) {
				r = right[i]
			}
			b.WriteString(strings.TrimRight(l+gap+r, " ") + "\n")
		}
	} else {
		section(vendors)
		section(weaknesses)
	}
	section(exploitation)
	section(epss)
	for _, u := range d.Unavailable {
		b.WriteString("\n  " + c.Colorize("Unavailable: "+termtext.Clean(u), renderer.Gray) + "\n")
	}
	return b.String()
}

// renderQuickStart lists commands to start from.
func renderQuickStart(c *renderer.ColorConfig) string {
	commands := [][2]string{
		{"vulnx --help", "show help menu"},
		{`vulnx search "is_template:true"`, "cves with nuclei templates"},
		{`vulnx search "is_kev:true"`, "known exploited vulns"},
		{"vulnx id CVE-2021-44228", "fetch metadata for a CVE"},
		{"vulnx search --cpe <cpe>", "cves affecting a product version"},
		{"vulnx scan package-lock.json", "scan a lockfile or sbom (--vex)"},
		{"vulnx scan --host", "scan this machine"},
		{"vulnx analyze -f severity", "analyze by severity"},
	}
	width := 0
	for _, cmd := range commands {
		width = max(width, len(cmd[0]))
	}
	var b strings.Builder
	b.WriteString("\n  " + c.Colorize("QUICK START", renderer.Gray) + "\n")
	for _, cmd := range commands {
		fmt.Fprintf(&b, "  %-*s  %s\n", width, cmd[0], c.Colorize(cmd[1], renderer.Gray))
	}
	b.WriteString("\n")
	return b.String()
}

// cweLabel is a CWE id as a weakness bucket key; other keys (NVD-CWE-noinfo, CWE-Other) are not weaknesses.
var cweLabel = regexp.MustCompile(`^CWE-[0-9]+$`)

// cweNames names the weaknesses that lead the CVE list (CWE Top 25 and other frequent ones).
var cweNames = map[string]string{
	"CWE-79": "cross-site scripting", "CWE-787": "out-of-bounds write", "CWE-89": "sql injection",
	"CWE-352": "cross-site request forgery", "CWE-22": "path traversal", "CWE-125": "out-of-bounds read",
	"CWE-78": "os command injection", "CWE-416": "use after free", "CWE-862": "missing authorization",
	"CWE-434": "unrestricted file upload", "CWE-94": "code injection", "CWE-20": "improper input validation",
	"CWE-77": "command injection", "CWE-287": "improper authentication", "CWE-269": "improper privilege management",
	"CWE-502": "unsafe deserialization", "CWE-200": "information exposure", "CWE-863": "incorrect authorization",
	"CWE-918": "server-side request forgery", "CWE-119": "memory buffer errors", "CWE-476": "null pointer dereference",
	"CWE-798": "hard-coded credentials", "CWE-190": "integer overflow", "CWE-400": "uncontrolled resource consumption",
	"CWE-306": "missing authentication", "CWE-120": "buffer overflow", "CWE-401": "memory leak",
	"CWE-284": "improper access control", "CWE-264": "permissions & privileges", "CWE-399": "resource management",
	"CWE-617": "reachable assertion", "CWE-639": "authorization bypass (idor)", "CWE-601": "open redirect",
	"CWE-362": "race condition", "CWE-732": "incorrect permissions", "CWE-611": "xml external entities",
}
