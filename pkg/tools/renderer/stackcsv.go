package renderer

import (
	"fmt"
	"strings"

	"github.com/projectdiscovery/vulnx/v2"
)

// stackRow is one row of a scan's CSV: a package with one of its advisories, or alone when it has none.
type stackRow struct {
	item vulnx.StackItem
	adv  vulnx.StackAdvisory
}

var stackCSVColumns = []csvColumn[stackRow]{
	{"input", func(r stackRow) string { return r.item.Input }},
	{"package", func(r stackRow) string { return r.item.Package }},
	{"version", func(r stackRow) string { return r.item.Version }},
	{"status", func(r stackRow) string {
		if r.item.Unseen() {
			return "unseen"
		}
		return r.item.Status
	}},
	{"fixed_version", func(r stackRow) string { return r.item.FixedVersion }},
	{"advisory", func(r stackRow) string {
		if r.adv.CVE != "" {
			return r.adv.CVE
		}
		return r.adv.AdvisoryID
	}},
	{"severity", func(r stackRow) string { return r.adv.Severity }},
	{"cvss", func(r stackRow) string {
		if r.adv.CvssScore == 0 {
			return ""
		}
		return fmt.Sprintf("%.1f", r.adv.CvssScore)
	}},
	{"known_exploited", func(r stackRow) string { return yes(r.adv.Exploit != nil && r.adv.Exploit.KnownExploited) }},
	{"public_exploit", func(r stackRow) string { return yes(r.adv.Exploit != nil && r.adv.Exploit.PublicExploit) }},
	{"fixed_in", func(r stackRow) string { return fixedIn(r.adv.FixedIn) }},
	{"name", func(r stackRow) string { return strings.TrimSpace(r.adv.Name) }},
}

// fixedIn is an advisory's fixed versions, which the API gives as one string or a list.
func fixedIn(v any) string {
	switch f := v.(type) {
	case string:
		return f
	case []any:
		parts := make([]string, 0, len(f))
		for _, p := range f {
			parts = append(parts, fmt.Sprint(p))
		}
		return strings.Join(parts, " ")
	}
	return ""
}

func yes(b bool) string {
	if b {
		return "yes"
	}
	return ""
}

// RenderStackCSV is a scan result as CSV: one row per package and advisory, and one row for a package with none.
func RenderStackCSV(res vulnx.StackResult) ([]byte, error) {
	var rows []stackRow
	for _, it := range res.Items {
		if len(it.AdvisoryRows) == 0 {
			rows = append(rows, stackRow{item: it})
			continue
		}
		for _, a := range it.AdvisoryRows {
			rows = append(rows, stackRow{item: it, adv: a})
		}
	}
	return renderCSV(rows, stackCSVColumns)
}
