package vulnx

// VEX documents from a stack result (vulnx scan --vex, issue #385): one statement per (package, CVE).
//
//   affected row            -> CycloneDX "exploitable" / OpenVEX "affected" (with the fixed version when known)
//   undetermined row        -> CycloneDX "in_triage"   / OpenVEX "under_investigation" (with SecurityContext's reason)
//
// A clean package gets no statement: SecurityContext reports the advisories that do affect a version, not the
// ones it ruled out, so there is nothing to say "not_affected" about.

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// PackageURL returns a purl for a stack item: its input when that is a purl or CPE, otherwise built from the
// ecosystem/name the item carries.
func (it StackItem) PackageURL() string {
	in := strings.TrimSpace(it.Input)
	if strings.HasPrefix(in, "pkg:") || strings.HasPrefix(in, "cpe:") {
		return in
	}
	eco, name, ok := strings.Cut(it.Package, "/")
	if !ok || it.Version == "" {
		return in
	}
	typ := map[string]string{"pypi": "pypi", "npm": "npm", "maven": "maven", "go": "golang", "golang": "golang",
		"cargo": "cargo", "crates.io": "cargo", "rubygems": "gem", "gem": "gem", "composer": "composer",
		"packagist": "composer", "nuget": "nuget", "pub": "pub", "hex": "hex", "swift": "swift", "cpe": ""}[strings.ToLower(eco)]
	if typ == "" {
		return in
	}
	switch typ {
	case "maven":
		name = strings.Replace(name, ":", "/", 1)
	case "npm":
		name = strings.Replace(name, "@", "%40", 1)
	}
	return fmt.Sprintf("pkg:%s/%s@%s", typ, name, it.Version)
}

var commitHash = regexp.MustCompile(`^[0-9a-f]{12,40}$`)

// fixedVersions reads an advisory's fixed_in (a string or a list) as versions, leaving out commit hashes.
func fixedVersions(v any) string {
	var vals []string
	switch x := v.(type) {
	case string:
		vals = []string{x}
	case []any:
		for _, e := range x {
			vals = append(vals, fmt.Sprint(e))
		}
	}
	var out []string
	for _, s := range vals {
		s = strings.TrimSpace(s)
		if s != "" && !commitHash.MatchString(strings.ToLower(s)) {
			out = append(out, s)
		}
	}
	return strings.Join(out, " or ")
}

type vexStatement struct {
	cve, product, status, detail, fix string
}

func vexStatements(res StackResult) []vexStatement {
	var out []vexStatement
	seen := map[string]bool{}
	add := func(s vexStatement) {
		k := s.cve + "|" + s.product
		if s.cve == "" || seen[k] {
			return
		}
		seen[k] = true
		out = append(out, s)
	}
	for _, it := range res.Items {
		p := it.PackageURL()
		if p == "" {
			continue
		}
		for _, a := range it.AdvisoryRows {
			id := a.CVE
			if id == "" {
				id = a.AdvisoryID
			}
			fix := fixedVersions(a.FixedIn)
			if fix == "" {
				fix = it.FixedVersion
			}
			add(vexStatement{cve: id, product: p, status: "affected", fix: fix})
		}
		for _, a := range it.Undetermined {
			id := a.CVE
			if id == "" {
				id = a.AdvisoryID
			}
			add(vexStatement{cve: id, product: p, status: "under_investigation", detail: a.Reason})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].product != out[j].product {
			return out[i].product < out[j].product
		}
		return out[i].cve < out[j].cve
	})
	return out
}

// OpenVEX renders the stack as an OpenVEX document.
func OpenVEX(res StackResult, author string, now time.Time) ([]byte, error) {
	type stmt struct {
		Vulnerability   map[string]string   `json:"vulnerability"`
		Products        []map[string]string `json:"products"`
		Status          string              `json:"status"`
		StatusNotes     string              `json:"status_notes,omitempty"`
		ActionStatement string              `json:"action_statement,omitempty"`
	}
	ts := now.UTC().Format(time.RFC3339)
	doc := map[string]any{
		"@context":  "https://openvex.dev/ns/v0.2.0",
		"@id":       fmt.Sprintf("https://openvex.dev/docs/vulnx/%d", now.UnixNano()),
		"author":    author,
		"timestamp": ts,
		"version":   1,
		"tooling":   "vulnx (SecurityContext)",
	}
	stmts := []stmt{}
	for _, s := range vexStatements(res) {
		st := stmt{Vulnerability: map[string]string{"name": s.cve}, Products: []map[string]string{{"@id": s.product}}, Status: s.status}
		if s.status == "affected" {
			st.ActionStatement = "No fixed version known"
			if s.fix != "" {
				st.ActionStatement = "Upgrade to " + s.fix
			}
		} else if s.detail != "" {
			st.StatusNotes = s.detail
		}
		stmts = append(stmts, st)
	}
	doc["statements"] = stmts
	return json.MarshalIndent(doc, "", "  ")
}

// CycloneDXVEX renders the stack as a CycloneDX 1.5 VEX document.
func CycloneDXVEX(res StackResult, now time.Time) ([]byte, error) {
	type affect struct {
		Ref string `json:"ref"`
	}
	type analysis struct {
		State    string   `json:"state"`
		Response []string `json:"response,omitempty"`
		Detail   string   `json:"detail,omitempty"`
	}
	type vuln struct {
		ID       string   `json:"id"`
		Source   any      `json:"source,omitempty"`
		Analysis analysis `json:"analysis"`
		Affects  []affect `json:"affects"`
	}
	vulns := []vuln{}
	for _, s := range vexStatements(res) {
		v := vuln{ID: s.cve, Affects: []affect{{Ref: s.product}}}
		if strings.HasPrefix(s.cve, "CVE-") {
			v.Source = map[string]string{"name": "NVD", "url": "https://nvd.nist.gov/vuln/detail/" + s.cve}
		}
		if s.status == "affected" {
			v.Analysis = analysis{State: "exploitable", Response: []string{"update"}}
			if s.fix != "" {
				v.Analysis.Detail = "Fixed in " + s.fix
			} else {
				v.Analysis.Response = []string{"can_not_fix"}
				v.Analysis.Detail = "No fixed version known"
			}
		} else {
			v.Analysis = analysis{State: "in_triage", Detail: s.detail}
		}
		vulns = append(vulns, v)
	}
	doc := map[string]any{
		"bomFormat":       "CycloneDX",
		"specVersion":     "1.5",
		"version":         1,
		"metadata":        map[string]any{"timestamp": now.UTC().Format(time.RFC3339), "tools": []map[string]string{{"name": "vulnx", "vendor": "ProjectDiscovery"}}},
		"vulnerabilities": vulns,
	}
	return json.MarshalIndent(doc, "", "  ")
}
