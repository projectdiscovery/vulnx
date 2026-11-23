package vulnx

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestPackageURLEcosystems(t *testing.T) {
	for _, c := range []struct {
		it   StackItem
		want string
	}{
		{StackItem{Input: " pkg:pypi/requests@2.0 ", Package: "pypi/requests", Version: "2.0"}, "pkg:pypi/requests@2.0"},
		{StackItem{Input: "x", Package: "crates.io/serde", Version: "1.0.0"}, "pkg:cargo/serde@1.0.0"},
		{StackItem{Input: "x", Package: "RubyGems/rails", Version: "7.0.0"}, "pkg:gem/rails@7.0.0"},
		{StackItem{Input: "x", Package: "packagist/laravel/framework", Version: "10.0.0"}, "pkg:composer/laravel/framework@10.0.0"},
		{StackItem{Input: "x", Package: "unknown/thing", Version: "1"}, "x"},
		{StackItem{Input: "x", Package: "npm/lodash"}, "x"},
		{StackItem{Input: "x", Package: "lodash", Version: "1"}, "x"},
	} {
		if got := c.it.PackageURL(); got != c.want {
			t.Errorf("%+v: %q, want %q", c.it, got, c.want)
		}
	}
}

func TestVEXStatements(t *testing.T) {
	res := StackResult{Items: []StackItem{
		{Input: "npm/b@1", Package: "npm/b", Version: "1",
			AdvisoryRows: []StackAdvisory{{CVE: "CVE-2021-2"}, {AdvisoryID: "GHSA-xxxx-yyyy-zzzz"}, {}},
			Undetermined: []StackAdvisory{{CVE: "CVE-2021-2", Reason: "already affected"}}},
		{Input: "npm/a@1", Package: "npm/a", Version: "1", AdvisoryRows: []StackAdvisory{{CVE: "CVE-2021-9"}, {CVE: "CVE-2021-1"}}},
		{Input: "", Package: "", AdvisoryRows: []StackAdvisory{{CVE: "CVE-2021-3"}}},
	}}
	var got []string
	for _, s := range vexStatements(res) {
		got = append(got, s.product+" "+s.cve+" "+s.status)
	}
	want := []string{
		"pkg:npm/a@1 CVE-2021-1 affected",
		"pkg:npm/a@1 CVE-2021-9 affected",
		"pkg:npm/b@1 CVE-2021-2 affected",
		"pkg:npm/b@1 GHSA-xxxx-yyyy-zzzz affected",
	}
	if len(got) != len(want) {
		t.Fatalf("statements %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("statement %d: %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCycloneDXVEXAnalysis(t *testing.T) {
	res := StackResult{Items: []StackItem{{Input: "npm/a@1", Package: "npm/a", Version: "1",
		AdvisoryRows: []StackAdvisory{{CVE: "CVE-2021-1", FixedIn: "1.0.1"}, {AdvisoryID: "GHSA-aaaa-bbbb-cccc"}}}}}
	raw, err := CycloneDXVEX(res, time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Vulnerabilities []struct {
			ID       string            `json:"id"`
			Source   map[string]string `json:"source"`
			Analysis struct {
				State    string   `json:"state"`
				Response []string `json:"response"`
				Detail   string   `json:"detail"`
			} `json:"analysis"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Vulnerabilities) != 2 {
		t.Fatalf("vulnerabilities: %s", raw)
	}
	fixed, unfixed := doc.Vulnerabilities[0], doc.Vulnerabilities[1]
	if fixed.Source["name"] != "NVD" || fixed.Analysis.Response[0] != "update" || fixed.Analysis.Detail != "Fixed in 1.0.1" {
		t.Errorf("fixed CVE: %+v", fixed)
	}
	if unfixed.Source != nil || unfixed.Analysis.Response[0] != "can_not_fix" {
		t.Errorf("unfixed advisory: %+v", unfixed)
	}
}

func TestVEX(t *testing.T) {
	res := StackResult{Items: []StackItem{
		{Input: "npm/minimist@1.2.5", Package: "npm/minimist", Version: "1.2.5", Status: "affected", FixedVersion: "1.2.6",
			AdvisoryRows: []StackAdvisory{{CVE: "CVE-2021-44906", FixedIn: []any{"1.2.6"}}, {CVE: "CVE-2021-44906"}}},
		{Input: "pypi/r@2", Package: "pypi/r", Version: "2", Status: "affected",
			AdvisoryRows: []StackAdvisory{{CVE: "CVE-2020-1"}},
			Undetermined: []StackAdvisory{{CVE: "CVE-2020-2", Reason: "project_range_unknown"}}},
		{Input: "npm/left-pad@1.3.0", Package: "npm/left-pad", Version: "1.3.0", Status: "clean"},
	}}
	now := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	raw, err := OpenVEX(res, "me", now)
	if err != nil {
		t.Fatal(err)
	}
	var o struct {
		Author     string `json:"author"`
		Statements []struct {
			Vulnerability   map[string]string   `json:"vulnerability"`
			Products        []map[string]string `json:"products"`
			Status          string              `json:"status"`
			StatusNotes     string              `json:"status_notes"`
			ActionStatement string              `json:"action_statement"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(raw, &o); err != nil {
		t.Fatal(err)
	}
	if o.Author != "me" || len(o.Statements) != 3 {
		t.Fatalf("openvex: %s", raw)
	}
	got := map[string]string{}
	for _, s := range o.Statements {
		got[s.Vulnerability["name"]+"|"+s.Products[0]["@id"]] = s.Status + "|" + s.ActionStatement + s.StatusNotes
	}
	want := map[string]string{
		"CVE-2021-44906|pkg:npm/minimist@1.2.5": "affected|Upgrade to 1.2.6",
		"CVE-2020-1|pkg:pypi/r@2":               "affected|No fixed version known",
		"CVE-2020-2|pkg:pypi/r@2":               "under_investigation|project_range_unknown",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q, want %q", k, got[k], v)
		}
	}
	raw, err = CycloneDXVEX(res, now)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"state": "exploitable"`) || !strings.Contains(string(raw), `"state": "in_triage"`) {
		t.Errorf("cyclonedx: %s", raw)
	}
}

func TestVEXDuplicateKeepsFix(t *testing.T) {
	res := StackResult{Items: []StackItem{{Input: "npm/minimist@1.2.5", Package: "npm/minimist", Version: "1.2.5",
		AdvisoryRows: []StackAdvisory{{CVE: "CVE-2021-44906"}, {CVE: "CVE-2021-44906", FixedIn: "1.2.6"}}}}}
	st := vexStatements(res)
	if len(st) != 1 || st[0].fix != "1.2.6" {
		t.Errorf("statements %+v, want one with fix 1.2.6", st)
	}
}

func TestCycloneDXVEXComponents(t *testing.T) {
	res := StackResult{Items: []StackItem{
		{Input: "npm/a@1", Package: "npm/a", Version: "1", AdvisoryRows: []StackAdvisory{{CVE: "CVE-2021-1"}, {CVE: "CVE-2021-2"}}},
		{Input: "cpe:2.3:a:apache:tomcat:8.5.62:*:*:*:*:*:*:*", Package: "cpe/apache:tomcat", Version: "8.5.62", AdvisoryRows: []StackAdvisory{{CVE: "CVE-2021-3"}}},
	}}
	raw, err := CycloneDXVEX(res, time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components      []map[string]string `json:"components"`
		Vulnerabilities []struct {
			Affects []struct {
				Ref string `json:"ref"`
			} `json:"affects"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	refs := map[string]map[string]string{}
	for _, c := range doc.Components {
		refs[c["bom-ref"]] = c
	}
	if len(doc.Components) != 2 {
		t.Fatalf("components %v, want one per product", doc.Components)
	}
	for _, v := range doc.Vulnerabilities {
		if refs[v.Affects[0].Ref] == nil {
			t.Errorf("affects ref %q has no component", v.Affects[0].Ref)
		}
	}
	if c := refs["pkg:npm/a@1"]; c["name"] != "a" || c["version"] != "1" || c["purl"] != "pkg:npm/a@1" {
		t.Errorf("purl component: %v", c)
	}
	if c := refs["cpe:2.3:a:apache:tomcat:8.5.62:*:*:*:*:*:*:*"]; c["name"] != "apache:tomcat" || c["version"] != "8.5.62" || c["cpe"] == "" {
		t.Errorf("cpe component: %v", c)
	}
}

func TestVEXComponentDecodesPURL(t *testing.T) {
	for ref, want := range map[string][2]string{
		"pkg:deb/debian/foo@1%3A2.0-1?distro=debian-12": {"foo", "1:2.0-1"},
		"pkg:golang/github.com/a/b@v1.2.3#sub/dir":      {"b", "v1.2.3"},
		"pkg:npm/%40babel/core@7.0.0":                   {"core", "7.0.0"},
	} {
		c := vexComponent(ref)
		if c["name"] != want[0] || c["version"] != want[1] || c["purl"] != ref || c["bom-ref"] != ref {
			t.Errorf("%s: %v, want name %s version %s", ref, c, want[0], want[1])
		}
	}
}
