package vulnx

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNormalizeCheckEntry(t *testing.T) {
	cases := map[string]string{
		"apache:tomcat@8.5.62":                             "cpe:2.3:a:apache:tomcat:8.5.62:*:*:*:*:*:*:*",
		"jquery/jquery@1.11.3":                             "cpe:2.3:a:jquery:jquery:1.11.3:*:*:*:*:*:*:*",
		"npm/lodash@4.17.20":                               "npm/lodash@4.17.20",
		"pypi/django@3.2.0":                                "pypi/django@3.2.0",
		"pkg:npm/lodash@4.17.20":                           "pkg:npm/lodash@4.17.20",
		"cpe:2.3:a:x:y:1:*:*:*:*:*:*:*":                    "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*",
		"maven/org.apache.logging.log4j:log4j-core@2.14.1": "maven/org.apache.logging.log4j:log4j-core@2.14.1",
	}
	for in, want := range cases {
		if got := NormalizeCheckEntry(in); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}

func TestSBOMEntries(t *testing.T) {
	cdx := `{"bomFormat":"CycloneDX","components":[
	  {"purl":"pkg:npm/a@1"},
	  {"cpe":"cpe:2.3:a:apache:tomcat:8.5.62:*:*:*:*:*:*:*"},
	  {"purl":"pkg:npm/a@1"},
	  {"name":"nothing"},
	  {"purl":"pkg:maven/g/b@2","components":[{"purl":"pkg:npm/nested@3"}]}]}`
	e, f, ok := SBOMEntries([]byte(cdx))
	if !ok || f != "cyclonedx" || strings.Join(e, ",") != "pkg:npm/a@1,cpe:2.3:a:apache:tomcat:8.5.62:*:*:*:*:*:*:*,pkg:maven/g/b@2,pkg:npm/nested@3" {
		t.Errorf("cyclonedx: %v %s %v", e, f, ok)
	}
	spdx := `{"spdxVersion":"SPDX-2.3","packages":[
	  {"externalRefs":[{"referenceType":"cpe23Type","referenceLocator":"cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"},{"referenceType":"purl","referenceLocator":"pkg:pypi/r@2"}]},
	  {"externalRefs":[{"referenceType":"cpe23Type","referenceLocator":"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}]}]}`
	e, f, ok = SBOMEntries([]byte(spdx))
	if !ok || f != "spdx" || strings.Join(e, ",") != "pkg:pypi/r@2,cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*" {
		t.Errorf("spdx: %v %s %v", e, f, ok)
	}
	if _, _, ok := SBOMEntries([]byte(`{"lockfileVersion":3,"packages":{}}`)); ok {
		t.Error("a package-lock.json read as an SBOM")
	}
	if _, _, ok := SBOMEntries([]byte("services:\n  web:\n")); ok {
		t.Error("YAML read as an SBOM")
	}
}

func TestPackageURLAndFixes(t *testing.T) {
	for _, c := range []struct {
		it   StackItem
		want string
	}{
		{StackItem{Input: "npm/lodash@4.17.20", Package: "npm/lodash", Version: "4.17.20"}, "pkg:npm/lodash@4.17.20"},
		{StackItem{Input: "x", Package: "npm/@babel/core", Version: "7.0.0"}, "pkg:npm/%40babel/core@7.0.0"},
		{StackItem{Input: "x", Package: "maven/org.a:b", Version: "1"}, "pkg:maven/org.a/b@1"},
		{StackItem{Input: "x", Package: "go/github.com/a/b", Version: "v1.0.0"}, "pkg:golang/github.com/a/b@v1.0.0"},
		{StackItem{Input: "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*", Package: "cpe/x:y", Version: "1"}, "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"},
	} {
		if got := c.it.PackageURL(); got != c.want {
			t.Errorf("%+v: %s, want %s", c.it, got, c.want)
		}
	}
	if got := fixedVersions([]any{"2.31.0", "74ea7cf7a6a27a4eeb2ae24e162bcc942a6706d5"}); got != "2.31.0" {
		t.Errorf("fixedVersions dropped no commit: %q", got)
	}
	if got := fixedVersions("1.2.6"); got != "1.2.6" {
		t.Errorf("fixedVersions(string): %q", got)
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
