package vulnx

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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

// pagingServer answers a list two items a page with a cursor (or, cursorless, cut with none), counting requests;
// staleOnce answers the first cursor with the API's invalid-cursor 400.
func pagingServer(t *testing.T, cursorless, staleOnce bool) (*httptest.Server, *int) {
	t.Helper()
	calls := 0
	stale := staleOnce
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		raw, _ := io.ReadAll(r.Body)
		var body struct{ Packages []string }
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Error(err)
		}
		offset := 0
		if c := r.URL.Query().Get("cursor"); c != "" {
			if stale {
				stale = false
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error": "invalid cursor", "field": "cursor"}`))
				return
			}
			_, _ = fmt.Sscan(c, &offset)
		}
		end := min(offset+2, len(body.Packages))
		if cursorless && len(body.Packages) > 2 {
			end = 1 // cut, with no way to the rest
		}
		page := map[string]any{"total": len(body.Packages), "truncated": end < len(body.Packages),
			"summary": map[string]any{"packages": len(body.Packages)}}
		var items []map[string]string
		for _, p := range body.Packages[offset:end] {
			items = append(items, map[string]string{"input": p, "status": "clean"})
		}
		page["items"] = items
		if end < len(body.Packages) && !cursorless {
			page["cursor"] = fmt.Sprint(end)
		}
		_ = json.NewEncoder(w).Encode(page)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestCheckFollowsTheCursor(t *testing.T) {
	entries := []string{"pkg:npm/a@1", "pkg:npm/b@1", "pkg:npm/c@1", "pkg:npm/d@1", "pkg:npm/e@1"}
	for _, c := range []struct {
		name              string
		cursorless, stale bool
		requests          int
	}{
		{"pages", false, false, 3},                // 2 + 2 + 1
		{"stale cursor restarts", false, true, 5}, // page, stale 400, then 3 pages again
		{"no cursor splits", true, false, 5},      // all cut -> [a b] whole, [c d e] cut -> [c], [d e]
	} {
		srv, calls := pagingServer(t, c.cursorless, c.stale)
		cl, err := New(WithBaseURL(srv.URL))
		if err != nil {
			t.Fatal(err)
		}
		res, err := cl.CheckMany(context.Background(), entries)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		var got []string
		for _, it := range res.Items {
			got = append(got, it.Input)
		}
		if strings.Join(got, ",") != strings.Join(entries, ",") || *calls != c.requests {
			t.Errorf("%s: %d requests, items %v", c.name, *calls, got)
		}
		if !c.cursorless && (res.Total != 5 || res.Summary.Packages != 5) {
			t.Errorf("%s: total %d, summary %d: the first page's, once", c.name, res.Total, res.Summary.Packages)
		}
	}
}

// TestCheckCompact sends a gzip body asking for a compact answer and turns its refs back into whole rows.
func TestCheckCompact(t *testing.T) {
	var gotCompact bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Encoding") != "gzip" {
			t.Error("no gzip body")
		}
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		var body struct {
			Packages []string
			Compact  bool
		}
		if err := json.NewDecoder(zr).Decode(&body); err != nil {
			t.Fatal(err)
		}
		gotCompact = body.Compact
		_, _ = w.Write([]byte(`{"total": 3, "summary": {"packages": 3, "affected": 2},
			"items": [
				{"input": "pkg:npm/a@1", "package": "npm/a", "status": "affected", "advisory_rows": [{"ref": "a1", "fixed_in": ["2"]}]},
				{"input": "pkg:npm/a@1.5", "package": "npm/a", "status": "affected", "advisory_rows": [{"ref": "a1", "fixed_in": ["2"], "ranges": ["< 2"]}]},
				{"input": "pkg:npm/b@1", "package": "npm/b", "status": "clean"}],
			"advisories": {"a1": {"advisory_id": "GHSA-x", "cve": "CVE-2026-1", "severity": "high",
				"exploitation": {"known_exploited": true}}}}`))
	}))
	defer srv.Close()
	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	entries := make([]string, 1200) // more than a plain request takes: one compact request
	for i := range entries {
		entries[i] = fmt.Sprintf("pkg:npm/p%d@1", i)
	}
	res, err := c.CheckManyWith(context.Background(), entries, CheckOptions{Compact: true})
	if err != nil || !gotCompact {
		t.Fatalf("err %v, compact %v", err, gotCompact)
	}
	row := res.Items[1].AdvisoryRows[0]
	if row.Ref != "" || row.AdvisoryID != "GHSA-x" || row.CVE != "CVE-2026-1" || row.Exploit == nil || !row.Exploit.KnownExploited ||
		fmt.Sprint(row.Ranges) != "[< 2]" || fmt.Sprint(res.Items[0].AdvisoryRows[0].Ranges) != "[]" {
		t.Errorf("rows not expanded: %+v / %+v", res.Items[0].AdvisoryRows[0], row)
	}
}

// TestCheckCompactFallback asks the plain way, MaxCheckEntries a request, when the API refuses a compact check.
func TestCheckCompactFallback(t *testing.T) {
	plain := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Encoding") == "gzip" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error": "the body must be JSON", "field": "body"}`))
			return
		}
		plain++
		var body struct{ Packages []string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		_ = json.NewEncoder(w).Encode(map[string]any{"total": len(body.Packages), "items": []map[string]string{}})
	}))
	defer srv.Close()
	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	entries := make([]string, 1200)
	for i := range entries {
		entries[i] = fmt.Sprintf("pkg:npm/p%d@1", i)
	}
	if _, err := c.CheckManyWith(context.Background(), entries, CheckOptions{Compact: true}); err != nil || plain != 3 {
		t.Fatalf("err %v, plain requests %d (want 3 of 500)", err, plain)
	}
}
