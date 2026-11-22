package vulnx

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/utils/errkit"
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

// TestCheckExtensions reads the removals an API that judges editor extensions answers, and says "not checked",
// with no error, for one that refuses the type.
func TestCheckExtensions(t *testing.T) {
	knows, unavailable := true, false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if unavailable {
			if _, err := w.Write([]byte(`{"total": 1, "items": [{"input": "pkg:vscode-extension/evil/stealer@1.0.0",
				"status": "undetermined", "reason": "extension_removals_unavailable"}]}`)); err != nil {
				t.Error(err)
			}
			return
		}
		if !knows {
			w.WriteHeader(http.StatusBadRequest)
			if _, err := w.Write([]byte(`{"error": "packages: unknown purl type 'vscode-extension'", "field": "packages"}`)); err != nil {
				t.Error(err)
			}
			return
		}
		if _, err := w.Write([]byte(`{"total": 1, "summary": {"packages": 1, "affected": 1, "malicious": 1}, "items": [
			{"input": "pkg:vscode-extension/evil/stealer@1.0.0", "status": "affected", "malicious": true, "note": "removed",
			 "removed": [{"marketplace": "vs-marketplace", "type": "Malware", "tier": "malicious", "removed_at": "2026-10-02"}]}]}`)); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()
	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	entries := []string{"pkg:vscode-extension/evil/stealer@1.0.0"}
	res, checked, err := c.CheckExtensions(context.Background(), entries)
	if err != nil || !checked || len(res.Items) != 1 || !res.Items[0].Malicious ||
		res.Items[0].Removed[0] != (StackRemoval{Marketplace: "vs-marketplace", Type: "Malware", Tier: "malicious", RemovedAt: "2026-10-02"}) {
		t.Fatalf("err %v checked %v res %+v", err, checked, res)
	}
	knows = false
	if res, checked, err = c.CheckExtensions(context.Background(), entries); err != nil || checked || len(res.Items) != 0 {
		t.Fatalf("an API without the type: err %v checked %v", err, checked)
	}
	knows, unavailable = true, true
	if res, checked, err = c.CheckExtensions(context.Background(), entries); err != nil || checked || len(res.Items) != 0 {
		t.Fatalf("an API with no removal lists: err %v checked %v", err, checked)
	}
	if _, checked, err = c.CheckExtensions(context.Background(), nil); err != nil || !checked {
		t.Fatalf("nothing to check: err %v checked %v", err, checked)
	}
}

// TestShareFile uploads with a one-day expiry where the API can expire stacks, and does not send the file where
// it cannot.
func TestShareFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "host.cdx.json")
	if err := os.WriteFile(file, []byte(`{"bomFormat":"CycloneDX","components":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, supported := range []bool{true, false} {
		uploads, field := 0, ""
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/openapi.json" {
				if supported {
					_, _ = w.Write([]byte(`{"paths": {"/v1/stack": {"post": {"properties": {"expires_in": {}}}}}}`))
				} else {
					_, _ = w.Write([]byte(`{"paths": {}}`))
				}
				return
			}
			uploads++
			field = r.FormValue("expires_in")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"found": true, "id": "abc", "status": "queued", "expires_at": "2026-11-12T15:00:00Z"}`))
		}))
		c, err := New(WithBaseURL(srv.URL))
		if err != nil {
			t.Fatal(err)
		}
		id, expiresAt, err := c.ShareFile(context.Background(), file, 24*time.Hour)
		srv.Close()
		if supported && (err != nil || id != "abc" || expiresAt != "2026-11-12T15:00:00Z" || field != "86400" || uploads != 1) {
			t.Errorf("supported: id %q expires %q field %q uploads %d err %v", id, expiresAt, field, uploads, err)
		}
		if !supported && (!errkit.Is(err, ErrExpiryUnsupported) || uploads != 0) {
			t.Errorf("unsupported: uploads %d err %v", uploads, err)
		}
	}
}

// TestProductsByRepository reads the products per repository, and reports an API without the lookup as unsupported.
func TestProductsByRepository(t *testing.T) {
	old := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if old {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error": "unknown query parameter(s) ['repository']", "field": "query"}`))
			return
		}
		if r.URL.Query().Get("repository") != "unicode-org/icu,google/brotli" {
			t.Errorf("query %s", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"items": [
			{"product": "icu-project:international_components_for_unicode", "repositories": ["unicode-org/icu"], "repositories_total": 1},
			{"product": "unicode:international_components_for_unicode", "repositories": ["unicode-org/icu"], "repositories_total": 1},
			{"product": "other:suite", "repositories": ["google/brotli"], "repositories_total": 2},
			{"product": "google:brotli", "repositories": ["google/brotli"], "repositories_total": 1}], "cursor": null}`))
	}))
	defer srv.Close()
	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	products, supported, err := c.ProductsByRepository(context.Background(), []string{"unicode-org/icu", "google/brotli"})
	if err != nil || !supported || len(products["unicode-org/icu"]) != 2 || strings.Join(products["google/brotli"], ",") != "google:brotli" { // not the product that lists two
		t.Errorf("%v %v %v", products, supported, err)
	}
	old = true
	if _, supported, err := c.ProductsByRepository(context.Background(), []string{"a/b"}); err != nil || supported {
		t.Errorf("an API without the lookup: supported %v err %v", supported, err)
	}
}

// TestCheckFunctionsFallback asks for function lists, and on an API that rejects the field answers without them.
func TestCheckFunctionsFallback(t *testing.T) {
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(raw))
		if strings.Contains(string(raw), `"functions"`) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error": "unknown body field(s) ['functions']", "field": "body"}`))
			return
		}
		_, _ = w.Write([]byte(`{"total": 1, "items": [{"input": "pkg:npm/a@1", "status": "clean"}]}`))
	}))
	defer srv.Close()
	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.CheckManyWith(context.Background(), []string{"pkg:npm/a@1"}, CheckOptions{Functions: true})
	if err != nil || !res.FunctionsUnavailable || len(res.Items) != 1 || len(bodies) != 2 {
		t.Fatalf("err %v, unavailable %v, items %d, requests %d", err, res.FunctionsUnavailable, len(res.Items), len(bodies))
	}
}
