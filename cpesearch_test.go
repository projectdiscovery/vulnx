package vulnx

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// versionServer serves one product version's CVE list: row i has CVSS 10 - i/10, published in 2020 + i%5.
type versionServer struct {
	t      *testing.T
	total  int
	found  bool
	mu     sync.Mutex
	limits []string
}

func (s *versionServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/v1/products/apache/tomcat/versions/8.5.62" {
		s.t.Errorf("path %s", r.URL.Path)
	}
	q := r.URL.Query()
	s.mu.Lock()
	s.limits = append(s.limits, q.Get("limit"))
	found := s.found
	s.mu.Unlock()
	start, _ := strconv.Atoi(q.Get("cursor"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	var rows []map[string]any
	for i := start; i < s.total && len(rows) < limit; i++ {
		sev := "high"
		if i%2 == 0 {
			sev = "critical"
		}
		rows = append(rows, map[string]any{"cve": fmt.Sprintf("CVE-2020-%04d", i), "severity": sev,
			"cvss_score": 10 - float64(i)/10, "published_date": fmt.Sprintf("%d-01-01", 2020+i%5)})
	}
	next := ""
	if start+len(rows) < s.total {
		next = strconv.Itoa(start + len(rows))
	}
	writeJSON(s.t, w, map[string]any{"found": found, "advisories_total": s.total, "advisories": rows, "cursor": next})
}

// pageLimits returns the limit of each request received so far.
func (s *versionServer) pageLimits() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.limits)
}

const tomcatCPE = "cpe:2.3:a:apache:tomcat:8.5.62:*:*:*:*:*:*:*"

func TestSearchCPEPaging(t *testing.T) {
	for _, c := range []struct {
		name       string
		total      int
		params     SearchParams
		wantCount  int
		wantTotal  int
		wantFirst  string
		wantLimits string
	}{
		{"bare cpe fetches only the rows asked for", 250, SearchParams{Limit: Ptr(5)}, 5, 250, "CVE-2020-0000", "5"},
		{"bare cpe with offset", 250, SearchParams{Limit: Ptr(10), Offset: Ptr(95)}, 10, 250, "CVE-2020-0095", "100,5"},
		{"filter fetches the whole list", 250, SearchParams{Query: Ptr("severity:high"), Limit: Ptr(3)}, 3, 125, "CVE-2020-0001", "100,100,100"},
		{"explicit newest-first sort is applied", 250, SearchParams{SortDesc: Ptr("cve_created_at"), Limit: Ptr(2)}, 2, 250, "CVE-2020-0004", "100,100,100"},
		{"ascending cvss sort", 30, SearchParams{SortAsc: Ptr("cvss_score"), Limit: Ptr(2)}, 2, 30, "CVE-2020-0029", "100"},
		{"date sort is stable", 30, SearchParams{SortAsc: Ptr("cve_created_at"), Limit: Ptr(1)}, 1, 30, "CVE-2020-0000", "100"},
		{"all", 150, SearchParams{All: true}, 150, 150, "CVE-2020-0000", "100,100"},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := &versionServer{t: t, total: c.total, found: true}
			srv := httptest.NewServer(s)
			defer srv.Close()
			p := c.params
			q := tomcatCPE
			if p.Query != nil {
				q = "(" + q + ") && (" + *p.Query + ")"
			}
			p.Query = &q
			r, err := newTestClient(t, srv).SearchVulnerabilities(context.Background(), p)
			if err != nil {
				t.Fatal(err)
			}
			if r.Count != c.wantCount || len(r.Results) != c.wantCount || r.Total != c.wantTotal || r.Results[0].CVEID != c.wantFirst {
				t.Errorf("count %d total %d first %s, want %d %d %s", r.Count, r.Total, r.Results[0].CVEID, c.wantCount, c.wantTotal, c.wantFirst)
			}
			if r.Results[0].Vendor != "apache" || r.Results[0].Product != "tomcat" {
				t.Errorf("product not filled from the CPE: %s:%s", r.Results[0].Vendor, r.Results[0].Product)
			}
			if got := strings.Join(s.pageLimits(), ","); got != c.wantLimits {
				t.Errorf("page limits %s, want %s", got, c.wantLimits)
			}
		})
	}
}

func TestSearchCPEErrors(t *testing.T) {
	s := &versionServer{t: t, total: cpeMaxRows + 1, found: true}
	srv := httptest.NewServer(s)
	defer srv.Close()
	c := newTestClient(t, srv)
	search := func(q string, p SearchParams) error {
		p.Query = &q
		_, err := c.SearchVulnerabilities(context.Background(), p)
		return err
	}
	if err := search(tomcatCPE+" && severity:high", SearchParams{}); !errors.Is(err, ErrUnsupportedQuery) || !strings.Contains(err.Error(), strconv.Itoa(cpeMaxRows)) {
		t.Errorf("filter on a version past the cap: %v", err)
	}
	if n := len(s.pageLimits()); n != 1 {
		t.Errorf("past the cap after %d requests, want 1", n)
	}
	for _, bad := range []struct {
		q string
		p SearchParams
	}{
		{tomcatCPE + " && vendor:apache", SearchParams{}},
		{tomcatCPE + " && is_ransomware:true", SearchParams{}},
		{tomcatCPE, SearchParams{SortDesc: Ptr("trending")}},
		{tomcatCPE, SearchParams{TermFacets: []string{"severity"}}},
	} {
		if err := search(bad.q, bad.p); !errors.Is(err, ErrUnsupportedQuery) {
			t.Errorf("%s %+v: %v", bad.q, bad.p, err)
		}
	}
	s.mu.Lock()
	s.found = false
	s.mu.Unlock()
	if err := search(tomcatCPE, SearchParams{}); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown product: %v", err)
	}
}

func TestCPERowMatches(t *testing.T) {
	yes, no := true, false
	r := scCVE{Severity: "critical", CvssScore: 9.8, EpssScore: 0.5, PublishedDate: "2025-03-10", CWE: []byte(`["CWE-22"]`),
		Exploitation: &scExploitation{KnownExploitedBy: []string{"cisa", "vulncheck"}, PublicExploit: true, Remote: &yes, AuthenticationRequired: &no}}
	q := func(s string) bool {
		tq, err := translateQuery(s)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		return cpeRowMatches(r, tq.params)
	}
	for s, want := range map[string]bool{
		"is_kev:true":                        true,
		"is_kev:false":                       false,
		"is_template:true":                   false,
		"severity:critical || severity:high": true,
		"severity:low":                       false,
		"cvss_score:>=9 && epss_score:>=0.4": true,
		"cvss_score:>=9.9":                   false,
		"cve_created_at:2025":                true,
		"cve_created_at:2024":                false,
		"cwe:CWE-22":                         true,
		"cwe:CWE-79":                         false,
		"is_remote:true && is_auth:false":    true,
		"is_auth:true":                       false,
	} {
		if got := q(s); got != want {
			t.Errorf("%s: %v, want %v", s, got, want)
		}
	}
}

// cursorPages serves version-list pages of distinct CVEs, sizes[i] rows on page i, every page with cursor "a".
func cursorPages(t *testing.T, total int, sizes ...int) *httptest.Server {
	var n atomic.Int32
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := int(n.Add(1)) - 1
		start := 0
		for _, sz := range sizes[:min(i, len(sizes))] {
			start += sz
		}
		rows := []map[string]any{}
		for j := range sizes[min(i, len(sizes)-1)] {
			rows = append(rows, map[string]any{"cve": fmt.Sprintf("CVE-2020-%04d", start+j), "severity": "high"})
		}
		writeJSON(t, w, map[string]any{"found": true, "advisories_total": total, "advisories": rows, "cursor": "a"})
	}))
}

func TestSearchCPERepeatedCursor(t *testing.T) {
	for _, c := range []struct {
		name    string
		sizes   []int
		params  SearchParams
		wantErr string
	}{
		{"bare search that has its rows on the repeating page", []int{100, 50}, SearchParams{Limit: Ptr(150)}, ""},
		{"bare search still short when the cursor repeats", []int{100, 30}, SearchParams{Limit: Ptr(150)}, "repeated a page cursor after 130"},
		{"bare search satisfied by the first page", []int{100}, SearchParams{Limit: Ptr(50)}, ""},
		{"--all needs the whole list", []int{100, 100}, SearchParams{All: true}, "repeated a page cursor after 200 of 300"},
		{"a filter needs the whole list", []int{100, 100}, SearchParams{Query: Ptr("severity:high")}, "repeated a page cursor"},
		{"a sort needs the whole list", []int{100, 100}, SearchParams{SortDesc: Ptr("cvss_score")}, "repeated a page cursor"},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv := cursorPages(t, 300, c.sizes...)
			defer srv.Close()
			p := c.params
			q := tomcatCPE
			if p.Query != nil {
				q += " && " + *p.Query
			}
			p.Query = &q
			r, err := newTestClient(t, srv).SearchVulnerabilities(context.Background(), p)
			switch {
			case c.wantErr == "" && err != nil:
				t.Errorf("unexpected error: %v", err)
			case c.wantErr == "" && r.Count != *c.params.Limit:
				t.Errorf("count %d, want %d", r.Count, *c.params.Limit)
			case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
				t.Errorf("err %v, want %q", err, c.wantErr)
			}
		})
	}
}

func TestSearchCPEOverlappingPages(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rows := []map[string]any{}
		for i := range 100 {
			rows = append(rows, map[string]any{"cve": fmt.Sprintf("CVE-2020-%04d", i), "severity": "high"})
		}
		writeJSON(t, w, map[string]any{"found": true, "advisories_total": 300, "advisories": rows, "cursor": r.URL.Query().Get("cursor") + "x"})
	}))
	defer srv.Close()
	_, err := newTestClient(t, srv).SearchVulnerabilities(context.Background(), SearchParams{Query: Ptr(tomcatCPE), All: true})
	if err == nil || !strings.Contains(err.Error(), "returned CVE-2020-0000 twice") {
		t.Errorf("overlapping pages: %v", err)
	}
}

func TestSortRowsUsesShownTimestamp(t *testing.T) {
	rows := []scCVE{
		{CVE: "early", PublishedDate: "2026-01-01", PublishedAt: "2026-01-01T01:00:00Z"},
		{CVE: "late", PublishedDate: "2026-01-01", PublishedAt: "2026-01-01T23:00:00Z"},
	}
	sortRows(rows, "published_date:desc")
	if rows[0].CVE != "late" {
		t.Errorf("same-day rows not ordered by published_at: %s first", rows[0].CVE)
	}
}

func TestSearchCPEIncomplete(t *testing.T) {
	page := func(n int, cursor string) map[string]any {
		rows := []map[string]any{}
		for i := range n {
			rows = append(rows, map[string]any{"cve": fmt.Sprintf("CVE-2020-%04d", i), "severity": "high"})
		}
		return map[string]any{"found": true, "advisories_total": 250, "advisories": rows, "cursor": cursor}
	}
	for _, c := range []struct {
		name    string
		pages   []map[string]any
		params  SearchParams
		wantErr string
	}{
		{"truncated list with --all", []map[string]any{page(100, "")}, SearchParams{All: true}, "paging ended early after 100 of 250"},
		{"truncated list before a filter", []map[string]any{page(100, "")}, SearchParams{Query: Ptr("severity:high")}, "paging ended early"},
		{"empty page repeating the cursor", []map[string]any{page(100, "a"), page(0, "a")}, SearchParams{All: true}, "repeated a page cursor"},
		{"bare search with its rows", []map[string]any{page(100, "")}, SearchParams{Limit: Ptr(50)}, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			var n atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeJSON(t, w, c.pages[min(int(n.Add(1))-1, len(c.pages)-1)])
			}))
			defer srv.Close()
			p := c.params
			q := tomcatCPE
			if p.Query != nil {
				q += " && " + *p.Query
			}
			p.Query = &q
			_, err := newTestClient(t, srv).SearchVulnerabilities(context.Background(), p)
			switch {
			case c.wantErr == "" && err != nil:
				t.Errorf("unexpected error: %v", err)
			case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
				t.Errorf("err %v, want %q", err, c.wantErr)
			}
		})
	}
}

func TestSearchCPEIncompleteCleansServerText(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bad := "CVE-2024-0001\x1b[2J\u202e"
		writeJSON(t, w, map[string]any{"found": true, "advisories_total": 3, "advisories": []map[string]any{{"cve": bad}, {"cve": bad}}, "cursor": "x"})
	}))
	defer srv.Close()
	_, err := newTestClient(t, srv).SearchVulnerabilities(context.Background(), SearchParams{Query: Ptr(tomcatCPE), All: true})
	if err == nil || strings.ContainsAny(err.Error(), "\x1b\u202e") || !strings.Contains(err.Error(), "returned CVE-2024-0001[2J twice") {
		t.Errorf("duplicate-CVE error: %q, want the id without control or bidi characters", err)
	}
}
