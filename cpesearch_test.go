package vulnx

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
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
	writeJSON(s.t, w, map[string]any{"found": s.found, "advisories_total": s.total, "advisories": rows, "cursor": next})
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
		{"default sort keeps the server's order", 250, SearchParams{SortDesc: Ptr("cve_created_at"), Limit: Ptr(2)}, 2, 250, "CVE-2020-0000", "2"},
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
			if got := strings.Join(s.limits, ","); got != c.wantLimits {
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
	if n := len(s.limits); n != 1 {
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
	s.found = false
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
