package vulnx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// newTestClient returns a client for srv with no key from the environment and a short retry wait.
func newTestClient(t *testing.T, srv *httptest.Server, opts ...Option) *Client {
	t.Helper()
	t.Setenv(APIKeyEnvVar, "")
	c, err := New(append([]Option{WithBaseURL(srv.URL)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	c.retryWait = time.Millisecond
	return c
}

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Error(err)
	}
}

func TestAPIKeyPrecedence(t *testing.T) {
	var got []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.Header.Get(apiKeyHeader))
		mu.Unlock()
		writeJSON(t, w, map[string]any{"cve": "CVE-2021-44228"})
	}))
	defer srv.Close()

	for _, c := range []struct {
		name, env string
		opts      []Option
		want      string
	}{
		{"option beats env", "env-key", []Option{WithAPIKey("opt-key")}, "opt-key"},
		{"env when no option", "env-key", nil, "env-key"},
		{"blank option falls back to env", "env-key", []Option{WithAPIKey("  ")}, "env-key"},
		{"deprecated option", "", []Option{WithPDCPKey("old-key")}, "old-key"},
		{"anonymous", "", nil, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv(APIKeyEnvVar, c.env)
			client, err := New(append([]Option{WithBaseURL(srv.URL)}, c.opts...)...)
			if err != nil {
				t.Fatal(err)
			}
			if client.IsAuthenticated() != (c.want != "") {
				t.Errorf("IsAuthenticated = %v", client.IsAuthenticated())
			}
			if _, err := client.GetVulnerabilityByID(context.Background(), "CVE-2021-44228", nil); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			if last := got[len(got)-1]; last != c.want {
				t.Errorf("X-Api-Key = %q, want %q", last, c.want)
			}
		})
	}
}

func TestAPIKeyOnlyOverSafeTransport(t *testing.T) {
	t.Setenv(APIKeyEnvVar, "")
	for base, sent := range map[string]bool{
		"https://api.example.com": true,
		"http://api.example.com":  false,
		"http://localhost:8080":   true,
		"http://127.0.0.1:8080":   true,
		"http://[::1]:8080":       true,
		"http://10.0.0.1":         false,
	} {
		c, err := New(WithBaseURL(base), WithAPIKey("k"))
		if err != nil {
			t.Fatal(err)
		}
		req, err := c.newRequest(context.Background(), http.MethodGet, "/v1/cves", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := req.Header.Get(apiKeyHeader) != ""; got != sent {
			t.Errorf("%s: key sent = %v, want %v", base, got, sent)
		}
	}
}

func TestAPIKeyDroppedOnCrossHostRedirect(t *testing.T) {
	var otherKey string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherKey = r.Header.Get(apiKeyHeader)
		writeJSON(t, w, map[string]any{"cve": "CVE-2021-44228"})
	}))
	defer other.Close()
	var sameKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/cves/CVE-2021-44228":
			http.Redirect(w, r, other.URL+r.URL.Path, http.StatusFound)
		case "/v1/cves/CVE-2023-4966":
			http.Redirect(w, r, "/moved", http.StatusFound)
		default:
			sameKey = r.Header.Get(apiKeyHeader)
			writeJSON(t, w, map[string]any{"cve": "CVE-2023-4966"})
		}
	}))
	defer srv.Close()

	c := newTestClient(t, srv, WithAPIKey("secret"))
	if _, err := c.GetVulnerabilityByID(context.Background(), "CVE-2021-44228", nil); err != nil {
		t.Fatal(err)
	}
	if otherKey != "" {
		t.Errorf("key sent to another host after a redirect: %q", otherKey)
	}
	if _, err := c.GetVulnerabilityByID(context.Background(), "CVE-2023-4966", nil); err != nil {
		t.Fatal(err)
	}
	if sameKey != "secret" {
		t.Errorf("key lost on a same-host redirect: %q", sameKey)
	}
}

func TestResponseBodyCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := []byte(strings.Repeat(" ", 1<<20))
		for written := 0; written <= maxResponseBytes; written += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer srv.Close()
	_, err := newTestClient(t, srv).GetVulnerabilityByID(context.Background(), "CVE-2021-44228", nil)
	if !errors.Is(err, ErrDecodeResponse) || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("oversized body: %v", err)
	}
}

func TestErrorMessageCleaned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(t, w, map[string]string{"error": "bad \x1b[31mquery\u202e"})
	}))
	defer srv.Close()
	_, err := newTestClient(t, srv).GetVulnerabilityByID(context.Background(), "CVE-2021-44228", nil)
	if !errors.Is(err, ErrBadRequest) {
		t.Fatalf("400: %v", err)
	}
	if strings.ContainsAny(err.Error(), "\x1b\u202e") || !strings.Contains(err.Error(), "bad [31mquery") {
		t.Errorf("server message not cleaned: %q", err)
	}
}

// statusServer answers each request with the next status in the list (and Retry-After when given), then 200.
func statusServer(t *testing.T, statuses []int, retryAfter string) (*httptest.Server, *int) {
	t.Helper()
	calls := 0
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n := calls
		calls++
		mu.Unlock()
		if n < len(statuses) {
			if retryAfter != "" {
				w.Header().Set("Retry-After", retryAfter)
			}
			w.WriteHeader(statuses[n])
			return
		}
		writeJSON(t, w, map[string]any{"cve": "CVE-2021-44228"})
	}))
	return srv, &calls
}

func TestRetry(t *testing.T) {
	for _, c := range []struct {
		name       string
		method     string
		statuses   []int
		retryAfter string
		wantErr    error
		wantCalls  int
	}{
		{"GET 500 retried once", http.MethodGet, []int{500}, "", nil, 2},
		{"GET 500 twice fails", http.MethodGet, []int{500, 500}, "", ErrInternalServerError, 2},
		{"POST 500 not retried", http.MethodPost, []int{500}, "", ErrInternalServerError, 1},
		{"POST 503 with Retry-After retried", http.MethodPost, []int{503}, "0", nil, 2},
		{"429 with short Retry-After retried", http.MethodGet, []int{429}, "0", nil, 2},
		{"429 without Retry-After not retried", http.MethodGet, []int{429}, "", ErrTooManyRequests, 1},
		{"429 with long Retry-After not retried", http.MethodGet, []int{429}, "120", ErrTooManyRequests, 1},
		{"404 not retried", http.MethodGet, []int{404}, "", ErrNotFound, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv, calls := statusServer(t, c.statuses, c.retryAfter)
			defer srv.Close()
			client := newTestClient(t, srv)
			var body any
			if c.method == http.MethodPost {
				body = map[string]string{"a": "b"}
			}
			req, err := client.newRequest(context.Background(), c.method, "/v1/x", nil, body)
			if err != nil {
				t.Fatal(err)
			}
			var out map[string]any
			err = client.do(req, &out)
			if c.wantErr == nil && err != nil || c.wantErr != nil && !errors.Is(err, c.wantErr) {
				t.Errorf("err = %v, want %v", err, c.wantErr)
			}
			if *calls != c.wantCalls {
				t.Errorf("calls = %d, want %d", *calls, c.wantCalls)
			}
		})
	}
}

func TestRetryWaitCancelled(t *testing.T) {
	srv, calls := statusServer(t, []int{503}, "30")
	defer srv.Close()
	c := newTestClient(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.GetVulnerabilityByID(ctx, "CVE-2021-44228", nil)
	if !errors.Is(err, ErrRequestFailed) || time.Since(start) > 5*time.Second {
		t.Errorf("cancelled wait: err %v after %s", err, time.Since(start))
	}
	if *calls != 1 {
		t.Errorf("calls = %d, want 1", *calls)
	}
}

// cveServer serves /v1/cves from total synthetic rows, pageSize at most per page, recording each query.
type cveServer struct {
	t         *testing.T
	total     int
	repeat    bool // answer every page with the same cursor
	mu        sync.Mutex
	queries   []url.Values
	products  []map[string]string
	notFounds map[string]bool
}

func (s *cveServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.queries = append(s.queries, r.URL.Query())
	s.mu.Unlock()
	q := r.URL.Query()
	switch {
	case r.URL.Path == "/v1/products":
		writeJSON(s.t, w, map[string]any{"items": s.products})
		return
	case strings.HasPrefix(r.URL.Path, "/v1/cves/"):
		id := strings.TrimPrefix(r.URL.Path, "/v1/cves/")
		if s.notFounds[id] {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSON(s.t, w, map[string]any{"cve": id})
		return
	}
	start, _ := strconv.Atoi(q.Get("cursor"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	var items []map[string]any
	for i := start; i < s.total && len(items) < limit; i++ {
		items = append(items, map[string]any{"cve": fmt.Sprintf("CVE-2024-%04d", i)})
	}
	next := ""
	if s.repeat {
		next = "7"
	} else if start+len(items) < s.total {
		next = strconv.Itoa(start + len(items))
	}
	writeJSON(s.t, w, map[string]any{"total": s.total, "items": items, "cursor": next})
}

func (s *cveServer) cveQueries() []url.Values {
	var out []url.Values
	for _, q := range s.queries {
		if q.Has("limit") && !q.Has("fields") {
			out = append(out, q)
		}
	}
	return out
}

func TestSearchPaging(t *testing.T) {
	ids := func(r SearchResponse) []string {
		var out []string
		for _, v := range r.Results {
			out = append(out, v.CVEID)
		}
		return out
	}
	for _, c := range []struct {
		name          string
		total         int
		limit, offset int
		all           bool
		wantFirst     string
		wantCount     int
		wantLimits    []string
	}{
		{"one page", 500, 10, 0, false, "CVE-2024-0000", 10, []string{"10"}},
		{"two pages", 500, 150, 0, false, "CVE-2024-0000", 150, []string{"100", "50"}},
		{"offset skips rows", 500, 5, 120, false, "CVE-2024-0120", 5, []string{"100", "25"}},
		{"short result", 3, 10, 0, false, "CVE-2024-0000", 3, []string{"10"}},
		{"all", 250, 10, 0, true, "CVE-2024-0000", 250, []string{"100", "100", "50"}},
		{"all with offset", 250, 10, 40, true, "CVE-2024-0040", 210, []string{"100", "100", "50"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := &cveServer{t: t, total: c.total}
			srv := httptest.NewServer(s)
			defer srv.Close()
			r, err := newTestClient(t, srv).SearchVulnerabilities(context.Background(),
				SearchParams{Limit: Ptr(c.limit), Offset: Ptr(c.offset), All: c.all})
			if err != nil {
				t.Fatal(err)
			}
			got := ids(r)
			if r.Count != c.wantCount || len(got) != c.wantCount || got[0] != c.wantFirst || r.Total != c.total {
				t.Errorf("count %d total %d first %v, want %d %d %s", r.Count, r.Total, got[:min(1, len(got))], c.wantCount, c.total, c.wantFirst)
			}
			var limits []string
			for _, q := range s.cveQueries() {
				limits = append(limits, q.Get("limit"))
			}
			if strings.Join(limits, ",") != strings.Join(c.wantLimits, ",") {
				t.Errorf("page limits %v, want %v", limits, c.wantLimits)
			}
		})
	}
}

func TestSearchRepeatedCursorStops(t *testing.T) {
	s := &cveServer{t: t, total: 1000, repeat: true}
	srv := httptest.NewServer(s)
	defer srv.Close()
	r, err := newTestClient(t, srv).SearchVulnerabilities(context.Background(), SearchParams{Limit: Ptr(500)})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(s.cveQueries()); n != 2 {
		t.Errorf("requests = %d, want 2 (stop when a cursor repeats)", n)
	}
	if r.Count != 200 {
		t.Errorf("count = %d, want 200", r.Count)
	}
}

func TestSearchWindowLimits(t *testing.T) {
	s := &cveServer{t: t, total: scMaxAll + 1}
	srv := httptest.NewServer(s)
	defer srv.Close()
	c := newTestClient(t, srv)
	if _, err := c.SearchVulnerabilities(context.Background(), SearchParams{Limit: Ptr(100), Offset: Ptr(MaxResultWindow - 99)}); !errors.Is(err, ErrUnsupportedQuery) {
		t.Errorf("offset + limit past the window: %v", err)
	}
	if len(s.queries) != 0 {
		t.Errorf("a rejected window still sent %d requests", len(s.queries))
	}
	if _, err := c.SearchVulnerabilities(context.Background(), SearchParams{Limit: Ptr(MaxResultWindow)}); err != nil {
		t.Errorf("limit at the window: %v", err)
	}
	_, err := c.SearchVulnerabilities(context.Background(), SearchParams{All: true})
	if !errors.Is(err, ErrUnsupportedQuery) || !strings.Contains(err.Error(), strconv.Itoa(scMaxAll)) {
		t.Errorf("--all past the cap: %v", err)
	}
}

func TestSearchCVEIDs(t *testing.T) {
	s := &cveServer{t: t, notFounds: map[string]bool{"CVE-2000-0001": true}}
	srv := httptest.NewServer(s)
	defer srv.Close()
	c := newTestClient(t, srv)
	q := "(cve_id:CVE-2021-44228 || cve_id:cve-2021-44228 || cve_id:CVE-2000-0001 || cve_id:CVE-2023-4966)"
	r, err := c.SearchVulnerabilities(context.Background(), SearchParams{Query: Ptr(q)})
	if err != nil {
		t.Fatal(err)
	}
	if r.Total != 3 || r.Count != 2 || r.Results[0].CVEID != "CVE-2021-44228" || r.Results[1].CVEID != "CVE-2023-4966" {
		t.Errorf("total %d count %d results %+v", r.Total, r.Count, r.Results)
	}
	if len(s.queries) != 3 {
		t.Errorf("requests = %d, want 3 (one per distinct id)", len(s.queries))
	}
	r, err = c.SearchVulnerabilities(context.Background(), SearchParams{Query: Ptr(q), Limit: Ptr(1), Offset: Ptr(1)})
	if err != nil || r.Count != 0 {
		t.Errorf("offset onto a missing id: %+v %v", r.Results, err)
	}
	if _, err := c.SearchVulnerabilities(context.Background(), SearchParams{Query: Ptr("cve_id:CVE-2021-44228 && severity:high")}); !errors.Is(err, ErrUnsupportedQuery) {
		t.Errorf("cve_id with another filter: %v", err)
	}
}

func TestSearchBareProduct(t *testing.T) {
	for _, c := range []struct {
		name     string
		products []map[string]string
		wantErr  error
		want     string
	}{
		{"one match", []map[string]string{{"product": "Apache:Log4j", "name": "log4j"}, {"product": "x:log4j-core", "name": "log4j-core"}}, nil, "apache:log4j"},
		{"several matches", []map[string]string{{"product": "a:log4j", "name": "log4j"}, {"product": "b:log4j", "name": "Log4j"}}, ErrUnsupportedQuery, ""},
		{"no match", []map[string]string{{"product": "x:log4j-core", "name": "log4j-core"}}, ErrNotFound, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := &cveServer{t: t, total: 1, products: c.products}
			srv := httptest.NewServer(s)
			defer srv.Close()
			_, err := newTestClient(t, srv).SearchVulnerabilities(context.Background(), SearchParams{Query: Ptr("product:log4j")})
			if c.wantErr != nil {
				if !errors.Is(err, c.wantErr) {
					t.Errorf("err = %v, want %v", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := s.queries[0].Get("q"); got != "log4j" {
				t.Errorf("products lookup q = %q", got)
			}
			if got := s.cveQueries()[0].Get("product"); got != c.want {
				t.Errorf("product = %q, want %q", got, c.want)
			}
		})
	}
}

func TestSearchRejectsBeforeRequest(t *testing.T) {
	s := &cveServer{t: t, total: 1}
	srv := httptest.NewServer(s)
	defer srv.Close()
	c := newTestClient(t, srv)
	for _, p := range []SearchParams{
		{Query: Ptr("h1.reports:>0")},
		{Query: Ptr("cvss_score:>7")},
		{SortDesc: Ptr("h1.reports")},
		{TermFacets: []string{"tags"}},
		{RangeFacets: []string{"cvss_score"}},
	} {
		if _, err := c.SearchVulnerabilities(context.Background(), p); !errors.Is(err, ErrUnsupportedQuery) {
			t.Errorf("%+v: %v", p, err)
		}
	}
	if len(s.queries) != 0 {
		t.Errorf("rejected searches sent %d requests", len(s.queries))
	}
}

func TestGetVulnerabilityByIDRejectsNonCVE(t *testing.T) {
	s := &cveServer{t: t}
	srv := httptest.NewServer(s)
	defer srv.Close()
	_, err := newTestClient(t, srv).GetVulnerabilityByID(context.Background(), "php-xdebug-rce", nil)
	if !errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "not a CVE id") {
		t.Errorf("template id: %v", err)
	}
	if len(s.queries) != 0 {
		t.Errorf("non-CVE id sent a request")
	}
}

func TestRetryAfter(t *testing.T) {
	for in, want := range map[string]time.Duration{"0": 500 * time.Millisecond, " 2 ": 2500 * time.Millisecond} {
		if got, ok := retryAfter(in); !ok || got != want {
			t.Errorf("%q: %s %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "-1", "Wed, 21 Oct 2015 07:28:00 GMT"} {
		if _, ok := retryAfter(in); ok {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestAPIErrorsDoNotAccumulate(t *testing.T) {
	msgs := []string{"invalid cursor", "unknown body field(s) ['functions']"}
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(t, w, map[string]string{"error": msgs[n%len(msgs)]})
		n++
	}))
	defer srv.Close()
	c := newTestClient(t, srv)
	sentinel := ErrBadRequest.Error()
	var errs []error
	for range msgs {
		_, err := c.GetVulnerabilityByID(context.Background(), "CVE-2021-44228", nil)
		errs = append(errs, err)
	}
	if strings.Contains(errs[1].Error(), msgs[0]) {
		t.Errorf("second error carries the first one's message: %v", errs[1])
	}
	if ErrBadRequest.Error() != sentinel {
		t.Errorf("sentinel modified: %q", ErrBadRequest.Error())
	}
	var apiErr *APIError
	if !errors.As(errs[1], &apiErr) || apiErr.StatusCode != http.StatusBadRequest || apiErr.Message != msgs[1] || !errors.Is(errs[1], ErrBadRequest) {
		t.Errorf("APIError not exposed: %#v", errs[1])
	}
	if _, err := translateQuery("cvss_score:>7"); err == nil || strings.Contains(err.Error(), msgs[0]) {
		t.Errorf("unsupported query error: %v", err)
	}
}

func TestUserAgent(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
		writeJSON(t, w, map[string]any{"cve": "CVE-2021-44228"})
	}))
	defer srv.Close()
	for _, c := range []struct {
		opts []Option
		want string
	}{
		// a test binary records no vulnx module version
		{nil, UserAgent},
		{[]Option{WithUserAgent("vulnx/2.0.2")}, "vulnx/2.0.2"},
		{[]Option{WithUserAgent("  ")}, UserAgent},
	} {
		if _, err := newTestClient(t, srv, c.opts...).GetVulnerabilityByID(context.Background(), "CVE-2021-44228", nil); err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("User-Agent = %q, want %q", got, c.want)
		}
	}
}
