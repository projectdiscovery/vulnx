// Package vulnx is a Go client for the SecurityContext CVE API
// (https://api.securitycontext.com). It translates vulnx's field:value query language into the API's
// parameters, handles authentication, retries and pagination, and returns vulnx's Vulnerability records.
//
// # Quick Start
//
//	ctx := context.Background()
//
//	client, err := vulnx.New() // reads SECURITYCONTEXT_API_KEY when set
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	out, err := client.SearchVulnerabilities(ctx, vulnx.SearchParams{
//	    Query: vulnx.Ptr("is_kev:true && severity:critical"),
//	    Limit: vulnx.Ptr(10),
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	fmt.Println(len(out.Results))
//
// # Rate Limiting
//
// Calls without an API key are rate limited per address. The client waits out a short 429 by itself;
// a longer one is returned as ErrTooManyRequests.
//
// The client is safe for concurrent use by multiple goroutines.
package vulnx

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	retryablehttp "github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/vulnx/v2/internal/termtext"
)

const (
	// DefaultBaseURL is the default base URL for the API (SecurityContext).
	DefaultBaseURL = "https://api.securitycontext.com"
	// UserAgent is the product token of the client's User-Agent; New adds the module version when the build
	// records one (vulnx/2.0.2). WithUserAgent replaces it.
	UserAgent  = "vulnx"
	modulePath = "github.com/projectdiscovery/vulnx/v2"
	// BaseURLEnvVar is the environment variable name for overriding the base URL.
	BaseURLEnvVar = "VULNX_API_URL"
	// APIKeyEnvVar holds the SecurityContext API key New uses when no option sets one. Without a key, calls
	// are anonymous and rate limited per address.
	APIKeyEnvVar = "SECURITYCONTEXT_API_KEY"
	// MaxResultWindow is the deepest offset + limit a search reaches without SearchParams.All.
	MaxResultWindow = scMaxWindow

	apiKeyHeader = "X-Api-Key"
	// maxRateLimitWait bounds how long the client waits on a Retry-After before giving up.
	maxRateLimitWait  = 65 * time.Second
	maxResponseBytes  = 64 << 20
	maxErrorBodyBytes = 64 << 10
	maxErrorMessage   = 500
)

// Client errors
var (
	ErrBadRequest          = errors.New("bad request: client sent an invalid request")
	ErrUnauthorized        = errors.New("unauthorized: invalid or missing API key")
	ErrNotFound            = errors.New("not found: resource does not exist")
	ErrTooManyRequests     = errors.New("too many requests: SecurityContext allows anonymous callers a limited number of requests a minute per address")
	ErrInternalServerError = errors.New("internal server error: something went wrong on the server")
	ErrUnknownAPIError     = errors.New("unknown api error")

	ErrRequestBuildFailure = errors.New("failed to build request")
	ErrRequestFailed       = errors.New("request failed")
	ErrMarshalBody         = errors.New("failed to marshal request body")
	ErrCreateHTTPRequest   = errors.New("failed to create http request")
	ErrDecodeResponse      = errors.New("failed to decode response")
)

// Option represents a functional option that mutates a *Client* during
// construction.
//
//	client, err := vulnx.New(
//	    vulnx.WithAPIKey("<YOUR_KEY>"),
//	    vulnx.WithRetryableHTTPOptions(retryablehttp.Options{RetryMax: 5}),
//	)
type Option func(*Client)

// Client provides high-level helpers around the SecurityContext API. It is safe for
// concurrent use. Zero values for *Client* fields are not meaningful—always use
// the *New* constructor.
type Client struct {
	baseURL   string
	apiKey    string
	httpc     *retryablehttp.Client
	http      *http.Client
	userAgent string
	retryWait time.Duration
	keyWarn   sync.Once
	// Optional debug hooks
	debugRequest  func(*http.Request)
	debugResponse func(*http.Response)
}

// New returns a new *Client* configured by the supplied *Option*s. An API key set by an option wins;
// otherwise the SECURITYCONTEXT_API_KEY environment variable is used, and without either calls are anonymous.
// The key is sent only over https or to a loopback host, and never follows a redirect to another host.
//
// Custom HTTP behaviour (timeouts, proxies) can be injected via *WithClient* or *WithRetryableHTTPOptions*.
func New(opts ...Option) (*Client, error) {
	c := &Client{
		baseURL:   cmp.Or(os.Getenv(BaseURLEnvVar), DefaultBaseURL),
		userAgent: defaultUserAgent(),
		httpc:     retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle),
		retryWait: time.Second,
	}
	for _, opt := range opts {
		opt(c)
	}
	c.apiKey = cmp.Or(strings.TrimSpace(c.apiKey), strings.TrimSpace(os.Getenv(APIKeyEnvVar)))
	// a copy, so the redirect policy does not change a client the caller passed in
	hc := http.Client{}
	if c.httpc.HTTPClient != nil {
		hc = *c.httpc.HTTPClient
	}
	hc.CheckRedirect = keyRedirectPolicy(hc.CheckRedirect)
	c.http = &hc
	return c, nil
}

// WithClient overrides the default *retryablehttp.Client*; its HTTPClient carries the transport, proxy and
// timeout settings.
func WithClient(hc *retryablehttp.Client) Option {
	return func(c *Client) {
		c.httpc = hc
	}
}

// WithUserAgent sets the User-Agent sent with every request; an empty value keeps the default.
func WithUserAgent(ua string) Option {
	ua = strings.TrimSpace(ua)
	return func(c *Client) {
		if ua != "" {
			c.userAgent = ua
		}
	}
}

// defaultUserAgent is "vulnx/<version>" with the vulnx module's version from the build info, or "vulnx" when the
// build records none (go run, tests, a local checkout).
func defaultUserAgent() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return UserAgent
	}
	mods := append([]*debug.Module{&info.Main}, info.Deps...)
	for _, m := range mods {
		if m.Path == modulePath && m.Version != "" && m.Version != "(devel)" {
			return UserAgent + "/" + strings.TrimPrefix(m.Version, "v")
		}
	}
	return UserAgent
}

// WithAPIKey sets the SecurityContext API key sent in the X-Api-Key header.
func WithAPIKey(apiKey string) Option {
	return func(c *Client) {
		c.apiKey = apiKey
	}
}

// WithPDCPKey sets the API key sent in the X-Api-Key header.
//
// Deprecated: the backend is SecurityContext, which accepts only SecurityContext keys; use WithAPIKey.
func WithPDCPKey(apiKey string) Option {
	return WithAPIKey(apiKey)
}

// WithKeyFromEnv reads the API key from the SECURITYCONTEXT_API_KEY environment variable.
//
// Deprecated: New reads SECURITYCONTEXT_API_KEY itself when no option sets a key.
func WithKeyFromEnv() Option {
	return func(c *Client) {
		c.apiKey = os.Getenv(APIKeyEnvVar)
	}
}

// WithBaseURL points the client at an alternative endpoint—useful for testing
// against staging or mock servers.
func WithBaseURL(url string) Option {
	return func(c *Client) {
		c.baseURL = url
	}
}

// WithRetryableHTTPOptions constructs a fresh *retryablehttp.Client* with the
// supplied options and wires it into the *Client* instance.
func WithRetryableHTTPOptions(clientOpts retryablehttp.Options) Option {
	return func(c *Client) {
		c.httpc = retryablehttp.NewClient(clientOpts)
	}
}

// WithDebugRequest sets a callback that is invoked with the *http.Request before it is sent.
func WithDebugRequest(cb func(*http.Request)) Option {
	return func(c *Client) {
		c.debugRequest = cb
	}
}

// WithDebugResponse sets a callback that is invoked with the *http.Response after it is received (before decoding).
func WithDebugResponse(cb func(*http.Response)) Option {
	return func(c *Client) {
		c.debugResponse = cb
	}
}

// SearchVulnerabilities searches CVEs with vulnx's field:value query language (see SupportedFilters) and returns
// one page of results, or every result with SearchParams.All. A query SecurityContext cannot answer is rejected
// with ErrUnsupportedQuery. It is safe to call concurrently.
func (c *Client) SearchVulnerabilities(ctx context.Context, params SearchParams) (SearchResponse, error) {
	var resp SearchResponse
	resp.fields = params.Fields
	q := ""
	if params.Query != nil {
		q = *params.Query
	}
	tq, err := translateQuery(q)
	if err != nil {
		return resp, err
	}
	if tq.productName != "" {
		key, err := c.resolveProduct(ctx, tq.productName)
		if err != nil {
			return resp, err
		}
		if err := setParam(tq, "product", "product", key); err != nil {
			return resp, err
		}
	}
	facetSize := 0
	if params.FacetSize != nil {
		facetSize = *params.FacetSize
	}
	facetReqs, facets, err := translateFacets(params.TermFacets, params.RangeFacets, facetSize)
	if err != nil {
		return resp, err
	}
	sortKey, err := sortParam(params.SortAsc, params.SortDesc)
	if err != nil {
		return resp, err
	}
	limit, offset := 10, 0
	if params.Limit != nil {
		limit = *params.Limit
	}
	if params.Offset != nil {
		offset = *params.Offset
	}
	if offset < 0 || limit < 0 {
		return resp, unsupported("offset and limit must not be negative")
	}
	// compared without adding, so a huge offset cannot wrap around
	if !params.All && (offset > MaxResultWindow || limit > MaxResultWindow-offset) {
		return resp, unsupported("offset + limit can be at most %d (SecurityContext pages by cursor, %d rows a request); set All (vulnx search --all) to fetch every result", MaxResultWindow, scMaxPage)
	}

	if tq.cpe != nil {
		if strings.Contains(tq.params.Get("exploit"), "ransomware") {
			return resp, unsupported("is_ransomware cannot be combined with cpe:")
		}
		if sortKey != "" && !strings.HasPrefix(sortKey, "cvss_score") && !strings.HasPrefix(sortKey, "epss_score") &&
			!strings.HasPrefix(sortKey, "published_date") && !strings.HasPrefix(sortKey, "modified_date") {
			return resp, unsupported("with cpe:, sort by cve_created_at, cve_updated_at, cvss_score or epss_score")
		}
		r, err := c.searchCPE(ctx, tq, sortKey, len(facetReqs) > 0, limit, offset, params.All, params.Progress)
		r.fields = params.Fields
		return r, err
	}

	if tq.idsSet {
		if len(facetReqs) > 0 {
			return resp, unsupported("facets are not available with cve_id: (each id is fetched as one record)")
		}
		if sortKey != "" {
			return resp, unsupported("cve_id: lookups return the records in the order given; sorting is not available")
		}
		if params.All {
			limit = len(tq.ids)
		}
		return c.lookupIDs(ctx, tq, limit, offset, params.Fields, params.Progress)
	}

	query := tq.params
	query.Set("sort", cmp.Or(sortKey, defaultSort))
	if facets != "" {
		query.Set("facets", facets)
	}
	want := max(offset+limit, 1) // a facet-only request still needs one row
	if params.All {
		want = scMaxPage // the first page tells the total; offset is not added, so it cannot overflow
	}
	skipped, consumed := 0, 0
	cursor := ""
	seen := map[string]bool{}
	for page := 0; ; page++ {
		query.Set("limit", strconv.Itoa(min(want-consumed, scMaxPage)))
		if cursor != "" {
			query.Set("cursor", cursor)
			query.Del("facets") // counted on the first page
		}
		var list scList
		req, err := c.newRequest(ctx, http.MethodGet, "/v1/cves", query, nil)
		if err != nil {
			return resp, wrapErr(ErrRequestBuildFailure, err)
		}
		if err := c.do(req, &list); err != nil {
			return resp, err
		}
		if page == 0 {
			resp.Total = list.Total
			resp.Facets = buildFacets(facetReqs, list.Facets, list.Total)
			if params.All {
				if list.Total > scMaxAll {
					return resp, unsupported("the search matches %d CVEs; --all fetches at most %d: narrow the query", list.Total, scMaxAll)
				}
				limit, want = max(list.Total-offset, 0), list.Total
			}
		}
		pageRows := len(list.Items)
		for i := range list.Items {
			consumed++
			if skipped < offset {
				skipped++
				continue
			}
			if len(resp.Results) < limit {
				resp.Results = append(resp.Results, list.Items[i].toVulnerability())
			}
		}
		if params.Progress != nil {
			params.Progress(len(resp.Results), resp.Total)
		}
		// a cursor already used means the next page would repeat rows, so these rows cannot be trusted as a result
		if list.Cursor != "" && seen[list.Cursor] {
			return resp, incomplete("the server repeated a page cursor", len(resp.Results), min(limit, max(resp.Total-offset, 0)))
		}
		if consumed >= want {
			break
		}
		if list.Cursor == "" || pageRows == 0 {
			// the reported total says more rows exist than paging returned
			if consumed < min(want, resp.Total) {
				return resp, incomplete("paging ended early", len(resp.Results), min(limit, max(resp.Total-offset, 0)))
			}
			break
		}
		seen[list.Cursor] = true
		cursor = list.Cursor
	}
	resp.Count = len(resp.Results)
	return resp, nil
}

// defaultSort is the order of a search that sets no sort: newest first.
const defaultSort = "published_date:desc"

// incomplete reports a paged search that stopped before returning the rows it needed. The rows fetched so far are
// in the response, but they are not the full result.
func incomplete(why string, got, want int) error {
	return wrapErr(ErrUnknownAPIError, fmt.Errorf("%s after %d of %d results; the index may have changed during the search, retry", why, got, want))
}

// lookupIDs fetches cve_id: terms one record at a time; Total counts the distinct ids asked for, found or not.
func (c *Client) lookupIDs(ctx context.Context, tq *scQuery, limit, offset int, fields []string, progress func(int, int)) (SearchResponse, error) {
	resp := SearchResponse{fields: fields}
	if len(tq.params) > 0 {
		return resp, unsupported("cve_id: cannot be combined with other filters")
	}
	ids := tq.ids
	resp.Total = len(ids)
	// offset and limit page through the ids asked for, so a missing id leaves its page short
	start := min(offset, len(ids))
	for _, id := range ids[start : start+min(limit, len(ids)-start)] {
		one, err := c.GetVulnerabilityByID(ctx, id, nil)
		switch {
		case errors.Is(err, ErrNotFound):
		case err != nil:
			return resp, err
		default:
			resp.Results = append(resp.Results, *one.Data)
		}
		if progress != nil {
			progress(len(resp.Results), resp.Total)
		}
	}
	resp.Count = len(resp.Results)
	return resp, nil
}

// resolveProduct finds the NVD vendor:product for a product name given without its vendor.
func (c *Client) resolveProduct(ctx context.Context, name string) (string, error) {
	req, err := c.newRequest(ctx, http.MethodGet, "/v1/products", url.Values{"q": {name}, "limit": {strconv.Itoa(scMaxPage)}, "fields": {"product,name"}}, nil)
	if err != nil {
		return "", wrapErr(ErrRequestBuildFailure, err)
	}
	var list struct {
		Items []struct {
			Product string `json:"product"`
			Name    string `json:"name"`
		} `json:"items"`
	}
	if err := c.do(req, &list); err != nil {
		return "", err
	}
	var keys []string
	for _, it := range list.Items {
		if strings.EqualFold(it.Name, name) {
			keys = append(keys, strings.ToLower(it.Product))
		}
	}
	switch len(keys) {
	case 0:
		return "", wrapErr(ErrNotFound, fmt.Errorf("NVD has no product named %s; give the product as vendor:product, or filter by vendor", termtext.Clean(name)))
	case 1:
		return keys[0], nil
	}
	return "", unsupported("several NVD products are named %s (%s); give one as vendor:product", name, termtext.Clean(strings.Join(keys, ", ")))
}

// GetVulnerabilityByID fetches a single CVE record (for example "CVE-2023-1234").
// *params* is accepted for compatibility; SecurityContext returns the whole record.
func (c *Client) GetVulnerabilityByID(ctx context.Context, id string, params *GetByIDParams) (VulnerabilityResponse, error) {
	var resp VulnerabilityResponse
	id = strings.TrimSpace(id)
	if !IsCVEID(id) {
		return resp, wrapErr(ErrNotFound, fmt.Errorf("%s is not a CVE id; only CVE records are supported", id))
	}
	var rec scCVE
	req, err := c.newRequest(ctx, http.MethodGet, "/v1/cves/"+url.PathEscape(strings.ToUpper(id)), nil, nil)
	if err != nil {
		return resp, wrapErr(ErrRequestBuildFailure, err)
	}
	if err := c.do(req, &rec); err != nil {
		return resp, err
	}
	v := rec.toVulnerability()
	resp.Data = &v
	return resp, nil
}

// GetVulnerabilityFilters lists the query fields the SecurityContext backend
// accepts. The list is built into vulnx: the API has no filters endpoint.
func (c *Client) GetVulnerabilityFilters(ctx context.Context) ([]VulnerabilityFilter, error) {
	return SupportedFilters(), nil
}

// IsAuthenticated returns true if the client has an API key configured.
func (c *Client) IsAuthenticated() bool {
	return c.apiKey != ""
}

// newRequest builds an HTTP request with authentication and query params.
func (c *Client) newRequest(ctx context.Context, method, path string, query url.Values, body any) (*http.Request, error) {
	requestURL := c.baseURL + path
	if len(query) > 0 {
		requestURL += "?" + query.Encode()
	}
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, wrapErr(ErrMarshalBody, err)
		}
		reader = strings.NewReader(string(b))
	}
	req, err := http.NewRequestWithContext(ctx, method, requestURL, reader)
	if err != nil {
		return nil, wrapErr(ErrCreateHTTPRequest, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c.setHeaders(req)
	return req, nil
}

// setHeaders sets the User-Agent and, when the URL allows it, the API key.
func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("User-Agent", c.userAgent)
	if c.apiKey == "" {
		return
	}
	if keySafeURL(req.URL) {
		req.Header.Set(apiKeyHeader, c.apiKey)
		return
	}
	c.keyWarn.Do(func() {
		gologger.Error().Msgf("the API key is not sent to %s: a key goes only over https or to a loopback host", req.URL.Host)
	})
}

// keySafeURL reports whether an API key may be sent to u: over https, or to a loopback host.
func keySafeURL(u *url.URL) bool {
	if u.Scheme == "https" {
		return true
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// keyRedirectPolicy drops the API key from a redirect that leaves the original host or would send it in the clear.
// net/http copies custom headers to every redirect hop, unlike Authorization.
func keyRedirectPolicy(next func(*http.Request, []*http.Request) error) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if !strings.EqualFold(req.URL.Host, via[0].URL.Host) || !keySafeURL(req.URL) {
			req.Header.Del(apiKeyHeader)
		}
		if next != nil {
			return next(req, via)
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
}

// do executes the HTTP request and decodes the JSON response, retrying once when retryDelay allows it.
func (c *Client) do(req *http.Request, out any) error {
	resp, err := c.send(req)
	if wait, ok := c.retryDelay(req, resp, err); ok {
		reason := "request failed"
		if resp != nil {
			reason = resp.Status
			c.discard(resp)
		}
		gologger.Info().Msgf("SecurityContext: %s; retrying in %s", reason, wait.Round(100*time.Millisecond))
		timer := time.NewTimer(wait)
		select {
		case <-req.Context().Done():
			timer.Stop()
			return wrapErr(ErrRequestFailed, req.Context().Err())
		case <-timer.C:
		}
		retry := req.Clone(req.Context())
		if req.GetBody != nil {
			if retry.Body, err = req.GetBody(); err != nil {
				return wrapErr(ErrRequestFailed, err)
			}
		}
		resp, err = c.send(retry)
	}
	if err != nil {
		return wrapErr(ErrRequestFailed, err)
	}
	if c.debugResponse != nil {
		c.debugResponse(resp)
	}
	defer c.discard(resp)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return c.handleAPIError(resp)
	}
	if out == nil {
		return nil
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return wrapErr(ErrRequestFailed, err)
	}
	if len(b) > maxResponseBytes {
		return wrapErr(ErrDecodeResponse, fmt.Errorf("response is larger than %d MiB", maxResponseBytes>>20))
	}
	if err := json.Unmarshal(b, out); err != nil {
		return wrapErr(ErrDecodeResponse, err)
	}
	return nil
}

func (c *Client) send(req *http.Request) (*http.Response, error) {
	if c.debugRequest != nil {
		c.debugRequest(req)
	}
	return c.http.Do(req)
}

func (c *Client) discard(resp *http.Response) {
	if err := resp.Body.Close(); err != nil {
		gologger.Debug().Msgf("closing response body: %s", err)
	}
}

// retryDelay decides whether a failed attempt is retried and after how long: a 429 or 503 (the server did not
// act on the request) with a Retry-After of at most maxRateLimitWait, and, for GET and HEAD only, a network
// error, another 5xx, or a 503 without a usable Retry-After. A POST that may have reached the server is not
// sent twice.
func (c *Client) retryDelay(req *http.Request, resp *http.Response, err error) (time.Duration, bool) {
	if req.Context().Err() != nil {
		return 0, false
	}
	idempotent := req.Method == http.MethodGet || req.Method == http.MethodHead
	if err != nil {
		// a response with an error is a redirect the redirect policy refused, not a network failure
		return c.retryWait, idempotent && resp == nil
	}
	if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusServiceUnavailable &&
		(!idempotent || resp.StatusCode < 500) {
		return 0, false
	}
	if wait, ok := retryAfter(resp.Header.Get("Retry-After"), time.Now()); ok {
		return wait, wait <= maxRateLimitWait
	}
	// a 429 without Retry-After says nothing about when to come back
	return c.retryWait, idempotent && resp.StatusCode != http.StatusTooManyRequests
}

// handleAPIError turns a non-2xx response into an error carrying the server's message, cleaned for a terminal.
func (c *Client) handleAPIError(resp *http.Response) error {
	kind := ErrUnknownAPIError
	switch resp.StatusCode {
	case http.StatusNotFound:
		kind = ErrNotFound
	case http.StatusBadRequest:
		kind = ErrBadRequest
	case http.StatusUnauthorized:
		kind = ErrUnauthorized
	case http.StatusTooManyRequests:
		kind = ErrTooManyRequests
	case http.StatusInternalServerError:
		kind = ErrInternalServerError
	}
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
	if err != nil {
		return &APIError{StatusCode: resp.StatusCode, Message: "could not read the response body: " + err.Error(), kind: kind}
	}
	msg := strings.TrimSpace(string(bodyBytes))
	var errorBody map[string]any
	if json.Unmarshal(bodyBytes, &errorBody) == nil {
		for _, key := range []string{"error", "msg", "message", "cause"} {
			if v, ok := errorBody[key]; ok {
				msg = fmt.Sprint(v)
				break
			}
		}
	}
	msg = termtext.Clean(msg)
	if r := []rune(msg); len(r) > maxErrorMessage {
		msg = string(r[:maxErrorMessage]) + "..."
	}
	return &APIError{StatusCode: resp.StatusCode, Message: msg, kind: kind}
}

// APIError is a non-2xx answer from the API. errors.Is matches it against the sentinel for its status
// (ErrBadRequest, ErrUnauthorized, ...); Message is the server's message, cleaned for a terminal.
type APIError struct {
	StatusCode int
	Message    string
	kind       error
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%s (HTTP %d): %s", e.kind, e.StatusCode, e.Message)
}

func (e *APIError) Unwrap() error { return e.kind }

// wrapErr returns an error that matches sentinel and cause under errors.Is. It never modifies sentinel:
// errkit.Append adds the cause to the package-level sentinel itself, so its text would accumulate every
// earlier error in the process.
func wrapErr(sentinel, cause error) error {
	return fmt.Errorf("%w: %w", sentinel, cause)
}

// retryAfter reads a Retry-After header, in seconds or as an HTTP date, as a wait from now. A wait past
// maxRateLimitWait is reported as just over it, so a huge value cannot overflow into a short wait.
func retryAfter(h string, now time.Time) (time.Duration, bool) {
	h = strings.TrimSpace(h)
	if h != "" && strings.Trim(h, "0123456789") == "" {
		// all digits: a delay in seconds, however long (one too big for int64 is still over the cap)
		n, err := strconv.ParseInt(h, 10, 64)
		if err != nil || n > int64(maxRateLimitWait/time.Second) {
			return maxRateLimitWait + time.Second, true
		}
		return time.Duration(n)*time.Second + 500*time.Millisecond, true
	}
	t, err := http.ParseTime(h)
	if err != nil {
		return 0, false
	}
	return min(max(t.Sub(now), 0), maxRateLimitWait+time.Second) + 500*time.Millisecond, true
}
