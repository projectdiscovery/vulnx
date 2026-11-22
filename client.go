// Package vulnx provides a robust, idiomatic Go client for interacting
// with the ProjectDiscovery vulnx REST API. The client focuses on
// the "/v2/vulnerability" endpoints, exposing high-level helper methods that
// handle authentication, request construction, network-level retries, and JSON
// decoding so that callers can concentrate on business logic.
//
// # Quick Start
//
// The snippet below demonstrates a minimal, production-ready workflow. While
// authentication is optional, using an API key is strongly recommended to
// avoid rate limiting and ensure better performance:
//
//	ctx := context.Background()
//
//	client, err := vulnx.New(
//	    vulnx.WithKeyFromEnv(), // or vulnx.WithPDCPKey("<YOUR_KEY>")
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	out, err := client.SearchVulnerabilities(ctx, vulnx.SearchParams{
//	    Query: vulnx.Ptr("id:CVE-2023-4799"),
//	    Limit: vulnx.Ptr(10),
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	fmt.Println(len(out.Vulnerabilities))
//
// # Rate Limiting
//
// Unauthenticated requests are subject to strict rate limits. If you encounter
// 429 (Too Many Requests) errors, configure an API key using WithPDCPKey() or
// WithKeyFromEnv() to get higher rate limits and better service reliability.
//
// The client is safe for concurrent use by multiple goroutines.
//
// For complete API semantics refer to https://api.projectdiscovery.io/docs.
package vulnx

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	retryablehttp "github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/utils/auth/pdcp"
	"github.com/projectdiscovery/utils/errkit"
)

const (
	// DefaultBaseURL is the default base URL for the API (SecurityContext).
	DefaultBaseURL = "https://api.securitycontext.com"
	// UserAgent is the default user agent for the client.
	UserAgent = "vulnx-client/2.0"
	// BaseURLEnvVar is the environment variable name for overriding the base URL.
	BaseURLEnvVar = "VULNX_API_URL"
	// APIKeyEnvVar holds a SecurityContext API key. SecurityContext rejects any key it does not know (401), so a
	// PDCP key is never sent to it; without a key, calls are anonymous and rate limited per address.
	APIKeyEnvVar = "SECURITYCONTEXT_API_KEY"
	// maxRateLimitWait bounds how long the client waits on a 429's Retry-After before giving up.
	maxRateLimitWait = 65 * time.Second
)

// Client errors
var (
	ErrBadRequest          = errkit.New("bad request: client sent an invalid request")
	ErrUnauthorized        = errkit.New("unauthorized: invalid or missing API key")
	ErrNotFound            = errkit.New("not found: resource does not exist")
	ErrTooManyRequests     = errkit.New("too many requests: SecurityContext allows anonymous callers a limited number of requests a minute per address")
	ErrInternalServerError = errkit.New("internal server error: something went wrong on the server")
	ErrUnknownAPIError     = errkit.New("unknown api error")

	ErrRequestBuildFailure = errkit.New("failed to build request")
	ErrRequestFailed       = errkit.New("request failed")
	ErrMarshalBody         = errkit.New("failed to marshal request body")
	ErrCreateHTTPRequest   = errkit.New("failed to create http request")
	ErrDecodeResponse      = errkit.New("failed to decode response")
)

// Option represents a functional option that mutates a *Client* during
// construction. It follows the standard "functional options" pattern popularised
// by Google and is the preferred way to add optional parameters without an
// explosion of constructor variants.
//
// A typical call site looks like this:
//
//	client, err := vulnx.New(
//	    vulnx.WithPDCPKey("<YOUR_KEY>"),
//	    vulnx.WithRetryableHTTPOptions(retryablehttp.Options{RetryMax: 5}),
//	)
//	if err != nil {
//	    // handle error
//	}
type Option func(*Client)

// Client provides high-level helpers around the vulnx API. It is safe for
// concurrent use. Zero values for *Client* fields are not meaningful—always use
// the *New* constructor.
type Client struct {
	baseURL   string
	apiKey    string
	httpc     *retryablehttp.Client
	userAgent string
	// Optional debug hooks
	debugRequest  func(*http.Request)
	debugResponse func(*http.Response)
}

// New returns a new *Client* configured by the supplied *Option*s. Authentication
// is optional but strongly recommended - unauthenticated requests are subject
// to strict rate limits. Use *WithPDCPKey* or *WithKeyFromEnv* to configure
// an API key for better performance and higher rate limits.
//
// The returned client is ready for immediate use:
//
//	c, err := vulnx.New(vulnx.WithPDCPKey("<YOUR_KEY>"))
//	if err != nil { /* handle */ }
//
//	// Or without authentication (subject to rate limits):
//	c, err := vulnx.New()
//	if err != nil { /* handle */ }
//
// Custom HTTP behaviour (timeouts, retries, logging) can be injected via
// *WithClient* or *WithRetryableHTTPOptions*.
func New(opts ...Option) (*Client, error) {
	// Check for base URL override from environment
	baseURL := DefaultBaseURL
	if envURL := os.Getenv(BaseURLEnvVar); envURL != "" {
		baseURL = envURL
	}

	c := &Client{
		baseURL:   baseURL,
		userAgent: UserAgent,
		httpc:     retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle), // Default retryablehttp client
	}
	for _, opt := range opts {
		opt(c)
	}
	// PDCP keys belong to template-service; SecurityContext answers 401 to them. Only a SecurityContext key is sent.
	c.apiKey = strings.TrimSpace(os.Getenv(APIKeyEnvVar))
	// API key is now optional - authentication is not required but recommended
	// If a custom httpc was not provided, set the default retryablehttp client
	if c.httpc == nil {
		c.httpc = retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)
	}
	return c, nil
}

// WithClient overrides the default *retryablehttp.Client* used for all network
// operations. It enables advanced users to specify custom transports, proxy
// settings, or instrumentation hooks.
func WithClient(hc *retryablehttp.Client) Option {
	return func(c *Client) {
		c.httpc = hc
	}
}

// WithPDCPKey sets the ProjectDiscovery Cloud Platform (PDCP) API key that will
// be sent in the `X-Api-Key` HTTP header.
func WithPDCPKey(apiKey string) Option {
	return func(c *Client) {
		c.apiKey = apiKey
	}
}

// WithKeyFromEnv attempts to discover a PDCP API key from the local credential
// store (managed by `pdcp`) or the `PDCP_API_KEY` environment variable.
func WithKeyFromEnv() Option {
	return func(c *Client) {
		pch := pdcp.PDCPCredHandler{}
		if creds, err := pch.GetCreds(); err == nil {
			c.apiKey = creds.APIKey
			return
		}
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

// SearchVulnerabilities performs a full-text search across all vulnerability
// documents and returns a paginated *SearchResponse*.
//
// The behaviour of the search is controlled via *SearchParams*; see that type
// for field-level documentation.
//
// SearchVulnerabilities may contact the network multiple times if retries are
// enabled on the underlying HTTP client. It is safe to call concurrently.
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

	// cpe: a product version's CVEs (issue #77)
	if tq.cpe != nil {
		if strings.Contains(tq.params.Get("exploit"), "ransomware") {
			return resp, unsupported("is_ransomware cannot be combined with cpe:")
		}
		if sortKey != "" && !strings.HasPrefix(sortKey, "cvss_score") && !strings.HasPrefix(sortKey, "epss_score") &&
			!strings.HasPrefix(sortKey, "published_date") && !strings.HasPrefix(sortKey, "modified_date") {
			return resp, unsupported("with cpe:, sort by cve_created_at, cve_updated_at, cvss_score or epss_score")
		}
		r, err := c.searchCPE(ctx, tq, sortKey, len(facetReqs) > 0, limit, offset, params.All)
		r.fields = params.Fields
		return r, err
	}

	// cve_id: terms are a direct lookup (one request per id); other filters can't be combined with them
	if len(tq.ids) > 0 {
		if len(tq.params) > 0 {
			return resp, unsupported("cve_id: cannot be combined with other filters")
		}
		for i, id := range tq.ids {
			if i < offset {
				continue
			}
			if len(resp.Results) >= limit {
				break
			}
			one, err := c.GetVulnerabilityByID(ctx, id, nil)
			if errkit.Is(err, ErrNotFound) {
				continue
			}
			if err != nil {
				return resp, err
			}
			resp.Results = append(resp.Results, *one.Data)
		}
		resp.Count, resp.Total = len(resp.Results), len(resp.Results)
		return resp, nil
	}

	if !params.All && offset+limit > scMaxWindow {
		return resp, unsupported("offset + limit can be at most %d (SecurityContext pages by cursor, %d rows a request)", scMaxWindow, scMaxPage)
	}
	query := tq.params
	if sortKey != "" {
		query.Set("sort", sortKey)
	}
	if facets != "" {
		query.Set("facets", facets)
	}
	want := offset + limit
	if want < 1 {
		want = 1 // a facet-only request still needs one row
	}
	if params.All {
		want = offset + scMaxPage // the first page tells the total
	}
	skipped, consumed := 0, 0
	cursor := ""
	for page := 0; ; page++ {
		pageSize := want - consumed
		if pageSize > scMaxPage {
			pageSize = scMaxPage
		}
		query.Set("limit", strconv.Itoa(pageSize))
		if cursor != "" {
			query.Set("cursor", cursor)
			query.Del("facets") // counted on the first page
		}
		var list scList
		req, err := c.newRequest(ctx, http.MethodGet, "/v1/cves", query, nil)
		if err != nil {
			return resp, errkit.Append(ErrRequestBuildFailure, err)
		}
		if err := c.do(req, &list); err != nil {
			return resp, errkit.Append(ErrRequestFailed, err)
		}
		if page == 0 {
			resp.Total = list.Total
			resp.Facets = buildFacets(facetReqs, list.Facets, list.Total)
			if params.All {
				limit, want = list.Total, offset+list.Total
			}
		}
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
		if list.Cursor == "" || len(list.Items) == 0 || consumed >= want {
			break
		}
		cursor = list.Cursor
	}
	resp.Count = len(resp.Results)
	return resp, nil
}

// GetVulnerabilityByID fetches a single vulnerability document identified by
// its canonical ID (for example "CVE-2023-1234").
//
// When *params* is non-nil the *Fields* slice can be used to limit the response
// payload to a subset of fields, reducing bandwidth.
func (c *Client) GetVulnerabilityByID(ctx context.Context, id string, params *GetByIDParams) (VulnerabilityResponse, error) {
	var resp VulnerabilityResponse
	id = strings.TrimSpace(id)
	if !IsCVEID(id) {
		// template-service also served nuclei template records with no CVE; SecurityContext serves CVEs only
		return resp, errkit.Append(ErrNotFound, fmt.Errorf("%s is not a CVE id: only CVE records are served", id))
	}
	var rec scCVE
	req, err := c.newRequest(ctx, http.MethodGet, "/v1/cves/"+url.PathEscape(strings.ToUpper(id)), nil, nil)
	if err != nil {
		return resp, errkit.Append(ErrRequestBuildFailure, err)
	}
	err = c.do(req, &rec)
	if err != nil {
		return resp, errkit.Append(ErrRequestFailed, err)
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
// This can be used to provide better UX messaging about rate limits.
func (c *Client) IsAuthenticated() bool {
	return c.apiKey != ""
}

// newRequest builds an HTTP request with authentication and query params.
func (c *Client) newRequest(ctx context.Context, method, path string, query url.Values, body any) (*http.Request, error) {
	requestURL := c.baseURL + path
	if len(query) > 0 {
		requestURL += "?" + query.Encode()
	}
	var req *http.Request
	var err error
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, errkit.Append(ErrMarshalBody, err)
		}
		req, err = http.NewRequestWithContext(ctx, method, requestURL, strings.NewReader(string(b)))
		if err != nil {
			return nil, errkit.Append(ErrCreateHTTPRequest, err)
		}
		req.Header.Set("Content-Type", "application/json")
	} else {
		req, err = http.NewRequestWithContext(ctx, method, requestURL, nil)
		if err != nil {
			return nil, errkit.Append(ErrCreateHTTPRequest, err)
		}
	}
	// Only set API key header if one is provided
	if c.apiKey != "" {
		req.Header.Set("X-Api-Key", c.apiKey)
	}
	req.Header.Set("User-Agent", c.userAgent)
	return req, nil
}

// do executes the HTTP request and decodes the JSON response. A 429 with a
// Retry-After of at most maxRateLimitWait is waited out and retried once.
func (c *Client) do(req *http.Request, out any) error {
	if c.debugRequest != nil {
		c.debugRequest(req)
	}
	resp, err := c.httpc.HTTPClient.Do(req)
	if err != nil {
		return errkit.Append(ErrRequestFailed, err)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		if wait, ok := retryAfter(resp.Header.Get("Retry-After")); ok && wait <= maxRateLimitWait {
			_ = resp.Body.Close()
			gologger.Warning().Msgf("rate limited by SecurityContext; retrying in %s", wait.Round(time.Second))
			select {
			case <-req.Context().Done():
				return errkit.Append(ErrRequestFailed, req.Context().Err())
			case <-time.After(wait):
			}
			retry := req.Clone(req.Context())
			if req.GetBody != nil { // a POST: send its body again
				if retry.Body, err = req.GetBody(); err != nil {
					return errkit.Append(ErrRequestFailed, err)
				}
			}
			resp, err = c.httpc.HTTPClient.Do(retry)
			if err != nil {
				return errkit.Append(ErrRequestFailed, err)
			}
		}
	}
	if c.debugResponse != nil {
		c.debugResponse(resp)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			gologger.Error().Msgf("Failed to close response body: %s", err)
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return c.handleAPIError(resp)
	}

	if out != nil {
		dec := json.NewDecoder(resp.Body)
		if err := dec.Decode(out); err != nil {
			return errkit.Append(ErrDecodeResponse, err)
		}
	}
	return nil
}

// handleAPIError processes non-2xx HTTP responses, normalising them into the
// rich errkit error hierarchy so that callers can unwrap and inspect the root
// cause.
func (c *Client) handleAPIError(resp *http.Response) error {
	switch resp.StatusCode {
	case http.StatusNotFound:
		return ErrNotFound // Return ErrNotFound directly for 404 as it indicates no content
	}

	bodyBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return errkit.Wrap(ErrUnknownAPIError, fmt.Sprintf("api error (failed to read response body): %s", resp.Status))
	}

	var errorBody map[string]interface{}
	unmarshalErr := json.Unmarshal(bodyBytes, &errorBody)

	var detailedErr error
	if unmarshalErr == nil {
		// Check for common error message keys
		if errMsg, ok := errorBody["error"]; ok {
			detailedErr = errkit.New("api error", "status_code", resp.StatusCode, "error", errMsg)
		} else if errMsg, ok := errorBody["msg"]; ok {
			detailedErr = errkit.New("api error", "status_code", resp.StatusCode, "error", errMsg)
		} else if errMsg, ok := errorBody["message"]; ok {
			detailedErr = errkit.New("api error", "status_code", resp.StatusCode, "error", errMsg)
		} else if errMsg, ok := errorBody["cause"]; ok {
			detailedErr = errkit.New("api error", "status_code", resp.StatusCode, "error", errMsg)
		}
	}

	if detailedErr == nil {
		// Fallback to raw body if no specific keys found or unmarshalling failed
		detailedErr = errkit.New("api error", "status_code", resp.StatusCode, "error", strings.TrimSpace(string(bodyBytes)))
	}

	switch resp.StatusCode {
	case http.StatusBadRequest:
		return errkit.Append(ErrBadRequest, detailedErr)
	case http.StatusUnauthorized:
		return errkit.Append(ErrUnauthorized, detailedErr)
	case http.StatusTooManyRequests:
		return errkit.Append(ErrTooManyRequests, detailedErr)
	case http.StatusInternalServerError:
		return errkit.Append(ErrInternalServerError, detailedErr)
	default:
		return errkit.Append(ErrUnknownAPIError, detailedErr)
	}
}

// retryAfter reads a Retry-After header given in seconds.
func retryAfter(h string) (time.Duration, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(h))
	if err != nil || n < 0 {
		return 0, false
	}
	return time.Duration(n)*time.Second + 500*time.Millisecond, true
}
