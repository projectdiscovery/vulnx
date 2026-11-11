package vulnx

// Version checks and stack scans on SecurityContext's /v1/stack (vulnx check, vulnx scan), and a CVE's change
// history (/v1/cves/{id}?include=history, vulnx id --history).
//
//   - A list of entries (package versions, CPEs, distro packages) is answered at once: POST /v1/stack {"packages"}.
//   - A file (lockfile, CycloneDX / SPDX SBOM, Compose file, Dockerfile) is queued: POST /v1/stack multipart, then
//     GET /v1/stack/{id} until it is ready, paging its items by cursor.
//   - A product version's full CVE list: GET /v1/products/{vendor}/{product}/versions/{version}, paged by cursor
//     (a stack item carries its 10 most urgent).

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/utils/errkit"
)

// StackAdvisory is one advisory row of a stack item.
type StackAdvisory struct {
	AdvisoryID string          `json:"advisory_id,omitempty"`
	CVE        string          `json:"cve,omitempty"`
	Name       string          `json:"name,omitempty"`
	Severity   string          `json:"severity,omitempty"`
	CvssScore  float64         `json:"cvss_score,omitempty"`
	EpssScore  float64         `json:"epss_score,omitempty"`
	Ranges     []string        `json:"ranges,omitempty"`
	FixedIn    any             `json:"fixed_in,omitempty"`
	Basis      string          `json:"basis,omitempty"`
	Reason     string          `json:"reason,omitempty"`
	Match      any             `json:"match,omitempty"`
	Exploit    *scExploitation `json:"exploitation,omitempty"`
	Aliases    []string        `json:"aliases,omitempty"`
	// Ref is a compact answer's pointer into its advisories map; expandRefs replaces the row with the entry.
	Ref string `json:"ref,omitempty"`
	// Reachability is set by vulnx on a host scan's Go rows: reachable (a binary links a function the advisory names
	// as affected) or not_reachable (no binary carrying the module links any); empty when no function list is known.
	Reachability string `json:"reachability,omitempty"`
}

// AffectedPackage is one package a Go advisory names as affected, with its affected functions (none listed: every
// function of the package).
type AffectedPackage struct {
	Package   string   `json:"package"`
	Functions []string `json:"functions"`
}

// GoFunctions maps a Go item's package and an advisory row's id to the packages and functions the advisory names.
type GoFunctions map[string]map[string][]AffectedPackage

// ItemReachability says, per binary carrying a Go module version, whether it links an affected function: the
// binaries that do, those that link none, and those with an advisory no function list is known for.
type ItemReachability struct {
	Reachable    []string `json:"reachable,omitempty"`
	NotReachable []string `json:"not_reachable,omitempty"`
	Unknown      []string `json:"unknown,omitempty"`
}

// StackItem is one package (or product, or distro package) of a stack with SecurityContext's verdict.
type StackItem struct {
	Input             string            `json:"input,omitempty"`
	Package           string            `json:"package,omitempty"`
	Version           string            `json:"version,omitempty"`
	Status            string            `json:"status,omitempty"` // affected | clean | undetermined | unseen
	WorstSeverity     string            `json:"worst_severity,omitempty"`
	Advisories        int               `json:"advisories,omitempty"`
	AdvisoryRowsTotal int               `json:"advisory_rows_total,omitempty"`
	FixedVersion      string            `json:"fixed_version,omitempty"`
	KnownExploited    any               `json:"known_exploited,omitempty"`
	Malicious         bool              `json:"malicious,omitempty"`
	AdvisoryRows      []StackAdvisory   `json:"advisory_rows,omitempty"`
	Undetermined      []StackAdvisory   `json:"undetermined,omitempty"`
	UndeterminedTotal int               `json:"undetermined_total,omitempty"`
	Reason            string            `json:"reason,omitempty"`
	Distro            string            `json:"distro,omitempty"`
	Release           string            `json:"release,omitempty"`
	AdvisoriesURL     string            `json:"advisories_url,omitempty"`
	URL               string            `json:"url,omitempty"`
	IntroducedBy      any               `json:"introduced_by,omitempty"`
	Reachability      *ItemReachability `json:"reachability,omitempty"` // set by vulnx on a host scan's Go items
}

// StackSummary counts a stack's items.
type StackSummary struct {
	Packages            int            `json:"packages"`
	Affected            int            `json:"affected"`
	Clean               int            `json:"clean"`
	Undetermined        int            `json:"undetermined"`
	Unseen              int            `json:"unseen"`
	KnownExploited      int            `json:"known_exploited"`
	PublicExploit       int            `json:"public_exploit"`
	Malicious           int            `json:"malicious"`
	BySeverity          map[string]int `json:"by_severity,omitempty"`
	UndeterminedReasons []struct {
		Reason string `json:"reason"`
		Count  int    `json:"count"`
		Why    string `json:"why"`
	} `json:"undetermined_reasons,omitempty"`
}

// StackInfo describes a queued or finished stack.
type StackInfo struct {
	ID            string `json:"id,omitempty"`
	Name          string `json:"name,omitempty"`
	Source        string `json:"source,omitempty"`
	Status        string `json:"status,omitempty"` // queued | parsing | running | ready | failed
	Error         string `json:"error,omitempty"`
	PackagesTotal int    `json:"packages_total,omitempty"`
	Meta          any    `json:"meta,omitempty"`
	Services      any    `json:"services,omitempty"`
	Dockerfile    any    `json:"dockerfile,omitempty"`
}

// StackResult is a checked list or a scanned file: the summary and every item.
type StackResult struct {
	Stack       *StackInfo   `json:"stack,omitempty"`
	Summary     StackSummary `json:"summary"`
	Items       []StackItem  `json:"items"`
	Total       int          `json:"total"`
	GoFunctions GoFunctions  `json:"go_functions,omitempty"`
	// FunctionsUnavailable: function lists were asked for and the API does not serve them yet.
	FunctionsUnavailable bool `json:"-"`
}

type stackPage struct {
	Truncated bool         `json:"truncated"`
	ID        string       `json:"id"`
	Status    string       `json:"status"`
	Stack     *StackInfo   `json:"stack"`
	Summary   StackSummary `json:"summary"`
	Items     []StackItem  `json:"items"`
	Total     int          `json:"total"`
	Cursor    string       `json:"cursor"`
	ExpiresAt string       `json:"expires_at"`
	Functions GoFunctions  `json:"go_functions"`
	// Advisories is a compact answer's shared row content, by ref.
	Advisories map[string]StackAdvisory `json:"advisories"`
}

// MaxCheckEntries is how many entries one check sends (one request).
const MaxCheckEntries = 500

// MaxCompactEntries is how many entries one compact check sends: a whole machine's inventory.
const MaxCompactEntries = 5000

// checkMode is what a check asks the API for besides the verdicts.
type checkMode struct {
	functions bool // each Go advisory's affected functions (go_functions)
	compact   bool // each advisory once, up to MaxCompactEntries entries, a gzip body
}

func (m checkMode) maxEntries() int {
	if m.compact {
		return MaxCompactEntries
	}
	return MaxCheckEntries
}

var productShorthand = regexp.MustCompile(`^([a-z0-9][a-z0-9_.\-]*)[:/]([a-z0-9][a-z0-9_.\-+]*)@(\S+)$`)

// NormalizeCheckEntry turns vulnx's product shorthand (vendor:product@version, vendor/product@version) into a CPE;
// purls, CPEs and ecosystem/name@version entries pass through (SecurityContext reads them as they are).
func NormalizeCheckEntry(e string) string {
	e = strings.TrimSpace(e)
	low := strings.ToLower(e)
	if strings.HasPrefix(low, "cpe:") || strings.HasPrefix(low, "pkg:") {
		return e
	}
	if m := productShorthand.FindStringSubmatch(low); m != nil && !isEcosystem(m[1]) {
		return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", m[1], m[2], m[3])
	}
	return e
}

func isEcosystem(s string) bool {
	switch s {
	case "npm", "pypi", "maven", "go", "golang", "cargo", "crates.io", "rubygems", "gem", "composer", "packagist",
		"nuget", "pub", "hex", "swift", "cocoapods", "github", "deb", "rpm", "apk":
		return true
	}
	return false
}

// CheckPackages answers a list of entries at once (POST /v1/stack {"packages"}).
func (c *Client) CheckPackages(ctx context.Context, entries []string) (StackResult, error) {
	return c.checkPackages(ctx, entries, checkMode{})
}

func (c *Client) checkPackages(ctx context.Context, entries []string, mode checkMode) (StackResult, error) {
	var res StackResult
	if len(entries) == 0 {
		return res, errkit.Append(ErrBadRequest, fmt.Errorf("nothing to check"))
	}
	if len(entries) > mode.maxEntries() {
		return res, errkit.Append(ErrBadRequest, fmt.Errorf("at most %d entries per check (got %d)", mode.maxEntries(), len(entries)))
	}
	norm := make([]string, len(entries))
	for i, e := range entries {
		norm[i] = NormalizeCheckEntry(e)
	}
	return c.checkChunk(ctx, norm, mode)
}

// checkChunk posts a list and reads the whole answer. An answer cut at the API's response size carries a cursor:
// the same POST is repeated with ?cursor= until the last item, the summary (over the whole list) taken from the
// first page. An API that cuts without a cursor gets the list split in halves instead. A cursor the API no longer
// accepts (the dataset was rebuilt between pages) restarts the list once. (save: true would page it too, but a
// saved stack loses an rpm's binary package name and with it advisories that name the binary.)
func (c *Client) checkChunk(ctx context.Context, entries []string, mode checkMode) (StackResult, error) {
	res, err := c.checkPages(ctx, entries, mode)
	if err != nil && staleCursor(err) {
		return c.checkPages(ctx, entries, mode)
	}
	return res, err
}

// maxCheckPages bounds the pages one list is read in: 500 entries at one item a page.
const maxCheckPages = MaxCheckEntries

func (c *Client) checkPages(ctx context.Context, entries []string, mode checkMode) (StackResult, error) {
	var res StackResult
	body := map[string]any{"packages": entries}
	if mode.functions {
		body["functions"] = true
	}
	if mode.compact {
		body["compact"] = true
	}
	cursor := ""
	for n := 0; n < maxCheckPages; n++ {
		var query url.Values
		if cursor != "" {
			query = url.Values{"cursor": {cursor}}
		}
		req, err := c.newRequest(ctx, http.MethodPost, "/v1/stack", query, body)
		if err == nil && mode.compact {
			err = gzipBody(req, body)
		}
		if err != nil {
			return res, errkit.Append(ErrRequestBuildFailure, err)
		}
		var page stackPage
		if err := c.do(req, &page); err != nil {
			return res, errkit.Append(ErrRequestFailed, err)
		}
		expandRefs(page.Items, page.Advisories)
		if n == 0 {
			res.Summary, res.Total = page.Summary, page.Total
		}
		mergeStack(&res, StackResult{Items: page.Items, GoFunctions: page.Functions})
		if !page.Truncated || len(res.Items) >= res.Total {
			return res, nil
		}
		if page.Cursor == "" {
			if n > 0 || len(entries) < 2 {
				return res, errkit.Append(ErrRequestFailed, fmt.Errorf("the answer was cut with no cursor after %d of %d items", len(res.Items), res.Total))
			}
			return c.checkHalves(ctx, entries, mode)
		}
		cursor = page.Cursor
	}
	return res, errkit.Append(ErrRequestFailed, fmt.Errorf("the answer took more than %d pages", maxCheckPages))
}

// checkHalves checks a list in two halves, for an API that cuts an answer without a cursor.
func (c *Client) checkHalves(ctx context.Context, entries []string, mode checkMode) (StackResult, error) {
	half := len(entries) / 2
	first, err := c.checkChunk(ctx, entries[:half], mode)
	if err != nil {
		return first, err
	}
	second, err := c.checkChunk(ctx, entries[half:], mode)
	if err != nil {
		return first, err
	}
	mergeStack(&first, second)
	return first, nil
}

// gzipBody replaces a request's JSON body with its gzip, so a compact check of thousands of entries stays small.
func gzipBody(req *http.Request, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	b := buf.Bytes()
	req.Body, req.ContentLength = io.NopCloser(bytes.NewReader(b)), int64(len(b))
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }
	req.Header.Set("Content-Encoding", "gzip")
	return nil
}

// expandRefs turns a compact answer's rows back into whole rows: the shared entry, with the row's own ranges and
// fixes.
func expandRefs(items []StackItem, advisories map[string]StackAdvisory) {
	expand := func(rows []StackAdvisory) {
		for i, r := range rows {
			if r.Ref == "" {
				continue
			}
			full := advisories[r.Ref]
			full.Ranges, full.FixedIn = r.Ranges, r.FixedIn
			rows[i] = full
		}
	}
	for i := range items {
		expand(items[i].AdvisoryRows)
		expand(items[i].Undetermined)
	}
}

// staleCursor is the API's 400 for a cursor of another list or dataset.
func staleCursor(err error) bool {
	return errkit.Is(err, ErrBadRequest) && strings.Contains(err.Error(), "invalid cursor")
}

// mergeStack adds b's items and counts to a.
func mergeStack(a *StackResult, b StackResult) {
	a.Items = append(a.Items, b.Items...)
	for pkg, rows := range b.GoFunctions {
		if a.GoFunctions == nil {
			a.GoFunctions = GoFunctions{}
		}
		if a.GoFunctions[pkg] == nil {
			a.GoFunctions[pkg] = map[string][]AffectedPackage{}
		}
		for id, list := range rows {
			a.GoFunctions[pkg][id] = list
		}
	}
	a.Total += b.Total
	s, r := &a.Summary, b.Summary
	s.Packages += r.Packages
	s.Affected += r.Affected
	s.Clean += r.Clean
	s.Undetermined += r.Undetermined
	s.Unseen += r.Unseen
	s.KnownExploited += r.KnownExploited
	s.PublicExploit += r.PublicExploit
	s.Malicious += r.Malicious
	if s.BySeverity == nil {
		s.BySeverity = map[string]int{}
	}
	for k, v := range r.BySeverity {
		s.BySeverity[k] += v
	}
	s.UndeterminedReasons = append(s.UndeterminedReasons, r.UndeterminedReasons...)
}

// ProductVersionCVEs pages a product version's full CVE list (GET /v1/products/{vendor}/{product}/versions/{v}).
func (c *Client) ProductVersionCVEs(ctx context.Context, vendor, product, version string) ([]StackAdvisory, error) {
	var out []StackAdvisory
	path := fmt.Sprintf("/v1/products/%s/%s/versions/%s", url.PathEscape(vendor), url.PathEscape(product), url.PathEscape(version))
	cursor := ""
	for page := 0; page < 200; page++ {
		q := url.Values{"limit": {"100"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		req, err := c.newRequest(ctx, http.MethodGet, path, q, nil)
		if err != nil {
			return out, errkit.Append(ErrRequestBuildFailure, err)
		}
		var resp struct {
			Advisories []struct {
				CVE       string          `json:"cve"`
				Name      string          `json:"name"`
				Severity  string          `json:"severity"`
				CvssScore float64         `json:"cvss_score"`
				EpssScore float64         `json:"epss_score"`
				Match     any             `json:"match"`
				Exploit   *scExploitation `json:"exploitation"`
			} `json:"advisories"`
			Cursor string `json:"cursor"`
		}
		if err := c.do(req, &resp); err != nil {
			return out, errkit.Append(ErrRequestFailed, err)
		}
		for _, a := range resp.Advisories {
			out = append(out, StackAdvisory{AdvisoryID: a.CVE, CVE: a.CVE, Name: a.Name, Severity: a.Severity,
				CvssScore: a.CvssScore, EpssScore: a.EpssScore, Match: a.Match, Exploit: a.Exploit})
		}
		if resp.Cursor == "" || len(resp.Advisories) == 0 {
			break
		}
		cursor = resp.Cursor
	}
	return out, nil
}

// ScanFile uploads a lockfile, SBOM, Compose file or Dockerfile (POST /v1/stack, multipart) and returns the
// queued stack's id. SecurityContext recognises the file by its name, so the file's own name is sent.
func (c *Client) ScanFile(ctx context.Context, path string) (string, error) {
	page, err := c.uploadFile(ctx, path, nil)
	return page.ID, err
}

// ErrExpiryUnsupported: the API cannot expire a stored stack, so nothing was uploaded.
var ErrExpiryUnsupported = errkit.New("this SecurityContext API cannot expire a stored report's link, so nothing was uploaded")

// ShareFile uploads a file as a stored stack whose link expires: after expires it stops answering (SecurityContext
// keeps the names and versions for analysis, no longer tied to who sent them). It returns the stack's id and when
// the link expires. An API that cannot expire a link is not sent the file at all (ErrExpiryUnsupported): the link
// would work forever.
func (c *Client) ShareFile(ctx context.Context, path string, expires time.Duration) (id, expiresAt string, err error) {
	if err := c.StackExpirySupported(ctx); err != nil {
		return "", "", err
	}
	page, err := c.uploadFile(ctx, path, map[string]string{"expires_in": strconv.Itoa(int(expires.Seconds()))})
	if err != nil {
		return "", "", err
	}
	if page.ExpiresAt == "" {
		return page.ID, "", errkit.Append(ErrUnknownAPIError, fmt.Errorf("stack %s was stored without an expiry", page.ID))
	}
	return page.ID, page.ExpiresAt, nil
}

// StackExpirySupported is nil when the API can expire a stored stack (its description names expires_in), and
// ErrExpiryUnsupported when it cannot.
func (c *Client) StackExpirySupported(ctx context.Context) error {
	req, err := c.newRequest(ctx, http.MethodGet, "/v1/openapi.json", nil, nil)
	if err != nil {
		return errkit.Append(ErrRequestBuildFailure, err)
	}
	var spec json.RawMessage
	if err := c.do(req, &spec); err != nil {
		return errkit.Append(ErrRequestFailed, err)
	}
	if !bytes.Contains(spec, []byte(`"expires_in"`)) {
		return ErrExpiryUnsupported
	}
	return nil
}

// uploadFile posts a file (and form fields) to /v1/stack and returns the answer, its ID set.
func (c *Client) uploadFile(ctx context.Context, path string, fields map[string]string) (stackPage, error) {
	var page stackPage
	id, err := c.uploadInto(ctx, path, fields, &page)
	page.ID = id
	return page, err
}

func (c *Client) uploadInto(ctx context.Context, path string, fields map[string]string, page *stackPage) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("file", filepath.Base(path))
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(part, f); err != nil {
		return "", err
	}
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			return "", err
		}
	}
	if err := mw.Close(); err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/stack", bytes.NewReader(body.Bytes()))
	if err != nil {
		return "", errkit.Append(ErrCreateHTTPRequest, err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("User-Agent", c.userAgent)
	if c.apiKey != "" {
		req.Header.Set("X-Api-Key", c.apiKey)
	}
	// a body that can be sent again, for do()'s one retry after a 429
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body.Bytes())), nil }
	if err := c.do(req, page); err != nil {
		return "", errkit.Append(ErrRequestFailed, err)
	}
	id := page.ID
	if id == "" && page.Stack != nil {
		id = page.Stack.ID
	}
	if id == "" {
		return "", errkit.Append(ErrUnknownAPIError, fmt.Errorf("the upload was accepted but no stack id came back"))
	}
	return id, nil
}

// StackPage is where a stored stack is read by a person: its page on the SecurityContext site (an unlisted link:
// whoever has it can read it), or for another API its /v1/stack/{id}.
func (c *Client) StackPage(id string) string {
	if c.baseURL == DefaultBaseURL {
		return "https://securitycontext.com/stack/" + url.PathEscape(id)
	}
	return c.baseURL + "/v1/stack/" + url.PathEscape(id)
}

// WaitStackReady waits until a stored stack is parsed and returns its status and summary without its items (one
// small request a poll, where WaitStack reads every page).
func (c *Client) WaitStackReady(ctx context.Context, id string) (StackResult, error) {
	var res StackResult
	for {
		req, err := c.newRequest(ctx, http.MethodGet, "/v1/stack/"+url.PathEscape(id), url.Values{"limit": {"1"}}, nil)
		if err != nil {
			return res, errkit.Append(ErrRequestBuildFailure, err)
		}
		var p stackPage
		if err := c.do(req, &p); err != nil {
			return res, errkit.Append(ErrRequestFailed, err)
		}
		res.Stack, res.Summary, res.Total = p.Stack, p.Summary, p.Total
		if res.Stack == nil {
			res.Stack = &StackInfo{ID: p.ID, Status: p.Status}
		}
		switch res.Stack.Status {
		case "", "ready":
			return res, nil
		case "failed":
			return res, errkit.Append(ErrRequestFailed, fmt.Errorf("the stack could not be read: %s", res.Stack.Error))
		}
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		case <-time.After(7 * time.Second): // under an anonymous caller's ten requests a minute
		}
	}
}

// GetStack reads a stack: while it is queued or being scanned, its status; when ready, the summary and every item
// (all cursor pages).
func (c *Client) GetStack(ctx context.Context, id string) (StackResult, error) {
	var res StackResult
	cursor := ""
	for page := 0; page < 500; page++ {
		q := url.Values{"limit": {"100"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		req, err := c.newRequest(ctx, http.MethodGet, "/v1/stack/"+url.PathEscape(id), q, nil)
		if err != nil {
			return res, errkit.Append(ErrRequestBuildFailure, err)
		}
		var p stackPage
		if err := c.do(req, &p); err != nil {
			return res, errkit.Append(ErrRequestFailed, err)
		}
		if page == 0 {
			res.Stack = p.Stack
			if res.Stack == nil {
				res.Stack = &StackInfo{ID: p.ID, Status: p.Status}
			}
			res.Summary, res.Total = p.Summary, p.Total
			if res.Stack.Status != "" && res.Stack.Status != "ready" {
				return res, nil
			}
		}
		res.Items = append(res.Items, p.Items...)
		if p.Cursor == "" || len(p.Items) == 0 {
			break
		}
		cursor = p.Cursor
	}
	return res, nil
}

// WaitStack polls a stack until it is ready or failed (or ctx ends), calling progress with each status seen.
func (c *Client) WaitStack(ctx context.Context, id string, progress func(status string)) (StackResult, error) {
	delay := 2 * time.Second
	for {
		res, err := c.GetStack(ctx, id)
		if err != nil {
			return res, err
		}
		status := ""
		if res.Stack != nil {
			status = res.Stack.Status
		}
		if progress != nil {
			progress(status)
		}
		switch status {
		case "ready", "":
			return res, nil
		case "failed":
			msg := "the scan failed"
			if res.Stack != nil && res.Stack.Error != "" {
				msg = res.Stack.Error
			}
			return res, errkit.Append(ErrUnknownAPIError, fmt.Errorf("%s", msg))
		}
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		case <-time.After(delay):
		}
		if delay < 10*time.Second { // anonymous callers share 10 requests a minute
			delay += 2 * time.Second
		}
	}
}

// ChangeEntry is one recorded change to a CVE (include=history).
type ChangeEntry struct {
	ChangedDate string `json:"changed_date"`
	Field       string `json:"field"`
	Source      string `json:"source,omitempty"`
	OldValue    any    `json:"old_value"`
	NewValue    any    `json:"new_value"`
}

// GetCVEHistory returns the changes SecurityContext recorded for a CVE (oldest first).
func (c *Client) GetCVEHistory(ctx context.Context, id string) ([]ChangeEntry, error) {
	if !IsCVEID(id) {
		return nil, errkit.Append(ErrNotFound, fmt.Errorf("%s is not a CVE id", id))
	}
	q := url.Values{"include": {"history"}}
	req, err := c.newRequest(ctx, http.MethodGet, "/v1/cves/"+url.PathEscape(strings.ToUpper(strings.TrimSpace(id))), q, nil)
	if err != nil {
		return nil, errkit.Append(ErrRequestBuildFailure, err)
	}
	var resp struct {
		History []ChangeEntry `json:"history"`
	}
	if err := c.do(req, &resp); err != nil {
		return nil, errkit.Append(ErrRequestFailed, err)
	}
	return resp.History, nil
}

// SBOMEntries reads a CycloneDX or SPDX JSON SBOM and returns its components as check entries: each component's
// purl, or its CPE when it has none. ok is false when the file is not a JSON SBOM (a lockfile, Compose file ...).
// vulnx checks an SBOM's entries as a list (one request, answered at once) rather than uploading the file.
func SBOMEntries(raw []byte) (entries []string, format string, ok bool) {
	var doc struct {
		BOMFormat   string            `json:"bomFormat"`
		SPDXVersion string            `json:"spdxVersion"`
		Components  []json.RawMessage `json:"components"`
		Packages    []struct {
			ExternalRefs []struct {
				ReferenceType    string `json:"referenceType"`
				ReferenceLocator string `json:"referenceLocator"`
			} `json:"externalRefs"`
		} `json:"packages"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return nil, "", false
	}
	seen := map[string]bool{}
	add := func(e string) {
		e = strings.TrimSpace(e)
		if e != "" && !seen[e] {
			seen[e] = true
			entries = append(entries, e)
		}
	}
	switch {
	case strings.EqualFold(doc.BOMFormat, "CycloneDX"):
		var walk func(list []json.RawMessage)
		walk = func(list []json.RawMessage) {
			for _, rawC := range list {
				var c struct {
					Purl       string `json:"purl"`
					CPE        string `json:"cpe"`
					Properties []struct {
						Name  string `json:"name"`
						Value string `json:"value"`
					} `json:"properties"`
					Components []json.RawMessage `json:"components"`
				}
				if json.Unmarshal(rawC, &c) != nil {
					continue
				}
				if c.Purl != "" {
					props := map[string]string{}
					for _, p := range c.Properties {
						props[p.Name[strings.LastIndex(p.Name, ":")+1:]] = p.Value
					}
					add(withUpstream(c.Purl, props))
				} else if c.CPE != "" {
					add(c.CPE)
				}
				walk(c.Components)
			}
		}
		walk(doc.Components)
		return entries, "cyclonedx", true
	case doc.SPDXVersion != "":
		for _, p := range doc.Packages {
			purl, cpe := "", ""
			for _, r := range p.ExternalRefs {
				switch strings.ToLower(r.ReferenceType) {
				case "purl":
					purl = r.ReferenceLocator
				case "cpe23type", "cpe22type":
					if cpe == "" {
						cpe = r.ReferenceLocator
					}
				}
			}
			if purl != "" {
				add(purl)
			} else if cpe != "" {
				add(cpe)
			}
		}
		return entries, "spdx", true
	}
	return nil, "", false
}

// withUpstream adds the source package to an OS package purl that lacks it, from the component properties some
// SBOM generators add (SrcName, SrcEpoch, SrcVersion, SrcRelease). A distribution's advisories name the source package
// (glibc, not libc6), so without it most OS packages would be looked up under the wrong name.
func withUpstream(purl string, props map[string]string) string {
	low := strings.ToLower(purl)
	isDeb, isRPM, isAPK := strings.HasPrefix(low, "pkg:deb/"), strings.HasPrefix(low, "pkg:rpm/"), strings.HasPrefix(low, "pkg:apk/")
	src := props["SrcName"]
	if (!isDeb && !isRPM && !isAPK) || src == "" || strings.Contains(low, "upstream=") {
		return purl
	}
	ver := props["SrcVersion"]
	if rel := props["SrcRelease"]; rel != "" && ver != "" {
		ver += "-" + rel
	}
	up := src
	switch {
	case isDeb && ver != "":
		if e := props["SrcEpoch"]; e != "" && e != "0" {
			ver = e + ":" + ver
		}
		up = src + "@" + ver
	case isRPM && ver != "":
		up = src + "-" + ver + ".src.rpm"
	}
	sep := "?"
	if strings.Contains(purl, "?") {
		sep = "&"
	}
	return purl + sep + "upstream=" + url.QueryEscape(up)
}

// CheckMany checks any number of entries, MaxCheckEntries a request, and merges the answers.
func (c *Client) CheckMany(ctx context.Context, entries []string) (StackResult, error) {
	return c.CheckManyWith(ctx, entries, CheckOptions{})
}

// CheckOptions are CheckManyWith's options.
type CheckOptions struct {
	// Functions asks for each Go advisory's affected functions (StackResult.GoFunctions). An API that does not
	// serve them yet answers without: StackResult.FunctionsUnavailable.
	Functions bool
	// Compact asks for compact answers: MaxCompactEntries entries a request, each advisory once, a gzip body. An
	// API without them is asked again the plain way.
	Compact bool
	// Progress, when set, is called after each request with the entries checked so far.
	Progress func(done, total int)
}

// CheckManyWith is CheckMany with options.
func (c *Client) CheckManyWith(ctx context.Context, entries []string, opts CheckOptions) (StackResult, error) {
	var all StackResult
	mode := checkMode{functions: opts.Functions, compact: opts.Compact}
	size := mode.maxEntries()
	for start := 0; start < len(entries); start += size {
		end := min(start+size, len(entries))
		res, err := c.checkPackages(ctx, entries[start:end], mode)
		// an API without compact answers refuses the field, the gzip body or the batch size: the plain way instead
		if err != nil && mode.compact && start == 0 && errkit.Is(err, ErrBadRequest) {
			opts.Compact = false
			return c.CheckManyWith(ctx, entries, opts)
		}
		if err != nil && mode.functions && functionsRejected(err) {
			mode.functions, all.FunctionsUnavailable = false, true
			res, err = c.checkPackages(ctx, entries[start:end], mode)
		}
		if err != nil {
			return all, err
		}
		mergeStack(&all, res)
		if opts.Progress != nil {
			opts.Progress(end, len(entries))
		}
	}
	return all, nil
}

// functionsRejected is an API's 400 for a body field it does not know: one deployed before function lists.
func functionsRejected(err error) bool {
	return errkit.Is(err, ErrBadRequest) && strings.Contains(err.Error(), "functions")
}

// ScanImage queues a scan of a container image by registry reference (POST /v1/stack {"image", "platform"}):
// SecurityContext pulls it (public registries only) and reads its OS packages, language manifests and bundled
// libraries. Returns the stack id; WaitStack follows it.
func (c *Client) ScanImage(ctx context.Context, ref, platform string) (string, error) {
	body := map[string]any{"image": ref}
	if platform != "" {
		body["platform"] = platform
	}
	req, err := c.newRequest(ctx, http.MethodPost, "/v1/stack", nil, body)
	if err != nil {
		return "", errkit.Append(ErrRequestBuildFailure, err)
	}
	var page stackPage
	if err := c.do(req, &page); err != nil {
		return "", errkit.Append(ErrRequestFailed, err)
	}
	if page.ID == "" && page.Stack != nil {
		page.ID = page.Stack.ID
	}
	if page.ID == "" {
		return "", errkit.Append(ErrUnknownAPIError, fmt.Errorf("the image scan was accepted but no stack id came back"))
	}
	return page.ID, nil
}
