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
	Functions GoFunctions  `json:"go_functions"`
}

// MaxCheckEntries is how many entries one check sends (one request).
const MaxCheckEntries = 500

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
	return c.checkPackages(ctx, entries, false)
}

func (c *Client) checkPackages(ctx context.Context, entries []string, functions bool) (StackResult, error) {
	var res StackResult
	if len(entries) == 0 {
		return res, errkit.Append(ErrBadRequest, fmt.Errorf("nothing to check"))
	}
	if len(entries) > MaxCheckEntries {
		return res, errkit.Append(ErrBadRequest, fmt.Errorf("at most %d entries per check (got %d)", MaxCheckEntries, len(entries)))
	}
	norm := make([]string, len(entries))
	for i, e := range entries {
		norm[i] = NormalizeCheckEntry(e)
	}
	return c.checkChunk(ctx, norm, functions)
}

// checkChunk posts a list and, when the answer is cut at the API's response size (truncated, no cursor), splits
// the list in halves and asks again until every answer is whole. (save: true would page it, but a saved stack
// loses an rpm's binary package name and with it advisories that name the binary, so lists are never saved.)
func (c *Client) checkChunk(ctx context.Context, entries []string, functions bool) (StackResult, error) {
	var res StackResult
	body := map[string]any{"packages": entries}
	if functions {
		body["functions"] = true
	}
	req, err := c.newRequest(ctx, http.MethodPost, "/v1/stack", nil, body)
	if err != nil {
		return res, errkit.Append(ErrRequestBuildFailure, err)
	}
	var page stackPage
	if err := c.do(req, &page); err != nil {
		return res, errkit.Append(ErrRequestFailed, err)
	}
	if !page.Truncated || len(page.Items) >= page.Total || len(entries) < 2 {
		res.Summary, res.Items, res.Total, res.GoFunctions = page.Summary, page.Items, page.Total, page.Functions
		return res, nil
	}
	half := len(entries) / 2
	first, err := c.checkChunk(ctx, entries[:half], functions)
	if err != nil {
		return res, err
	}
	second, err := c.checkChunk(ctx, entries[half:], functions)
	if err != nil {
		return res, err
	}
	mergeStack(&first, second)
	return first, nil
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
	var page stackPage
	if err := c.do(req, &page); err != nil {
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
	// Progress, when set, is called after each request with the entries checked so far.
	Progress func(done, total int)
}

// CheckManyWith is CheckMany with options.
func (c *Client) CheckManyWith(ctx context.Context, entries []string, opts CheckOptions) (StackResult, error) {
	var all StackResult
	for start := 0; start < len(entries); start += MaxCheckEntries {
		end := start + MaxCheckEntries
		if end > len(entries) {
			end = len(entries)
		}
		res, err := c.checkPackages(ctx, entries[start:end], opts.Functions)
		if err != nil && opts.Functions && functionsRejected(err) {
			opts.Functions, all.FunctionsUnavailable = false, true
			res, err = c.checkPackages(ctx, entries[start:end], false)
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
