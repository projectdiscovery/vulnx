package vulnx

// vulnx search --cpe <cpe> (or cpe: in a query, or --product vendor:product --version v): the CVEs affecting one
// product version (issue #77), from /v1/products/{vendor}/{product}/versions/{version}. That endpoint answers most
// urgent first (severity, then CVSS) and filters on one severity only, so:
//   - a bare cpe: search pages through it, fetching only the rows asked for;
//   - with other filters or a sort, the version's whole list is fetched (it is bounded: a product version, not
//     the CVE list) and vulnx filters and sorts it.

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/utils/errkit"
)

const cpeMaxRows = 5000 // 50 requests: a whole version list is fetched only when filters or a sort need it

type cpePage struct {
	Found           bool    `json:"found"`
	VersionKnown    bool    `json:"version_known"`
	AdvisoriesTotal int     `json:"advisories_total"`
	Advisories      []scCVE `json:"advisories"`
	Cursor          string  `json:"cursor"`
}

// cpe searches accept these /v1/cves parameters, applied by vulnx to the version's CVEs
var cpeFilterable = map[string]bool{
	"severity": true, "exploit": true, "min_cvss": true, "min_epss": true, "published_since": true,
	"published_before": true, "cwe": true, "remote": true, "authentication_required": true, "nvd_status": true,
}

func (c *Client) searchCPE(ctx context.Context, tq *scQuery, sortKey string, hasFacets bool, limit, offset int, all bool) (SearchResponse, error) {
	var resp SearchResponse
	if hasFacets {
		return resp, unsupported("facets are not available with cpe: (a product version's CVE list)")
	}
	if len(tq.ids) > 0 {
		return resp, unsupported("cve_id: and cpe: cannot be combined")
	}
	for k := range tq.params {
		if !cpeFilterable[k] {
			name := map[string]string{"q": "keywords", "vendor": "--vendor", "product": "--product", "category": "category:",
				"deployment_model": "deployment_model:", "oss": "is_oss:"}[k]
			if name == "" {
				name = k
			}
			return resp, unsupported("%s cannot be combined with cpe: (it already names the product)", name)
		}
	}
	filtered := len(tq.params) > 0
	if sortKey == "published_date:desc" { // vulnx's default sort; a version's CVEs come most urgent first
		sortKey = ""
	}
	full := filtered || sortKey != "" || all
	ref := tq.cpe
	path := fmt.Sprintf("/v1/products/%s/%s/versions/%s", url.PathEscape(ref.vendor), url.PathEscape(ref.product), url.PathEscape(ref.version))
	want := offset + limit
	if want < 1 {
		want = 1
	}
	var rows []scCVE
	cursor := ""
	for {
		q := url.Values{"limit": {strconv.Itoa(scMaxPage)}}
		if !full && want-len(rows) < scMaxPage {
			q.Set("limit", strconv.Itoa(want-len(rows)))
		}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		req, err := c.newRequest(ctx, http.MethodGet, path, q, nil)
		if err != nil {
			return resp, errkit.Append(ErrRequestBuildFailure, err)
		}
		var p cpePage
		if err := c.do(req, &p); err != nil {
			if errkit.Is(err, ErrNotFound) {
				return resp, errkit.Append(ErrNotFound, fmt.Errorf("NVD has no product %s:%s", ref.vendor, ref.product))
			}
			return resp, errkit.Append(ErrRequestFailed, err)
		}
		if !p.Found {
			return resp, errkit.Append(ErrNotFound, fmt.Errorf("NVD has no product %s:%s (check the vendor and product names)", ref.vendor, ref.product))
		}
		if resp.Total == 0 {
			resp.Total = p.AdvisoriesTotal
		}
		rows = append(rows, p.Advisories...)
		if full && p.AdvisoriesTotal > cpeMaxRows {
			return resp, unsupported("%s:%s %s has %d CVEs; filters and sorting on it fetch at most %d (narrow with a bare --cpe search)", ref.vendor, ref.product, ref.version, p.AdvisoriesTotal, cpeMaxRows)
		}
		if p.Cursor == "" || len(p.Advisories) == 0 || (!full && len(rows) >= want) {
			break
		}
		cursor = p.Cursor
	}
	if full {
		kept := rows[:0]
		for _, r := range rows {
			if cpeRowMatches(r, tq.params) {
				kept = append(kept, r)
			}
		}
		rows = kept
		resp.Total = len(rows)
		if sortKey != "" {
			sortRows(rows, sortKey)
		}
	}
	for i := offset; i < len(rows) && (all || len(resp.Results) < limit); i++ {
		v := rows[i].toVulnerability()
		if v.Vendor == "" {
			v.Vendor, v.Product = ref.vendor, ref.product
			v.AffectedProducts = []*ProductInfo{{Vendor: ref.vendor, Product: ref.product}}
		}
		resp.Results = append(resp.Results, v)
	}
	resp.Count = len(resp.Results)
	return resp, nil
}

// cpeRowMatches applies translated /v1/cves filters to one CVE of a version list.
func cpeRowMatches(r scCVE, p url.Values) bool {
	e := r.Exploitation
	if e == nil {
		e = &scExploitation{}
	}
	if v := p.Get("severity"); v != "" && !inList(strings.ToLower(r.Severity), strings.Split(v, ",")) {
		return false
	}
	if v := p.Get("nvd_status"); v != "" && !inList(r.NVDStatus, strings.Split(v, ",")) {
		return false
	}
	if v := p.Get("min_cvss"); v != "" {
		if f, _ := strconv.ParseFloat(v, 64); r.CvssScore < f {
			return false
		}
	}
	if v := p.Get("min_epss"); v != "" {
		if f, _ := strconv.ParseFloat(v, 64); r.EpssScore < f {
			return false
		}
	}
	pub := firstNonEmpty(r.PublishedDate, r.PublishedAt)
	if v := p.Get("published_since"); v != "" && (len(pub) < 10 || pub[:10] < v) {
		return false
	}
	if v := p.Get("published_before"); v != "" && (len(pub) < 10 || pub[:10] >= v) {
		return false
	}
	if v := p.Get("cwe"); v != "" && !strings.Contains(strings.ToUpper(string(r.CWE)), `"`+v+`"`) && !strings.Contains(strings.ToUpper(string(r.CWE)), `"ID":"`+v+`"`) {
		return false
	}
	if v := p.Get("remote"); v != "" && (e.Remote == nil || strconv.FormatBool(*e.Remote) != v) {
		return false
	}
	if v := p.Get("authentication_required"); v != "" && (e.AuthenticationRequired == nil || strconv.FormatBool(*e.AuthenticationRequired) != v) {
		return false
	}
	if v := p.Get("exploit"); v != "" {
		for _, k := range strings.Split(v, ",") {
			neg := strings.HasPrefix(k, "-")
			has := false
			switch strings.TrimPrefix(k, "-") {
			case "known_exploited":
				has = inList("cisa", e.KnownExploitedBy)
			case "vulncheck_known_exploited":
				has = inList("vulncheck", e.KnownExploitedBy)
			case "public_exploit":
				has = e.PublicExploit
			case "nuclei_template":
				has = e.NucleiTemplate != nil
			case "initial_access":
				has = e.InitialAccess
			case "ransomware":
				return false // the version list carries no ransomware flag; refused before fetching (see translate)
			}
			if has == neg {
				return false
			}
		}
	}
	return true
}

func inList(v string, list []string) bool {
	for _, x := range list {
		if strings.EqualFold(strings.TrimSpace(x), v) {
			return true
		}
	}
	return false
}

func sortRows(rows []scCVE, sortKey string) {
	field, dir, _ := strings.Cut(sortKey, ":")
	key := func(r scCVE) float64 {
		switch field {
		case "cvss_score":
			return r.CvssScore
		case "epss_score":
			return r.EpssScore
		case "published_date", "modified_date":
			d := firstNonEmpty(r.PublishedDate, r.PublishedAt)
			if field == "modified_date" {
				d = firstNonEmpty(r.ModifiedDate, r.ModifiedAt)
			}
			if t := scTime(d); t != nil {
				return float64(t.Unix())
			}
			return float64(time.Time{}.Unix())
		}
		return 0
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if dir == "asc" {
			return key(rows[i]) < key(rows[j])
		}
		return key(rows[i]) > key(rows[j])
	})
}
