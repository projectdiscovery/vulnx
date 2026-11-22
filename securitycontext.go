package vulnx

// The SecurityContext backend (api.securitycontext.com /v1/cves), which replaces template-service's
// /v2/vulnerability API. SecurityContext's API is used as it is: vulnx translates its own query language and field
// names into /v1/cves parameters, and turns SecurityContext's records back into vulnx's Vulnerability, so the CLI,
// the renderer and the MCP tools keep working. What /v1/cves cannot answer is rejected with a sentence that says
// so (ErrUnsupportedQuery), never silently widened.

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/utils/errkit"
)

// ErrUnsupportedQuery: the query asks for something the SecurityContext API does not filter, sort or facet on.
var ErrUnsupportedQuery = errkit.New("unsupported query")

const (
	scMaxPage    = 100  // /v1/cves answers at most 100 rows a page
	scMaxWindow  = 1000 // offset + limit vulnx pages through (one request per 100 rows)
	scMaxQWords  = 5    // q= takes at most 5 words
	scMaxFacets  = 3    // facets= takes at most 3 dimensions
	scCVEPattern = `^(?i)CVE-\d{4}-\d{4,}$`
)

var cveIDPattern = regexp.MustCompile(scCVEPattern)

// IsCVEID reports whether id is a CVE identifier, the only kind of record SecurityContext serves.
func IsCVEID(id string) bool { return cveIDPattern.MatchString(strings.TrimSpace(id)) }

func unsupported(format string, args ...any) error {
	return errkit.Append(ErrUnsupportedQuery, fmt.Errorf(format, args...))
}

// ---------------------------------------------------------------------------------------------------------------
// Query translation

// scQuery is a translated search: the /v1/cves parameters, or one CVE id to fetch directly.
type scQuery struct {
	params url.Values
	ids    []string
	cpe    *cpeRef // a cpe: term: the CVEs of that product version (issue #77)
}

// cpeRef is the product version a cpe: term names.
type cpeRef struct{ vendor, product, version string }

// parseCPE reads a CPE 2.3 string or a CPE 2.2 URI naming one product version.
func parseCPE(s string) (*cpeRef, error) {
	s = strings.TrimSpace(s)
	low := strings.ToLower(s)
	var parts []string
	switch {
	case strings.HasPrefix(low, "cpe:2.3:"):
		parts = strings.Split(s[len("cpe:2.3:"):], ":")
	case strings.HasPrefix(low, "cpe:/"):
		parts = strings.Split(s[len("cpe:/"):], ":")
	default:
		return nil, unsupported("%q is not a CPE (cpe:2.3:a:vendor:product:version:... or cpe:/a:vendor:product:version)", s)
	}
	if len(parts) < 4 || parts[1] == "" || parts[2] == "" {
		return nil, unsupported("%q: a CPE needs a vendor, a product and a version", s)
	}
	ver := parts[3]
	if ver == "" || ver == "*" || ver == "-" {
		return nil, unsupported("%q has no version: give one to list the CVEs affecting it", s)
	}
	unesc := func(x string) string { return strings.ReplaceAll(x, "\\", "") }
	return &cpeRef{vendor: strings.ToLower(unesc(parts[1])), product: strings.ToLower(unesc(parts[2])), version: unesc(ver)}, nil
}

type queryTerm struct {
	field string // "" for a bare word
	value string
	neg   bool
}

// translateQuery turns vulnx's query (the Bleve subset the CLI flags produce, plus field:value terms a user types)
// into /v1/cves parameters. Terms are ANDed; an OR is accepted only between values of one field (severity:a ||
// severity:b) or as the vendor-or-product pair the --vendor / --product flags write.
func translateQuery(q string) (*scQuery, error) {
	out := &scQuery{params: url.Values{}}
	q = strings.TrimSpace(q)
	if q == "" {
		return out, nil
	}
	conjuncts, err := splitTop(q, "&&")
	if err != nil {
		return nil, err
	}
	var words []string
	exploit := map[string]bool{}
	var exploitOrder []string
	addExploit := func(kind string, neg bool) error {
		v := kind
		if neg {
			v = "-" + kind
		}
		if exploit[kind] || exploit["-"+kind] {
			if !exploit[v] {
				return unsupported("%s is asked both true and false", kind)
			}
			return nil
		}
		exploit[v] = true
		exploitOrder = append(exploitOrder, v)
		return nil
	}
	for _, c := range conjuncts {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		// "(a && b)" inside a conjunct: flatten
		if inner, ok := stripParens(c); ok {
			if parts, _ := splitTop(inner, "&&"); len(parts) > 1 {
				sub, err := translateQuery(inner)
				if err != nil {
					return nil, err
				}
				for k, vs := range sub.params {
					for _, v := range vs {
						if k == "exploit" {
							for _, e := range strings.Split(v, ",") {
								if err := addExploit(strings.TrimPrefix(e, "-"), strings.HasPrefix(e, "-")); err != nil {
									return nil, err
								}
							}
							continue
						}
						if k == "q" {
							words = append(words, strings.Fields(v)...)
							continue
						}
						if out.params.Get(k) != "" && out.params.Get(k) != v {
							return nil, unsupported("%s is given twice (%s, %s); SecurityContext takes one", k, out.params.Get(k), v)
						}
						out.params.Set(k, v)
					}
				}
				out.ids = append(out.ids, sub.ids...)
				if sub.cpe != nil {
					out.cpe = sub.cpe
				}
				continue
			}
		}
		terms, err := orTerms(c)
		if err != nil {
			return nil, err
		}
		if len(terms) > 1 {
			if err := applyOr(out, terms); err != nil {
				return nil, err
			}
			continue
		}
		t := terms[0]
		if t.field == "" {
			if t.neg {
				return nil, unsupported("NOT on a keyword (%q) is not supported", t.value)
			}
			words = append(words, strings.Fields(t.value)...)
			continue
		}
		if err := applyTerm(out, t, addExploit); err != nil {
			return nil, err
		}
	}
	if len(exploitOrder) > 0 {
		out.params.Set("exploit", strings.Join(exploitOrder, ","))
	}
	words = append(words, out.params["q"]...)
	out.params.Del("q")
	if len(words) > 0 {
		if len(words) > scMaxQWords {
			return nil, unsupported("a keyword search takes at most %d words (got %d: %s)", scMaxQWords, len(words), strings.Join(words, " "))
		}
		out.params.Set("q", strings.Join(words, " "))
	}
	return out, nil
}

var boolExploit = map[string]string{
	"is_kev":      "known_exploited",
	"is_vkev":     "vulncheck_known_exploited",
	"is_poc":      "public_exploit",
	"is_template": "nuclei_template",
	// SecurityContext signals template-service did not have
	"is_ransomware":     "ransomware",
	"is_initial_access": "initial_access",
}

var boolParam = map[string]string{
	"is_remote": "remote",
	"is_auth":   "authentication_required",
	"is_oss":    "oss",
}

// addWords appends keywords to q= (the 5-word limit is checked once all terms are read).
func addWords(out *scQuery, words []string) error {
	out.params["q"] = append(out.params["q"], words...)
	return nil
}

// datePeriod reads 2024, 2024-03 or 2024-03-05 as [start, end): the first day and the day after the period.
func datePeriod(d string) (string, string, bool) {
	for _, f := range []struct {
		layout string
		next   func(time.Time) time.Time
	}{
		{"2006-01-02", func(t time.Time) time.Time { return t.AddDate(0, 0, 1) }},
		{"2006-01", func(t time.Time) time.Time { return t.AddDate(0, 1, 0) }},
		{"2006", func(t time.Time) time.Time { return t.AddDate(1, 0, 0) }},
	} {
		if len(d) >= len(f.layout) {
			if t, err := time.Parse(f.layout, d[:len(f.layout)]); err == nil && (len(d) == len(f.layout) || f.layout == "2006-01-02") {
				return t.Format("2006-01-02"), f.next(t).Format("2006-01-02"), true
			}
		}
	}
	return "", "", false
}

func applyTerm(out *scQuery, t queryTerm, addExploit func(string, bool) error) error {
	field := strings.ToLower(t.field)
	v := t.value
	set := func(k, val string) error {
		if t.neg {
			return unsupported("NOT %s:%s is not supported", t.field, t.value)
		}
		if prev := out.params.Get(k); prev != "" && prev != val {
			return unsupported("%s is given twice (%s, %s); SecurityContext takes one value", t.field, prev, val)
		}
		out.params.Set(k, val)
		return nil
	}
	if kind, ok := boolExploit[field]; ok {
		b, err := parseBool(field, v)
		if err != nil {
			return err
		}
		return addExploit(kind, b == t.neg)
	}
	if p, ok := boolParam[field]; ok {
		b, err := parseBool(field, v)
		if err != nil {
			return err
		}
		if t.neg {
			b = !b
		}
		out.params.Set(p, strconv.FormatBool(b))
		return nil
	}
	switch field {
	case "cpe":
		if t.neg {
			return unsupported("NOT cpe: is not supported")
		}
		ref, err := parseCPE("cpe:" + v)
		if err != nil {
			return err
		}
		if out.cpe != nil && *out.cpe != *ref {
			return unsupported("one cpe: per search")
		}
		out.cpe = ref
		return nil
	case "cve_id", "id", "doc_id":
		if t.neg || !IsCVEID(v) {
			return unsupported("%s:%s: only CVE ids are served (template records without a CVE are not)", t.field, v)
		}
		out.ids = append(out.ids, strings.ToUpper(v))
		return nil
	case "severity":
		return set("severity", strings.ToLower(v))
	case "vuln_status", "nvd_status":
		st, err := nvdStatus(v)
		if err != nil {
			return err
		}
		return set("nvd_status", st)
	case "cwe", "cwe_id", "weaknesses.cwe_id":
		return set("cwe", strings.ToUpper(v))
	case "vendor", "affected_products.vendor":
		return set("vendor", strings.ToLower(v))
	case "product", "affected_products.product":
		if !strings.Contains(v, ":") {
			return unsupported("product:%s needs the vendor too (vendor:product, e.g. f5:nginx); or use --vendor", v)
		}
		return set("product", strings.ToLower(v))
	case "category", "affected_products.category":
		return set("category", strings.ToLower(v))
	case "deployment_model", "affected_products.deployment_model":
		return set("deployment_model", strings.ToLower(v))
	case "cvss_score", "epss_score":
		op, num, err := splitOp(v)
		if err != nil {
			return unsupported("%s:%s: %v", t.field, v, err)
		}
		if t.neg || (op != ">" && op != ">=") {
			return unsupported("%s takes a lower bound only (%s:>=N); SecurityContext has no upper bound or exact match", t.field, t.field)
		}
		if _, err := strconv.ParseFloat(num, 64); err != nil {
			return unsupported("%s:%s is not a number", t.field, v)
		}
		return set(map[string]string{"cvss_score": "min_cvss", "epss_score": "min_epss"}[field], num)
	case "age_in_days":
		op, num, err := splitOp(v)
		if err != nil {
			return unsupported("age_in_days:%s: %v", v, err)
		}
		n, err := strconv.Atoi(num)
		if err != nil || n < 0 {
			return unsupported("age_in_days:%s is not a whole number of days", v)
		}
		if t.neg {
			return unsupported("NOT age_in_days is not supported")
		}
		today := time.Now().UTC()
		day := func(d int) string { return today.AddDate(0, 0, -d).Format("2006-01-02") }
		switch op {
		case "<":
			return set("published_since", day(n-1))
		case "<=":
			return set("published_since", day(n))
		case ">":
			return set("published_before", day(n))
		case ">=":
			return set("published_before", day(n-1))
		default: // exactly n days old
			if err := set("published_since", day(n)); err != nil {
				return err
			}
			return set("published_before", day(n-1))
		}
	case "cve_created_at", "published_date", "published_at":
		op, d, err := splitOp(v)
		if err != nil || t.neg {
			return unsupported("%s:%s: give a year, month or date, optionally with < or > (%s:2024, %s:>2026-01-01)", t.field, v, t.field, t.field)
		}
		start, end, ok := datePeriod(d)
		if !ok {
			return unsupported("%s:%s: give a year, month or date, optionally with < or > (%s:2024, %s:>2026-01-01)", t.field, v, t.field, t.field)
		}
		switch op {
		case ">=":
			return set("published_since", start)
		case ">":
			return set("published_since", end)
		case "<":
			return set("published_before", start)
		case "<=":
			return set("published_before", end)
		default: // within that year, month or day
			if err := set("published_since", start); err != nil {
				return err
			}
			return set("published_before", end)
		}
	case "description", "name", "title", "summary":
		if t.neg {
			return unsupported("NOT %s is not supported", t.field)
		}
		return addWords(out, strings.Fields(v))
	}
	return unsupported("SecurityContext cannot filter on %q; run `vulnx filters` for the fields it can", t.field)
}

// applyOr handles an OR group: values of one field, or the --vendor / --product vendor-or-product pair.
func applyOr(out *scQuery, terms []queryTerm) error {
	field := strings.ToLower(terms[0].field)
	values := []string{}
	seen := map[string]bool{}
	productPair := true
	for _, t := range terms {
		if t.neg {
			return unsupported("NOT inside an OR group is not supported")
		}
		f := strings.ToLower(t.field)
		if f != "affected_products.product" && f != "affected_products.vendor" {
			productPair = false
		}
		if !seen[strings.ToLower(t.value)] {
			seen[strings.ToLower(t.value)] = true
			values = append(values, strings.ToLower(t.value))
		}
	}
	if productPair {
		if len(values) > 1 {
			return unsupported("one vendor or product per search (got %s); SecurityContext filters on one", strings.Join(values, ", "))
		}
		v := values[0]
		if strings.Contains(v, ":") {
			out.params.Set("product", v)
		} else {
			out.params.Set("vendor", v)
		}
		return nil
	}
	for _, t := range terms {
		if !strings.EqualFold(t.field, terms[0].field) {
			return unsupported("OR between different fields (%s, %s) is not supported", terms[0].field, t.field)
		}
	}
	switch field {
	case "severity":
		out.params.Set("severity", strings.Join(values, ","))
	case "vuln_status", "nvd_status":
		var sts []string
		for _, v := range values {
			st, err := nvdStatus(v)
			if err != nil {
				return err
			}
			sts = append(sts, st)
		}
		out.params.Set("nvd_status", strings.Join(sts, ","))
	case "category", "affected_products.category":
		out.params.Set("category", strings.Join(values, ","))
	case "deployment_model", "affected_products.deployment_model":
		out.params.Set("deployment_model", strings.Join(values, ","))
	case "cve_id", "id", "doc_id":
		for _, v := range values {
			if !IsCVEID(v) {
				return unsupported("%s:%s: only CVE ids are served", field, v)
			}
			out.ids = append(out.ids, strings.ToUpper(v))
		}
	case "":
		return unsupported("OR between keywords (%s) is not supported: keywords are all required; run one search per keyword", strings.Join(values, " || "))
	default:
		return unsupported("OR on %q is not supported (only severity, vuln_status, category, deployment_model, cve_id)", terms[0].field)
	}
	return nil
}

// nvdStatuses: NVD's status words (SecurityContext's nvd_status), and vulnx's earlier words for them.
var nvdStatuses = map[string]string{
	"analyzed": "analyzed", "modified": "modified", "deferred": "deferred", "received": "received",
	"awaiting_analysis": "awaiting_analysis", "undergoing_analysis": "undergoing_analysis",
	// template-service's vuln_status values
	"new": "received", "confirmed": "analyzed", "unconfirmed": "awaiting_analysis,undergoing_analysis",
	"unknown": "deferred",
}

func nvdStatus(v string) (string, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "rejected" {
		return "", unsupported("rejected CVEs are not in SecurityContext's searchable list (NVD-rejected CVEs leave it)")
	}
	if st, ok := nvdStatuses[v]; ok {
		return st, nil
	}
	return "", unsupported("vuln_status %q: use analyzed, modified, deferred, received, awaiting_analysis or undergoing_analysis (or new, confirmed, unconfirmed, unknown)", v)
}

func parseBool(field, v string) (bool, error) {
	b, err := strconv.ParseBool(strings.ToLower(strings.Trim(v, `"`)))
	if err != nil {
		return false, unsupported("%s takes true or false (got %q)", field, v)
	}
	return b, nil
}

func splitOp(v string) (string, string, error) {
	for _, op := range []string{">=", "<=", ">", "<"} {
		if strings.HasPrefix(v, op) {
			return op, strings.Trim(strings.TrimSpace(v[len(op):]), `"`), nil
		}
	}
	if strings.ContainsAny(v, "[]{}") || strings.Contains(v, " TO ") {
		return "", "", fmt.Errorf("ranges are not supported; use > or <")
	}
	return "", strings.Trim(v, `"`), nil
}

// orTerms splits one conjunct into its OR'd terms (flattening nested parentheses).
func orTerms(c string) ([]queryTerm, error) {
	c = strings.TrimSpace(c)
	for {
		inner, ok := stripParens(c)
		if !ok {
			break
		}
		c = strings.TrimSpace(inner)
	}
	parts, err := splitTop(c, "||")
	if err != nil {
		return nil, err
	}
	if len(parts) == 1 {
		if strings.Contains(c, "(") && !strings.HasPrefix(strings.TrimSpace(strings.TrimPrefix(c, "NOT ")), `"`) {
			if inner, ok := stripParens(strings.TrimSpace(strings.TrimPrefix(c, "NOT "))); ok && strings.HasPrefix(c, "NOT ") {
				_ = inner
				return nil, unsupported("NOT on a group is not supported")
			}
		}
		t, err := parseTerm(c)
		if err != nil {
			return nil, err
		}
		return []queryTerm{t}, nil
	}
	var out []queryTerm
	for _, p := range parts {
		sub, err := orTerms(p)
		if err != nil {
			return nil, err
		}
		out = append(out, sub...)
	}
	return out, nil
}

var termPattern = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_.]*):(.+)$`)

func parseTerm(s string) (queryTerm, error) {
	s = strings.TrimSpace(s)
	t := queryTerm{}
	switch {
	case strings.HasPrefix(s, "NOT "):
		t.neg, s = true, strings.TrimSpace(s[4:])
	case strings.HasPrefix(s, "!"), strings.HasPrefix(s, "-") && strings.Contains(s, ":"):
		t.neg, s = true, strings.TrimSpace(s[1:])
	}
	if strings.ContainsAny(s, "()") {
		return t, unsupported("could not read %q (nested groups beyond AND of ORs are not supported)", s)
	}
	if m := termPattern.FindStringSubmatch(s); m != nil && !strings.HasPrefix(s, `"`) && !strings.HasPrefix(s, "'") {
		t.field, t.value = m[1], strings.Trim(strings.TrimSpace(m[2]), `"'`)
		if strings.ToLower(t.field) != "cpe" && strings.ContainsAny(t.value, "*?") {
			return t, unsupported("wildcards (%s) are not supported", s)
		}
		return t, nil
	}
	if strings.ContainsAny(s, "*?~") {
		return t, unsupported("wildcards and fuzzy terms (%s) are not supported", s)
	}
	t.value = strings.Trim(s, `"'`)
	return t, nil
}

// splitTop splits s on op outside parentheses and quotes.
func splitTop(s, op string) ([]string, error) {
	var parts []string
	depth, inQuote, start := 0, false, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"', '\'':
			inQuote = !inQuote
		case '(':
			if !inQuote {
				depth++
			}
		case ')':
			if !inQuote {
				depth--
				if depth < 0 {
					return nil, unsupported("unbalanced parentheses in %q", s)
				}
			}
		default:
			if !inQuote && depth == 0 && strings.HasPrefix(s[i:], op) {
				parts = append(parts, s[start:i])
				start = i + len(op)
				i += len(op) - 1
			}
		}
	}
	if depth != 0 || inQuote {
		return nil, unsupported("unbalanced parentheses or quotes in %q", s)
	}
	parts = append(parts, s[start:])
	// a top-level " AND " / " OR " written as words
	if op == "&&" && len(parts) == 1 && strings.Contains(s, " AND ") {
		return splitTop(strings.ReplaceAll(s, " AND ", " && "), op)
	}
	if op == "||" && len(parts) == 1 && strings.Contains(s, " OR ") {
		return splitTop(strings.ReplaceAll(s, " OR ", " || "), op)
	}
	return parts, nil
}

// stripParens removes one pair of parentheses that wraps the whole of s.
func stripParens(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "(") || !strings.HasSuffix(s, ")") {
		return s, false
	}
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 && i != len(s)-1 {
				return s, false
			}
		}
	}
	return s[1 : len(s)-1], true
}

// sortParam maps vulnx's sort fields to /v1/cves sort keys.
func sortParam(asc, desc *string) (string, error) {
	field, dir := "", ""
	switch {
	case asc != nil && *asc != "":
		field, dir = *asc, "asc"
	case desc != nil && *desc != "":
		field, dir = *desc, "desc"
	default:
		return "", nil
	}
	key, ok := map[string]string{
		"cve_created_at": "published_date", "published_date": "published_date", "created_at": "published_date",
		"age_in_days":    "published_date",
		"cve_updated_at": "modified_date", "modified_date": "modified_date", "updated_at": "modified_date",
		"cvss_score": "cvss_score", "epss_score": "epss_score", "trending": "trending", "repositories": "repositories",
	}[strings.ToLower(field)]
	if !ok {
		return "", unsupported("SecurityContext sorts by cve_created_at, cve_updated_at, cvss_score, epss_score, trending or repositories (not %s)", field)
	}
	if strings.ToLower(field) == "age_in_days" { // the youngest first is the newest published first
		if dir == "asc" {
			dir = "desc"
		} else {
			dir = "asc"
		}
	}
	return key + ":" + dir, nil
}

// facetMap maps a vulnx facet field to a /v1/cves facet and, for the exploit flags, the exploit kind it reads.
var facetMap = map[string]struct{ facet, kind string }{
	"severity":                           {"severity", ""},
	"vendor":                             {"vendor", ""},
	"affected_products.vendor":           {"vendor", ""},
	"cwe":                                {"cwe", ""},
	"weaknesses.cwe_id":                  {"cwe", ""},
	"vuln_status":                        {"nvd_status", ""},
	"nvd_status":                         {"nvd_status", ""},
	"is_remote":                          {"remote", ""},
	"is_auth":                            {"authentication_required", ""},
	"category":                           {"category", ""},
	"affected_products.category":         {"category", ""},
	"deployment_model":                   {"deployment_model", ""},
	"affected_products.deployment_model": {"deployment_model", ""},
	"year":                               {"year", ""},
	"exploit":                            {"exploit", ""},
	"is_kev":                             {"exploit", "known_exploited"},
	"is_vkev":                            {"exploit", "vulncheck_known_exploited"},
	"is_poc":                             {"exploit", "public_exploit"},
	"is_template":                        {"exploit", "nuclei_template"},
}

type facetReq struct {
	name, facet, kind string
	size              int
}

func translateFacets(term, rangeFacets []string, defaultSize int) ([]facetReq, string, error) {
	if len(rangeFacets) > 0 {
		return nil, "", unsupported("range facets are not supported by SecurityContext")
	}
	var reqs []facetReq
	dims := []string{}
	seen := map[string]bool{}
	for _, f := range term {
		f = strings.ReplaceAll(strings.TrimSpace(f), "=", ":")
		name, sizeStr, _ := strings.Cut(f, ":")
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		size := defaultSize
		if n, err := strconv.Atoi(strings.TrimSpace(sizeStr)); err == nil && n > 0 {
			size = n
		}
		m, ok := facetMap[strings.ToLower(name)]
		if !ok {
			names := make([]string, 0, len(facetMap))
			for k := range facetMap {
				if !strings.Contains(k, ".") {
					names = append(names, k)
				}
			}
			sort.Strings(names)
			return nil, "", unsupported("SecurityContext cannot facet on %q (it can on %s)", name, strings.Join(names, ", "))
		}
		reqs = append(reqs, facetReq{name: name, facet: m.facet, kind: m.kind, size: size})
		if !seen[m.facet] {
			seen[m.facet] = true
			dims = append(dims, m.facet)
		}
	}
	if len(dims) > scMaxFacets {
		return nil, "", unsupported("at most %d facets per search (asked: %s)", scMaxFacets, strings.Join(dims, ", "))
	}
	return reqs, strings.Join(dims, ","), nil
}

// buildFacets renders /v1/cves facets as vulnx's {name: {"buckets": [{key, count}]}}.
func buildFacets(reqs []facetReq, sc map[string][]scBucket, total int) map[string]any {
	if len(reqs) == 0 {
		return nil
	}
	out := map[string]any{}
	for _, r := range reqs {
		var buckets []map[string]any
		if r.kind != "" { // is_kev and friends: true / false from the exploit facet
			n := 0
			for _, b := range sc[r.facet] {
				if fmt.Sprint(b.Value) == r.kind {
					n = b.Count
				}
			}
			buckets = []map[string]any{{"key": "true", "count": float64(n)}, {"key": "false", "count": float64(total - n)}}
		} else {
			for _, b := range sc[r.facet] {
				if r.size > 0 && len(buckets) >= r.size {
					break // SecurityContext answers up to 50 buckets, largest first
				}
				buckets = append(buckets, map[string]any{"key": fmt.Sprint(b.Value), "count": float64(b.Count)})
			}
		}
		anyBuckets := make([]any, len(buckets))
		for i := range buckets {
			anyBuckets[i] = buckets[i]
		}
		out[r.name] = map[string]any{"buckets": anyBuckets}
	}
	return out
}

// ---------------------------------------------------------------------------------------------------------------
// --fields: the JSON answer keeps only the fields asked for (template-service narrowed server side; SecurityContext's
// field names differ, so vulnx narrows its own records). CSV output reads Results directly and keeps every column.

// MarshalJSON writes the response with each result narrowed to Fields, when set.
func (r SearchResponse) MarshalJSON() ([]byte, error) {
	type plain SearchResponse
	if len(r.fields) == 0 {
		return json.Marshal(plain(r))
	}
	keep := map[string]bool{}
	for _, f := range r.fields {
		keep[strings.TrimSpace(f)] = true
	}
	results := make([]map[string]json.RawMessage, 0, len(r.Results))
	for i := range r.Results {
		b, err := json.Marshal(r.Results[i])
		if err != nil {
			return nil, err
		}
		var all map[string]json.RawMessage
		if err := json.Unmarshal(b, &all); err != nil {
			return nil, err
		}
		row := map[string]json.RawMessage{}
		for k, v := range all {
			if keep[k] {
				row[k] = v
			}
		}
		results = append(results, row)
	}
	return json.Marshal(struct {
		Count   int                          `json:"count"`
		Facets  map[string]any               `json:"facets,omitempty"`
		Results []map[string]json.RawMessage `json:"results"`
		Total   int                          `json:"total"`
	}{r.Count, r.Facets, results, r.Total})
}

// ---------------------------------------------------------------------------------------------------------------
// SecurityContext records

type scBucket struct {
	Value any `json:"value"`
	Count int `json:"count"`
}

type scList struct {
	Count  int                   `json:"count"`
	Total  int                   `json:"total"`
	Items  []scCVE               `json:"items"`
	Cursor string                `json:"cursor"`
	Facets map[string][]scBucket `json:"facets"`
}

type scExploitation struct {
	KnownExploited         bool     `json:"known_exploited"`
	KnownExploitedBy       []string `json:"known_exploited_by"`
	ExploitationSeen       bool     `json:"exploitation_seen"`
	PublicExploit          bool     `json:"public_exploit"`
	PublicExploitCount     int      `json:"public_exploit_count"`
	PublicExploitFirstDate string   `json:"public_exploit_first_date"`
	NucleiTemplate         *struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	} `json:"nuclei_template"`
	InitialAccess          bool  `json:"initial_access"`
	Remote                 *bool `json:"remote"`
	AuthenticationRequired *bool `json:"authentication_required"`
	HackeroneReports       *int  `json:"hackerone_reports"`
	ExposedHosts           *int  `json:"exposed_hosts"`
}

type scCVE struct {
	CVE                 string          `json:"cve"`
	Name                string          `json:"name"`
	Description         string          `json:"description"`
	Impact              string          `json:"impact"`
	Remediation         string          `json:"remediation"`
	VulnerabilityType   string          `json:"vulnerability_type"`
	VulnerabilityImpact []string        `json:"vulnerability_impact"`
	RequirementType     string          `json:"requirement_type"`
	Requirements        string          `json:"requirements"`
	Severity            string          `json:"severity"`
	CvssScore           float64         `json:"cvss_score"`
	CvssVector          string          `json:"cvss_vector"`
	EpssScore           float64         `json:"epss_score"`
	EpssPercentile      float64         `json:"epss_percentile"`
	CWE                 json.RawMessage `json:"cwe"`
	Assignee            string          `json:"assignee"`
	PublishedDate       string          `json:"published_date"`
	ModifiedDate        string          `json:"modified_date"`
	PublishedAt         string          `json:"published_at"`
	ModifiedAt          string          `json:"modified_at"`
	AgeInDays           int             `json:"age_in_days"`
	PatchAvailable      bool            `json:"patch_available"`
	NVDStatus           string          `json:"nvd_status"`
	OSS                 bool            `json:"oss"`
	ProductKeys         []string        `json:"product_keys"`
	Exploitation        *scExploitation `json:"exploitation"`
	KnownExploited      []struct {
		List          string `json:"list"`
		AddedDate     string `json:"added_date"`
		DueDate       string `json:"due_date"`
		RansomwareUse bool   `json:"ransomware_use"`
	} `json:"known_exploited_entries"`
	NucleiTemplates []struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	} `json:"nuclei_templates"`
	Hackerone *struct {
		Reports int `json:"reports"`
		Rank    int `json:"rank"`
	} `json:"hackerone"`
	PublicExploits []struct {
		URL       string `json:"url"`
		Source    string `json:"source"`
		AddedDate string `json:"added_date"`
	} `json:"public_exploits"`
	PublicExploitsTotal int `json:"public_exploits_total"`
	References          []struct {
		URL    string   `json:"url"`
		Source string   `json:"source"`
		Tags   []string `json:"tags"`
	} `json:"references"`
	Products    json.RawMessage `json:"products"` // a count on a list row, [{product, ...}] on a record
	AdvisoryURL string          `json:"advisory_url"`
}

func scTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return &t
		}
	}
	return nil
}

func splitProductKey(key string) (string, string) {
	vendor, product, ok := strings.Cut(key, ":")
	if !ok {
		return "", key
	}
	return vendor, product
}

// toVulnerability turns a /v1/cves row or record into vulnx's Vulnerability.
func (r *scCVE) toVulnerability() Vulnerability {
	v := Vulnerability{
		CVEID: r.CVE, DocID: r.CVE, DocType: "cve", ID: r.CVE,
		Name: r.Name, Description: r.Description, Impact: r.Impact, Remediation: r.Remediation,
		VulnerabilityType: r.VulnerabilityType, VulnerabilityImpact: r.VulnerabilityImpact,
		RequirementType: r.RequirementType, Requirements: r.Requirements,
		Severity: r.Severity, CvssScore: r.CvssScore, CvssMetrics: r.CvssVector,
		EpssScore: r.EpssScore, EpssPercentile: r.EpssPercentile,
		Assignee: r.Assignee, AgeInDays: r.AgeInDays, IsPatchAvailable: r.PatchAvailable,
		VulnStatus: r.NVDStatus, IsOss: r.OSS,
	}
	if v.Name == "" {
		v.Name = r.CVE
	}
	v.CveCreatedAt = scTime(firstNonEmpty(r.PublishedAt, r.PublishedDate))
	v.CveUpdatedAt = scTime(firstNonEmpty(r.ModifiedAt, r.ModifiedDate))
	v.CreatedAt, v.UpdatedAt = v.CveCreatedAt, v.CveUpdatedAt
	if v.AgeInDays == 0 && v.CveCreatedAt != nil { // a version list's rows carry the date, not the age
		v.AgeInDays = int(time.Now().UTC().Sub(*v.CveCreatedAt).Hours() / 24)
	}

	// cwe: ["CWE-79"] on a list row, [{id, name}] on a record
	var ids []string
	var named []struct{ ID, Name string }
	if json.Unmarshal(r.CWE, &ids) != nil {
		if json.Unmarshal(r.CWE, &named) == nil {
			for _, c := range named {
				ids = append(ids, c.ID)
				v.Weaknesses = append(v.Weaknesses, &Weakness{CweID: c.ID, CweName: c.Name})
			}
		}
	}
	v.Cwe = ids

	if e := r.Exploitation; e != nil {
		for _, by := range e.KnownExploitedBy {
			switch by {
			case "cisa":
				v.IsKev = true
			case "vulncheck":
				v.IsVkev = true
			}
		}
		v.IsPoc = e.PublicExploit
		v.PocCount = e.PublicExploitCount
		v.PocFirstSeen = scTime(e.PublicExploitFirstDate)
		if e.NucleiTemplate != nil {
			v.IsTemplate = true
			v.URI = e.NucleiTemplate.URL
		}
		if e.Remote != nil {
			v.IsRemote = *e.Remote
		}
		if e.AuthenticationRequired != nil {
			v.IsAuth = *e.AuthenticationRequired
		}
		if e.HackeroneReports != nil && *e.HackeroneReports > 0 {
			v.H1 = &H1Stats{Reports: *e.HackeroneReports}
		}
		if e.ExposedHosts != nil && *e.ExposedHosts > 0 {
			v.Exposure = &VulnExposure{MaxHosts: *e.ExposedHosts, MinHosts: *e.ExposedHosts}
		}
	}
	for _, k := range r.KnownExploited {
		v.Kev = append(v.Kev, &KevInfo{Source: k.List, AddedDate: scTime(k.AddedDate), DueDate: scTime(k.DueDate),
			KnownRansomwareCampaignUse: k.RansomwareUse})
		switch k.List {
		case "cisa":
			v.IsKev = true
		case "vulncheck":
			v.IsVkev = true
		}
	}
	if len(r.NucleiTemplates) > 0 {
		v.IsTemplate = true
		v.URI = r.NucleiTemplates[0].URL
	}
	if r.Hackerone != nil && r.Hackerone.Reports > 0 {
		v.H1 = &H1Stats{Reports: r.Hackerone.Reports, Rank: r.Hackerone.Rank}
	}
	for _, p := range r.PublicExploits {
		v.Pocs = append(v.Pocs, &POC{URL: p.URL, Source: p.Source, AddedAt: scTime(p.AddedDate)})
	}
	if r.PublicExploitsTotal > v.PocCount {
		v.PocCount = r.PublicExploitsTotal
	}
	if len(v.Pocs) > 0 {
		v.IsPoc = true
	}
	for _, ref := range r.References {
		v.Citations = append(v.Citations, &Citation{URL: ref.URL, Source: ref.Source, Tags: ref.Tags})
	}
	keys := r.ProductKeys
	var products []struct {
		Product string `json:"product"`
	}
	if json.Unmarshal(r.Products, &products) == nil {
		for _, p := range products {
			keys = append(keys, p.Product)
		}
	}
	seen := map[string]bool{}
	for _, key := range keys {
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		vendor, product := splitProductKey(key)
		v.AffectedProducts = append(v.AffectedProducts, &ProductInfo{Vendor: vendor, Product: product})
	}
	if len(v.AffectedProducts) > 0 {
		v.Vendor, v.Product = v.AffectedProducts[0].Vendor, v.AffectedProducts[0].Product
	}
	return v
}

func firstNonEmpty(vals ...string) string {
	for _, s := range vals {
		if s != "" {
			return s
		}
	}
	return ""
}

// ---------------------------------------------------------------------------------------------------------------
// Filters (`vulnx filters`): what the SecurityContext backend accepts, built in (the API has no /filters endpoint)

// SupportedFilters lists the query fields vulnx translates to /v1/cves.
func SupportedFilters() []VulnerabilityFilter {
	b := func(field, desc string, facet bool) VulnerabilityFilter {
		return VulnerabilityFilter{Field: field, DataType: "boolean", Description: desc, FacetPossible: facet,
			Examples: []string{field + ":true", field + ":false"}, EnumValues: []string{"true", "false"}}
	}
	return []VulnerabilityFilter{
		{Field: "cve_id", DataType: "string", Description: "A CVE id (only CVE records are served)", Examples: []string{"cve_id:CVE-2021-44228"}},
		{Field: "cpe", DataType: "string", Description: "CVEs affecting one product version (search --cpe, or --product vendor:product --version v)", Examples: []string{"cpe:2.3:a:apache:tomcat:8.5.62:*:*:*:*:*:*:*"}},
		{Field: "severity", DataType: "enum", Description: "Severity; several values with ||", FacetPossible: true,
			Examples: []string{"severity:critical", "(severity:critical || severity:high)"}, EnumValues: []string{"critical", "high", "medium", "low", "none"}},
		b("is_kev", "In CISA's Known Exploited Vulnerabilities list (VulnCheck's list, which includes every CISA entry: is_vkev)", true),
		b("is_vkev", "In VulnCheck's KEV list", true),
		b("is_poc", "Has a public exploit or proof of concept", true),
		b("is_template", "Has a nuclei template", true),
		b("is_ransomware", "A KEV entry records known ransomware use", false),
		b("is_initial_access", "VulnCheck lists an initial-access exploit", false),
		b("is_remote", "Exploitable over the network (CVSS attack vector)", true),
		b("is_auth", "Needs authentication (CVSS privileges required)", true),
		b("is_oss", "Filed against open-source code, or reaches it through a package", false),
		{Field: "cvss_score", DataType: "number", Description: "CVSS score, lower bound only", CanSort: true, Examples: []string{"cvss_score:>=9"}},
		{Field: "epss_score", DataType: "number", Description: "EPSS score, lower bound only", CanSort: true, Examples: []string{"epss_score:>0.5"}},
		{Field: "age_in_days", DataType: "number", Description: "Days since publication (<N, >N or exact)", CanSort: true, Examples: []string{"age_in_days:<30"}},
		{Field: "cve_created_at", DataType: "date", Description: "Publication date, with < or >", CanSort: true, Examples: []string{"cve_created_at:>2026-01-01"}},
		{Field: "cve_updated_at", DataType: "date", Description: "Last modification date (sort only)", CanSort: true},
		{Field: "vuln_status", DataType: "enum", Description: "NVD's status", FacetPossible: true, Examples: []string{"vuln_status:analyzed"}},
		{Field: "cwe", DataType: "string", Description: "A CWE id", FacetPossible: true, Examples: []string{"cwe:CWE-79"}},
		{Field: "vendor", DataType: "string", Description: "One vendor (NVD's name)", FacetPossible: true, Examples: []string{"vendor:apache"}},
		{Field: "product", DataType: "string", Description: "One product as vendor:product", Examples: []string{"product:apache:log4j"}},
		{Field: "category", DataType: "string", Description: "Product category", FacetPossible: true, Examples: []string{"category:web_server"}},
		{Field: "deployment_model", DataType: "string", Description: "Product deployment model", FacetPossible: true, Examples: []string{"deployment_model:self_hosted"}},
		{Field: "trending", DataType: "number", Description: "Social trending score (sort only)", CanSort: true},
		{Field: "year", DataType: "number", Description: "Publication year (facet only)", FacetPossible: true},
	}
}
