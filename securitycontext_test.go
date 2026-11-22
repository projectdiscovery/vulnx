package vulnx

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/utils/errkit"
)

func TestTranslateQuery(t *testing.T) {
	day := func(d int) string { return time.Now().UTC().AddDate(0, 0, -d).Format("2006-01-02") }
	cases := []struct {
		q    string
		want map[string]string
		ids  int
	}{
		{"", map[string]string{}, 0},
		{"log4j rce", map[string]string{"q": "log4j rce"}, 0},
		{"is_kev:true", map[string]string{"exploit": "known_exploited"}, 0},
		{"is_kev:false && is_poc:true", map[string]string{"exploit": "-known_exploited,public_exploit"}, 0},
		{"NOT is_template:true", map[string]string{"exploit": "-nuclei_template"}, 0},
		{"(severity:critical || severity:high)", map[string]string{"severity": "critical,high"}, 0},
		{"affected_products.vendor:apache", map[string]string{"vendor": "apache"}, 0},
		{"affected_products.product:apache:log4j", map[string]string{"product": "apache:log4j"}, 0},
		{"(product:apache:log4j || product:Apache:Log4j)", map[string]string{"product": "apache:log4j"}, 0},
		{"cvss_score:>=9 && epss_score:>=0.5", map[string]string{"min_cvss": "9", "min_epss": "0.5"}, 0},
		{"severity:high && (severity:high || severity:high)", map[string]string{"severity": "high"}, 0},
		{"age_in_days:<30", map[string]string{"published_since": day(29)}, 0},
		{"age_in_days:>365", map[string]string{"published_before": day(365)}, 0},
		{"is_remote:true && is_auth:false", map[string]string{"remote": "true", "authentication_required": "false"}, 0},
		{"vuln_status:analyzed", map[string]string{"nvd_status": "analyzed"}, 0},
		{"(xss) && (is_kev:true && severity:high)", map[string]string{"q": "xss", "exploit": "known_exploited", "severity": "high"}, 0},
		{"cve_id:CVE-2021-44228", map[string]string{}, 1},
		{"(cve_id:CVE-2021-44228 || cve_id:CVE-2023-4966)", map[string]string{}, 2},
		{"cve_created_at:>=2026-01-01", map[string]string{"published_since": "2026-01-01"}, 0},
	}
	for _, c := range cases {
		got, err := translateQuery(c.q)
		if err != nil {
			t.Errorf("%q: %v", c.q, err)
			continue
		}
		if len(got.params) != len(c.want) {
			t.Errorf("%q: params %v, want %v", c.q, got.params, c.want)
		}
		for k, v := range c.want {
			if got.params.Get(k) != v {
				t.Errorf("%q: %s=%q, want %q", c.q, k, got.params.Get(k), v)
			}
		}
		if len(got.ids) != c.ids {
			t.Errorf("%q: ids %v, want %d", c.q, got.ids, c.ids)
		}
	}
}

func TestTranslateQueryRejects(t *testing.T) {
	for _, q := range []string{
		"tags:wordpress",
		"vulnerability_type:sqli",
		"cvss_score:<5",
		"(affected_products.vendor:a || affected_products.vendor:b)",
		"severity:high || is_kev:true",
		"(affected_products.product:apache || affected_products.vendor:apache)",
		"(product:f5:nginx || product:nginx:nginx)",
		"product:nginx && product:tomcat",
		"severity:critical && (severity:high || severity:low)",
		"(severity:high || severity:low) && severity:critical",
		"cvss_score:>7",
		"epss_score:>0.5",
		"cvss_score:7",
		"NOT (severity:high || severity:low)",
		"NOT (is_kev:true && is_poc:true)",
		"cve_id:php-xdebug-rce",
		"one two three four five six",
		"name:wordp*",
		"h1.reports:>0",
		"is_kev:true && is_kev:false",
		"(severity:high",
	} {
		_, err := translateQuery(q)
		if err == nil {
			t.Errorf("%q: accepted, want an error", q)
			continue
		}
		if !errors.Is(err, ErrUnsupportedQuery) && !errkit.Is(err, ErrUnsupportedQuery) {
			t.Errorf("%q: %v is not ErrUnsupportedQuery", q, err)
		}
	}
}

func TestSortAndFacets(t *testing.T) {
	s := func(v string) *string { return &v }
	if got, _ := sortParam(nil, s("cve_created_at")); got != "published_date:desc" {
		t.Errorf("sort cve_created_at desc: %q", got)
	}
	if got, _ := sortParam(s("age_in_days"), nil); got != "published_date:desc" {
		t.Errorf("sort age asc (youngest first): %q", got)
	}
	if _, err := sortParam(nil, s("poc_count")); err == nil {
		t.Error("sort poc_count accepted")
	}
	reqs, dims, err := translateFacets([]string{"severity:5", "is_kev", "is_poc", "affected_products.vendor:10"}, nil, 10)
	if err != nil || dims != "severity,exploit,vendor" || len(reqs) != 4 {
		t.Fatalf("facets: %v %q %v", reqs, dims, err)
	}
	f := buildFacets(reqs, map[string][]scBucket{
		"severity": {{Value: "critical", Count: 3}},
		"exploit":  {{Value: "known_exploited", Count: 2}},
	}, 10)
	kev := f["is_kev"].(map[string]any)["buckets"].([]any)
	if kev[0].(map[string]any)["count"].(float64) != 2 || kev[1].(map[string]any)["count"].(float64) != 8 {
		t.Errorf("is_kev buckets: %v", kev)
	}
	if _, _, err := translateFacets([]string{"tags"}, nil, 0); err == nil {
		t.Error("facet tags accepted")
	}
	if _, _, err := translateFacets([]string{"severity", "cwe", "vendor", "year"}, nil, 0); err == nil {
		t.Error("4 facets accepted")
	}
}

func TestTranslateDatesAndPhrases(t *testing.T) {
	cases := map[string]map[string]string{
		"cve_created_at:2024":                          {"published_since": "2024-01-01", "published_before": "2025-01-01"},
		"cve_created_at:2024-02":                       {"published_since": "2024-02-01", "published_before": "2024-03-01"},
		"cve_created_at:>=2024":                        {"published_since": "2024-01-01"},
		"cve_created_at:<2024":                         {"published_before": "2024-01-01"},
		"cve_created_at:>2026-01-01":                   {"published_since": "2026-01-02"},
		"description:'SQL injection' && severity:high": {"q": "SQL injection", "severity": "high"},
		"'buffer overflow' && severity:high":           {"q": "buffer overflow", "severity": "high"},
	}
	for q, want := range cases {
		got, err := translateQuery(q)
		if err != nil {
			t.Errorf("%q: %v", q, err)
			continue
		}
		for k, v := range want {
			if got.params.Get(k) != v {
				t.Errorf("%q: %s=%q, want %q (all: %v)", q, k, got.params.Get(k), v, got.params)
			}
		}
		if len(got.params) != len(want) {
			t.Errorf("%q: params %v, want %v", q, got.params, want)
		}
	}
}

func TestCPETerms(t *testing.T) {
	for in, want := range map[string]cpeRef{
		"cpe:2.3:a:apache:tomcat:8.5.62:*:*:*:*:*:*:*":                       {"apache", "tomcat", "8.5.62"},
		"cpe:/a:jquery:jquery:1.11.3":                                        {"jquery", "jquery", "1.11.3"},
		"(cpe:2.3:a:apache:http_server:1.3.13:*:*:*:*:*:*:*) && is_kev:true": {"apache", "http_server", "1.3.13"},
	} {
		q, err := translateQuery(in)
		if err != nil || q.cpe == nil || *q.cpe != want {
			t.Errorf("%s: %+v %v", in, q, err)
		}
	}
	for _, bad := range []string{"cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*", "cpe:2.3:a:apache", "NOT cpe:/a:x:y:1"} {
		if _, err := translateQuery(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestTranslateProductName(t *testing.T) {
	for q, want := range map[string]string{
		"product:tomcat":                         "tomcat",
		"affected_products.product:Log4j":        "log4j",
		"(product:nginx) && (severity:critical)": "nginx",
	} {
		got, err := translateQuery(q)
		if err != nil {
			t.Errorf("%q: %v", q, err)
			continue
		}
		if got.productName != want || got.params.Get("vendor") != "" || got.params.Get("product") != "" {
			t.Errorf("%q: productName %q params %v, want productName %q", q, got.productName, got.params, want)
		}
	}
}

func TestScoreGreaterThanMessage(t *testing.T) {
	_, err := translateQuery("cvss_score:>7")
	if err == nil || !strings.Contains(err.Error(), "cvss_score:>=7") {
		t.Errorf("cvss_score:>7: %v, want a hint to use cvss_score:>=7", err)
	}
}

func TestMarshalJSONFields(t *testing.T) {
	resp := SearchResponse{Count: 1, Total: 1, fields: []string{"cve_id", "h1.reports", "affected_products.vendor", "missing.path"},
		Results: []Vulnerability{{CVEID: "CVE-2021-44228", Severity: "critical", H1: &H1Stats{Reports: 3, Rank: 7},
			AffectedProducts: []*ProductInfo{{Vendor: "apache", Product: "log4j"}, {Vendor: "cisco", Product: "ios"}}}}}
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Results []map[string]any `json:"results"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	row := got.Results[0]
	want := map[string]any{
		"cve_id":            "CVE-2021-44228",
		"h1":                map[string]any{"reports": float64(3)},
		"affected_products": []any{map[string]any{"vendor": "apache"}, map[string]any{"vendor": "cisco"}},
	}
	if !reflect.DeepEqual(row, want) {
		t.Errorf("narrowed row %v, want %v", row, want)
	}

	resp.fields = []string{"h1.reports", "h1"}
	b, err = json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"h1":{"rank":7,"reports":3}`) {
		t.Errorf("h1 with h1.reports should keep the whole object: %s", b)
	}
}
