package clis

import (
	"math"
	"slices"
	"testing"
)

func TestMergeFields(t *testing.T) {
	base := []string{"doc_id", "cve_id"}
	got := mergeFields(base, []string{"doc_id", "severity"})
	if want := []string{"doc_id", "cve_id", "severity"}; !slices.Equal(got, want) {
		t.Errorf("mergeFields = %v, want %v", got, want)
	}
	if len(base) != 2 {
		t.Errorf("mergeFields mutated base: %v", base)
	}
}

func TestValidateSearchInputs(t *testing.T) {
	origLimit, origOffset, origAll, origFacet := searchLimit, searchOffset, searchAll, searchFacetSize
	t.Cleanup(func() {
		searchLimit, searchOffset, searchAll, searchFacetSize = origLimit, origOffset, origAll, origFacet
	})

	tests := []struct {
		name          string
		offset, limit int
		all           bool
		facetSize     int
		wantErr       bool
	}{
		{"defaults", 0, 10, false, 10, false},
		{"full window", 0, 1000, false, 10, false},
		{"last page", 990, 10, false, 10, false},
		{"one past window", 991, 10, false, 10, true},
		{"limit over cap", 0, 1001, false, 10, true},
		{"zero limit", 0, 0, false, 10, true},
		{"negative offset", -1, 10, false, 10, true},
		{"all ignores the window", 5000, 10, true, 10, false},
		{"all ignores a zero limit", 0, 0, true, 10, false},
		{"all ignores a limit over the cap", 0, 1001, true, 10, false},
		{"huge offset cannot wrap", math.MaxInt, 10, false, 10, true},
		{"facet size at cap", 0, 10, false, 50, false},
		{"facet size over cap", 0, 10, false, 51, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			searchOffset, searchLimit, searchAll, searchFacetSize = tt.offset, tt.limit, tt.all, tt.facetSize
			if err := validateSearchInputs(); (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestBuildFilterQuery(t *testing.T) {
	reset := func() {
		filterProduct, filterVendor, filterVersion, filterCPE = "", "", "", ""
		filterSeverity, filterVulnStatus, filterVulnAge = nil, "", ""
		filterKevOnly, filterTemplate, filterPOC, filterRemoteExploit = "", "", "", ""
		filterCvssScore, filterEpssScore = "", ""
	}
	t.Cleanup(reset)
	tests := []struct {
		name    string
		set     func()
		want    string
		wantErr bool
	}{
		{"none", func() {}, "", false},
		{"product", func() { filterProduct = "apache:log4j" }, "product:apache:log4j", false},
		{"product version", func() { filterProduct, filterVersion = "Apache:Tomcat", "8.5.62" }, "cpe:2.3:a:apache:tomcat:8.5.62:*:*:*:*:*:*:*", false},
		{"version without vendor", func() { filterProduct, filterVersion = "tomcat", "8.5.62" }, "", true},
		{"bad cpe", func() { filterCPE = "apache:tomcat" }, "", true},
		{"severities", func() { filterSeverity = []string{"critical", " high"} }, "(severity:critical || severity:high)", false},
		{"booleans", func() { filterKevOnly, filterRemoteExploit = "true", "FALSE" }, "is_kev:true && is_remote:false", false},
		{"bad boolean", func() { filterPOC = "yes" }, "", true},
		{"scores and age", func() { filterCvssScore, filterVulnAge = ">=7", "<30" }, "age_in_days:<30 && cvss_score:>=7", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reset()
			tt.set()
			got, err := buildFilterQuery()
			if (err != nil) != tt.wantErr || got != tt.want {
				t.Errorf("got %q, %v; want %q, wantErr %v", got, err, tt.want, tt.wantErr)
			}
		})
	}
}
