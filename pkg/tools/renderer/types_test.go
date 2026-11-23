package renderer

import (
	"testing"

	"github.com/projectdiscovery/vulnx/v2"
)

func TestFromVulnerabilityCleansText(t *testing.T) {
	v := &vulnx.Vulnerability{
		DocID:            "CVE-2021-44228",
		Name:             "Log4Shell\x1b[2J",
		Description:      "line one\nline\u202etwo",
		AffectedProducts: []*vulnx.ProductInfo{{Vendor: "apache\x07", Product: "log4j"}},
		Pocs:             []*vulnx.POC{{URL: "https://example.com/\x1b]8;;x\x1b\\"}},
	}
	e := FromVulnerability(v)
	if e.Name != "Log4Shell[2J" || e.Description != "line one\nlinetwo" {
		t.Errorf("name %q description %q", e.Name, e.Description)
	}
	if e.AffectedProducts[0].Vendor != "apache" || e.Pocs[0].URL != "https://example.com/]8;;x\\" {
		t.Errorf("nested text not cleaned: %q %q", e.AffectedProducts[0].Vendor, e.Pocs[0].URL)
	}
	if v.AffectedProducts[0].Vendor != "apache\x07" {
		t.Errorf("FromVulnerability modified its input")
	}
}
