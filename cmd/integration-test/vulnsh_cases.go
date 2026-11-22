package main

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/vulnx/v2/pkg/testutils"
)

// VulnxTestCase runs vulnx with Args and checks its exit status and stdout.
type VulnxTestCase struct {
	Args        []string
	ExpectedOut string
	ShouldFail  bool
}

func (v *VulnxTestCase) Execute() error {
	output, err := testutils.RunVulnxBinaryAndGetResults(*vulnxBinary, debug, v.Args)
	if err != nil && !v.ShouldFail {
		return errors.Wrap(err, "failed unexpectedly")
	}
	if err == nil && v.ShouldFail {
		return errors.New("should have failed but succeeded")
	}
	if v.ExpectedOut != "" && !strings.Contains(strings.Join(output, " "), v.ExpectedOut) {
		return errors.Errorf("output doesn't contain %q. Got: %s", v.ExpectedOut, strings.Join(output, " "))
	}
	return nil
}

var vulnxTestCases = map[string]*VulnxTestCase{
	"Get By CVE ID":           {Args: []string{"id", "CVE-1999-0027", "--json", "--silent"}, ExpectedOut: `"cve_id": "CVE-1999-0027"`},
	"Get By non-CVE ID fails": {Args: []string{"id", "php-xdebug-rce", "--json", "--silent"}, ShouldFail: true},
	"Search Command":          {Args: []string{"search", "--json", "--silent", "--limit", "1", "severity:critical"}, ExpectedOut: `"results"`},
	"Search Filter Flags":     {Args: []string{"search", "--json", "--silent", "--severity", "critical,high", "--kev"}, ExpectedOut: `"results"`},
	"Search Rejects >":        {Args: []string{"search", "--silent", "'cvss_score:>7'"}, ShouldFail: true},
	"Search Removed Flag":     {Args: []string{"search", "--silent", "--hackerone"}, ShouldFail: true},
	"Search Limit Over Cap":   {Args: []string{"search", "--silent", "--limit", "1001"}, ShouldFail: true},
	"Health Check":            {Args: []string{"healthcheck", "--silent"}},
	"Help Command":            {Args: []string{"--help"}, ExpectedOut: "vulnx — the swiss army knife for vulnerability intel"},
	"Analyze Command":         {Args: []string{"analyze", "--fields", "severity", "--json", "--silent"}, ExpectedOut: "facets"},
}
