package renderer

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/projectdiscovery/vulnx/v2"
)

// TestRenderStackCSV writes one row per package and advisory, an unseen package as unseen, and a cell a
// spreadsheet would read as a formula quoted.
func TestRenderStackCSV(t *testing.T) {
	var rows []vulnx.StackAdvisory
	if err := json.Unmarshal([]byte(`[{"cve": "CVE-2021-1", "severity": "critical", "cvss_score": 9.8, "fixed_in": ["4.17.21"],
		"exploitation": {"known_exploited": true}}, {"advisory_id": "GHSA-x", "severity": "high", "name": "=cmd"}]`), &rows); err != nil {
		t.Fatal(err)
	}
	raw, err := RenderStackCSV(vulnx.StackResult{Items: []vulnx.StackItem{
		{Input: "npm/lodash@4.17.20", Package: "npm/lodash", Version: "4.17.20", Status: "affected", AdvisoryRows: rows},
		{Input: "npm/ghost@1.0.0", Package: "npm/ghost", Version: "1.0.0", Status: "clean", Seen: "none"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := "input,package,version,status,fixed_version,advisory,severity,cvss,known_exploited,public_exploit,fixed_in,name\n" +
		"npm/lodash@4.17.20,npm/lodash,4.17.20,affected,,CVE-2021-1,critical,9.8,yes,,4.17.21,\n" +
		"npm/lodash@4.17.20,npm/lodash,4.17.20,affected,,GHSA-x,high,,,,,'=cmd\n" +
		"npm/ghost@1.0.0,npm/ghost,1.0.0,unseen,,,,,,,,\n"
	if string(raw) != want {
		t.Errorf("got\n%s\nwant\n%s", raw, want)
	}
	if strings.Count(string(raw), "\n") != 4 {
		t.Error("rows")
	}
}
