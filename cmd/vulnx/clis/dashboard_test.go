package clis

import (
	"strings"
	"testing"

	"github.com/projectdiscovery/vulnx/v2/pkg/tools/renderer"
)

// dashboardFixture is the index as one day's dashboard read it.
func dashboardFixture() dashboardData {
	return dashboardData{
		Total:    407116,
		Severity: map[string]int{"critical": 56345, "high": 155398, "medium": 181346, "low": 14027, "unknown": 12},
		Vendors: []bucket{{"linux", 22234}, {"microsoft", 19083}, {"google", 17240}, {"oracle", 14785}, {"debian", 10169},
			{"apple", 9000}},
		Weaknesses: []bucket{{"CWE-79", 50528}, {"CWE-89", 19643}, {"CWE-119", 14577}, {"CWE-787", 14483}, {"CWE-20", 13839}},
		Exploit: map[string]int{"known_exploited": 1790, "vulncheck_known_exploited": 6057, "ransomware": 361,
			"initial_access": 48, "nuclei_template": 4807, "public_exploit": 96977},
		EPSS: &[3]int{2516, 7202, 17581},
	}
}

// TestRenderDashboard draws the dashboard plain: the headline, sections in a fixed label column with right-aligned
// counts, one-decimal shares and bars scaled to each section's largest (a thin mark under one block), exploitation
// by count, and vendors beside weaknesses only where both fit.
func TestRenderDashboard(t *testing.T) {
	c := renderer.NoColorConfig()
	want := `
  407,116 CVEs   1,790 known exploited (CISA)   6,057 known exploited (VulnCheck)   96,977 public exploit

  SEVERITY     CVES  SHARE
  critical   56,345  13.8%  ▆▆▆▆▆
  high      155,398  38.2%  ▆▆▆▆▆▆▆▆▆▆▆▆▆▆
  medium    181,346  44.5%  ▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆
  low        14,027   3.4%  ▆▆

  TOP VENDORS    CVES  SHARE
  linux        22,234   5.5%  ▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆
  microsoft    19,083   4.7%  ▆▆▆▆▆▆▆▆▆▆▆▆▆▆
  google       17,240   4.2%  ▆▆▆▆▆▆▆▆▆▆▆▆▆
  oracle       14,785   3.6%  ▆▆▆▆▆▆▆▆▆▆▆
  debian       10,169   2.5%  ▆▆▆▆▆▆▆▆

  TOP WEAKNESSES                      CVES  SHARE
  CWE-79 cross-site scripting       50,528  12.4%  ▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆
  CWE-89 sql injection              19,643   4.8%  ▆▆▆▆▆▆▆
  CWE-119 memory buffer errors      14,577   3.6%  ▆▆▆▆▆
  CWE-787 out-of-bounds write       14,483   3.6%  ▆▆▆▆▆
  CWE-20 improper input validation  13,839   3.4%  ▆▆▆▆▆

  EXPLOITATION       CVES  SHARE
  public exploit   96,977  23.8%  ▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆
  VulnCheck KEV     6,057   1.5%  ▏
  nuclei template   4,807   1.2%  ▏
  CISA KEV          1,790   0.4%  ▏
  ransomware use      361   0.1%  ▏
  initial access       48  <0.1%  ▏
  VulnCheck KEV includes every CISA KEV entry

  EPSS                   CVES  SHARE
  0.7–1.0 (critical)    2,516   0.6%  ▏
  0.3–0.7 (high)        4,686   1.2%  ▏
  0.1–0.3 (medium)     10,379   2.5%  ▏
  under 0.1 or none   389,535  95.7%  ▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆
`
	for _, columns := range []int{0, 114} {
		if got := renderDashboard(dashboardFixture(), columns, c); got != want {
			t.Errorf("%d columns:\n%s\nwant\n%s", columns, got, want)
		}
	}
	wide := renderDashboard(dashboardFixture(), 115, c)
	for _, line := range []string{
		"  TOP VENDORS    CVES  SHARE                      TOP WEAKNESSES                      CVES  SHARE\n",
		"  microsoft    19,083   4.7%  ▆▆▆▆▆▆▆▆▆▆▆▆▆▆      CWE-89 sql injection              19,643   4.8%  ▆▆▆▆▆▆▆\n",
	} {
		if !strings.Contains(wide, line) {
			t.Errorf("side by side: no %q in\n%s", line, wide)
		}
	}
	if strings.Contains(wide, "\n  TOP WEAKNESSES") {
		t.Errorf("weaknesses stacked at 115 columns:\n%s", wide)
	}
}

// TestRenderDashboardColors colors severity bars as the host grid does, and nothing in plain mode.
func TestRenderDashboardColors(t *testing.T) {
	out := renderDashboard(dashboardFixture(), 0, renderer.DefaultColorConfig())
	if !strings.Contains(out, gridColors["critical"]+gridBar) || !strings.Contains(out, gridColors["low"]+gridBar) {
		t.Errorf("no severity colors:\n%q", out)
	}
	if plain := renderDashboard(dashboardFixture(), 0, renderer.NoColorConfig()); strings.Contains(plain, "\033[") {
		t.Errorf("escape codes with --no-color: %q", plain)
	}
}

// TestShare keeps one decimal and marks a share too small to show.
func TestShare(t *testing.T) {
	for _, c := range []struct {
		n, base int
		want    string
	}{{48, 407116, "<0.1%"}, {361, 407116, "0.1%"}, {0, 10, "0.0%"}, {1, 0, "-"}, {407116, 407116, "100.0%"}} {
		if got := share(c.n, c.base); got != c.want {
			t.Errorf("share(%d, %d) = %q, want %q", c.n, c.base, got, c.want)
		}
	}
}
