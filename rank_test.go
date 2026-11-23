package vulnx

import "testing"

func TestVersionLess(t *testing.T) {
	for _, c := range []struct {
		a, b string
		less bool
	}{
		{"1.9.2", "1.10.0", true},
		{"1.10.0", "1.9.2", false},
		{"1.2", "1.2.1", true},
		{"1.2.1", "1.2", false},
		{"1.2.3-rc1", "1.2.3", true},
		{"v1.2.3", "v1.2.3-0.20230101120000-abcdef012345", false},
		{"2.1.90", "2.1.100", true},
		{"1.2.3", "1.2.3", false},
		{"0.62.0", "0.38.0", false},
		{"0.58.1-0.20250101-abc", "0.58.1", true},
		{"99999999999999999999.1", "100000000000000000000.0", true},
	} {
		if got := VersionLess(c.a, c.b); got != c.less {
			t.Errorf("VersionLess(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

func TestSeverityRank(t *testing.T) {
	if !WorseSeverity("critical", "high") || WorseSeverity("low", "medium") || !WorseSeverity("low", "") || WorseSeverity("", "none") {
		t.Error("severity order")
	}
}
