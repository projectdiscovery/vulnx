package clis

import (
	"slices"
	"strings"
	"testing"

	"github.com/projectdiscovery/vulnx/v2"
)

func TestParseIDs(t *testing.T) {
	got := parseIDs(" CVE-2021-44228, CVE-2023-4966 \n# comment\n\n,CVE-2024-3400,\n")
	if want := []string{"CVE-2021-44228", "CVE-2023-4966", "CVE-2024-3400"}; !slices.Equal(got, want) {
		t.Errorf("parseIDs = %q, want %q", got, want)
	}
	if got := removeDuplicates([]string{"a", "b", "a"}); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("removeDuplicates = %q", got)
	}
}

func TestRenderHistory(t *testing.T) {
	out := renderHistory([]vulnx.ChangeEntry{
		{ChangedDate: "2026-10-03", Field: "severity", OldValue: "high", NewValue: "critical\x1b[31m"},
		{ChangedDate: "2026-10-05", Field: "epss", OldValue: nil, NewValue: strings.Repeat("x", 80), Source: "first"},
	})
	if strings.Contains(out, "\x1b") {
		t.Errorf("escape sequence printed: %q", out)
	}
	if strings.Index(out, "2026-10-05") > strings.Index(out, "2026-10-03") {
		t.Errorf("history not newest first:\n%s", out)
	}
	if !strings.Contains(out, "∅ → "+strings.Repeat("x", 57)+"...") || !strings.Contains(out, "(first)") {
		t.Errorf("unexpected rendering:\n%s", out)
	}
	if !strings.Contains(renderHistory(nil), "none recorded") {
		t.Errorf("empty history")
	}
}
