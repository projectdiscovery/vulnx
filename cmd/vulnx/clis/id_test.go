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

func TestNoVulnsMessage(t *testing.T) {
	refused := func(id string) idFailure {
		return idFailure{id, "failed to fetch " + id + `: request failed: Get "http://127.0.0.1:1/v1/cves/` + id + `": connection refused`}
	}
	notFound := idFailure{"CVE-1900-0001", "CVE-1900-0001 not found"}
	for _, c := range []struct {
		failures []idFailure
		want     string
	}{
		{nil, "No vulnerabilities were retrieved"},
		{[]idFailure{notFound}, "No vulnerabilities were retrieved: CVE-1900-0001 not found"},
		{[]idFailure{refused("CVE-2021-44228"), refused("CVE-2023-4966")},
			"No vulnerabilities were retrieved: all 2 ids failed the same way: " + refused("CVE-2021-44228").reason},
		{[]idFailure{refused("CVE-2021-44228"), notFound, refused("CVE-2023-4966")},
			"No vulnerabilities were retrieved: " + refused("CVE-2021-44228").reason + " (and 2 more failed)"},
	} {
		if got := noVulnsMessage(c.failures); got != c.want {
			t.Errorf("got  %q\nwant %q", got, c.want)
		}
	}
}

func TestExtractCVEIDs(t *testing.T) {
	in := "Critical vulnerabilities found: CVE-2021-44228, cve-2023-4966\n# CVE-1999-0001 in a comment\nCVE-2024-3400\nsee CVE-2021-44228.\nCVE-2024-1 is too short; xCVE-2024-12345 is not an id"
	want := []string{"CVE-2021-44228", "cve-2023-4966", "CVE-2024-3400", "CVE-2021-44228"}
	if got := extractCVEIDs(in); !slices.Equal(got, want) {
		t.Errorf("extractCVEIDs = %q, want %q", got, want)
	}
	if !isCVEContent("Critical vulnerabilities found: CVE-2021-44228, CVE-2023-4966") {
		t.Errorf("free text with CVE ids not routed to id")
	}
}
