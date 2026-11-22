package termtext

import "testing"

func TestClean(t *testing.T) {
	for in, want := range map[string]string{
		"plain text":           "plain text",
		"line one\nline\ttwo":  "line one\nline\ttwo",
		"\x1b[31mred\x1b[0m":   "[31mred[0m",
		"bell\a and \r return": "bell and  return",
		"c1 \u009b control":    "c1  control",
		"evil\u202egnp.exe":         "evilgnp.exe",
		"zero\u200bwidth\u2066iso":       "zerowidthiso",
		"café ünïcode 漢字":      "café ünïcode 漢字",
		"invalid \xff utf8":    "invalid  utf8",
	} {
		if got := Clean(in); got != want {
			t.Errorf("Clean(%q) = %q, want %q", in, got, want)
		}
	}
}
