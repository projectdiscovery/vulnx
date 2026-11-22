// Package termtext makes text from the network safe to print on a terminal.
package termtext

import (
	"strings"
	"unicode"
)

// Clean removes control characters (keeping newline and tab) and Unicode format characters such as bidi
// overrides and zero-width marks, so server text cannot move the cursor, recolour the terminal or reorder what
// the reader sees.
func Clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == unicode.ReplacementChar {
			return -1
		}
		return r
	}, s)
}
