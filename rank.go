package vulnx

import (
	"regexp"
	"strconv"
)

// severityRanks orders advisory severities, worst first; an unknown severity ranks last.
var severityRanks = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}

// SeverityRank is a severity's place, worst first: critical 0, high 1, medium 2, low 3, none 4, anything else 5.
func SeverityRank(severity string) int {
	if r, ok := severityRanks[severity]; ok {
		return r
	}
	return len(severityRanks)
}

// WorseSeverity is whether severity a is worse than b.
func WorseSeverity(a, b string) bool { return SeverityRank(a) < SeverityRank(b) }

var versionNumber = regexp.MustCompile(`\d+`)

// VersionLess orders two versions by their numbers (1.10.0 after 1.9.2). When one's numbers run on past the
// other's, a further dotted number makes it the later (1.2.1 after 1.2) and anything else the earlier (1.2.3-rc1
// and a Go pseudo-version of 1.2.3 before 1.2.3). Equal numbers: the longer, a suffixed build, is the earlier.
func VersionLess(a, b string) bool {
	x, y := versionNumber.FindAllStringIndex(a, -1), versionNumber.FindAllStringIndex(b, -1)
	for i := 0; i < len(x) && i < len(y); i++ {
		xi, xerr := strconv.ParseUint(a[x[i][0]:x[i][1]], 10, 64)
		yi, yerr := strconv.ParseUint(b[y[i][0]:y[i][1]], 10, 64)
		if xerr != nil || yerr != nil { // longer than any version number: compare as digits
			if xs, ys := a[x[i][0]:x[i][1]], b[y[i][0]:y[i][1]]; xs != ys {
				return len(xs) < len(ys) || len(xs) == len(ys) && xs < ys
			}
			continue
		}
		if xi != yi {
			return xi < yi
		}
	}
	switch {
	case len(x) > len(y):
		return !dottedAt(a, x[len(y)][0])
	case len(y) > len(x):
		return dottedAt(b, y[len(x)][0])
	}
	return len(a) > len(b)
}

// dottedAt is whether the number starting at i continues a dotted version (1.2 -> 1.2.1).
func dottedAt(s string, i int) bool { return i > 0 && s[i-1] == '.' }
