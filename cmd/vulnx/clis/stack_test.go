package clis

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/projectdiscovery/vulnx/v2"
)

// TestReadEntries reads one entry a line or a comma list, skipping blank lines and whole-line # comments.
func TestReadEntries(t *testing.T) {
	got, err := readEntries(strings.NewReader("# pinned\nnpm/a@1, npm/b@2\n\n  # indented comment\npypi/c@3\n"))
	if err != nil || strings.Join(got, " ") != "npm/a@1 npm/b@2 pypi/c@3" {
		t.Errorf("%q %v", got, err)
	}
}

// TestScanEntries merges arguments and --list, each entry once.
func TestScanEntries(t *testing.T) {
	list := filepath.Join(t.TempDir(), "versions.txt")
	if err := os.WriteFile(list, []byte("npm/b@2\nnpm/c@3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { scanList = "" })
	scanList = list
	got, err := scanEntries([]string{"npm/a@1,npm/b@2"}, strings.NewReader(""))
	if err != nil || strings.Join(got, " ") != "npm/a@1 npm/b@2 npm/c@3" {
		t.Errorf("%q %v", got, err)
	}
	scanList = filepath.Join(t.TempDir(), "missing.txt")
	if _, err := scanEntries(nil, strings.NewReader("")); err == nil {
		t.Error("a missing --list file")
	}
}

// TestLooksLikeEntry takes a lone argument that is not a file as a package version only when it can be one.
func TestLooksLikeEntry(t *testing.T) {
	for arg, want := range map[string]bool{"npm/lodash@4.17.20": true, "pkg:npm/lodash@4.17.20": true, "cpe:2.3:a:x:y:1:*": true,
		"apache:tomcat@8.5.62": true, "a@1,b@2": true, "-": true, "package-lock.jsn": false, "go.sum": false, "./requirements.txt": false} {
		if looksLikeEntry(arg) != want {
			t.Errorf("%s: want %v", arg, want)
		}
	}
}

// TestRenderStackTextHint names the flag that lists the rows not shown: --full when the answer holds a product's
// most urgent rows only, --show-all when every row is there and --show cut them.
func TestRenderStackTextHint(t *testing.T) {
	rows := make([]vulnx.StackAdvisory, 12)
	for i := range rows {
		rows[i] = vulnx.StackAdvisory{CVE: fmt.Sprintf("CVE-2024-%d", i), Severity: "high"}
	}
	item := vulnx.StackItem{Input: "apache:tomcat@8.5.62", Package: "cpe/apache:tomcat", Version: "8.5.62", Status: "affected",
		AdvisoryRowsTotal: 30, AdvisoryRows: rows}
	if out := renderStackText(vulnx.StackResult{Items: []vulnx.StackItem{item}}, 10, scanSource{}); !strings.Contains(out, "+20 more (--full lists them)") {
		t.Errorf("top rows only:\n%s", out)
	}
	item.AdvisoryRowsTotal = 12
	if out := renderStackText(vulnx.StackResult{Items: []vulnx.StackItem{item}}, 10, scanSource{}); !strings.Contains(out, "+2 more (--show-all lists them)") {
		t.Errorf("every row:\n%s", out)
	}
}

// TestScanEntriesStdin reads stdin for "-" as an argument or as --list's file.
func TestScanEntriesStdin(t *testing.T) {
	t.Cleanup(func() { scanList = "" })
	for _, c := range []struct {
		list string
		args []string
	}{{"", []string{"-"}}, {"-", nil}, {"-", []string{"npm/z@9"}}} {
		scanList = c.list
		got, err := scanEntries(c.args, strings.NewReader("npm/a@1\n# note\nnpm/b@2\n"))
		want := "npm/a@1 npm/b@2"
		if len(c.args) > 0 && c.args[0] != "-" {
			want = "npm/z@9 " + want
		}
		if err != nil || strings.Join(got, " ") != want {
			t.Errorf("--list %q %q: %q %v", c.list, c.args, got, err)
		}
	}
}

// TestRenderStackTextUnseen shows a package the index has no record of as unseen, after the clean ones are not,
// and the counts in the singular for one.
func TestRenderStackTextUnseen(t *testing.T) {
	res := vulnx.StackResult{Summary: vulnx.StackSummary{Packages: 1, Unseen: 1},
		Items: []vulnx.StackItem{{Input: "npm/ghost@1.0.0", Status: "clean", Seen: "none"}}}
	out := renderStackText(res, 10, scanSource{})
	if !strings.Contains(out, "[UNSEEN] npm/ghost@1.0.0") || strings.Contains(out, "[CLEAN]") ||
		!strings.Contains(out, "1 package: 0 affected, 0 clean, 0 undetermined, 1 unseen") {
		t.Errorf("%s", out)
	}
}

// TestCheckScanOutput takes -o file.json or file.csv, and a VEX document only as JSON.
func TestCheckScanOutput(t *testing.T) {
	t.Cleanup(func() { outputFile, scanVEX = "", "" })
	for _, c := range []struct {
		file, vex string
		ok        bool
	}{{"r.json", "", true}, {"r.CSV", "", true}, {"r.txt", "", false}, {"r", "", false}, {"r.csv", "openvex", false}, {"r.json", "openvex", true}} {
		outputFile, scanVEX = c.file, c.vex
		if err := checkScanOutput(); (err == nil) != c.ok {
			t.Errorf("%s --vex %q: %v", c.file, c.vex, err)
		}
	}
}

// TestTextShow lists every CVE with --full unless --show was given, and with --show-all always.
func TestTextShow(t *testing.T) {
	t.Cleanup(func() { scanFull, scanShowAll, scanShow = false, false, 10 })
	for _, c := range []struct {
		full, all, set bool
		show, want     int
	}{{false, false, false, 10, 10}, {true, false, false, 10, 0}, {true, false, true, 5, 5}, {false, true, true, 5, 0}} {
		scanFull, scanShowAll, scanShow = c.full, c.all, c.show
		if got := textShow(c.set); got != c.want {
			t.Errorf("%+v: %d", c, got)
		}
	}
}

// stackGridFixture is a lockfile's six npm packages and an image's two Debian packages.
func stackGridFixture(t *testing.T) vulnx.StackResult {
	var kev, poc []vulnx.StackAdvisory
	if err := json.Unmarshal([]byte(`[{"cve": "CVE-2021-1", "severity": "critical", "exploitation": {"known_exploited": true, "public_exploit": true}}]`), &kev); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`[{"cve": "CVE-2021-2", "severity": "high", "exploitation": {"public_exploit": true}}]`), &poc); err != nil {
		t.Fatal(err)
	}
	return vulnx.StackResult{
		Summary: vulnx.StackSummary{Packages: 8, Affected: 5, Clean: 2, Unseen: 1},
		Items: []vulnx.StackItem{
			{Input: "npm/lodash@4.17.20", Package: "npm/lodash", Version: "4.17.20", Status: "affected", WorstSeverity: "critical", Advisories: 1, AdvisoryRows: kev},
			{Input: "npm/minimist@1.2.0", Package: "npm/minimist", Version: "1.2.0", Status: "affected", WorstSeverity: "critical", Advisories: 1},
			{Input: "npm/axios@0.21.0", Package: "npm/axios", Version: "0.21.0", Status: "affected", WorstSeverity: "high", Advisories: 1, AdvisoryRows: poc},
			{Input: "npm/ws@7.4.0", Package: "npm/ws", Version: "7.4.0", Status: "affected", WorstSeverity: "medium", Advisories: 1},
			{Input: "npm/semver@7.5.2", Package: "npm/semver", Version: "7.5.2", Status: "clean", Seen: "version"},
			{Input: "npm/left-pad@9.9.9", Package: "npm/left-pad", Version: "9.9.9", Status: "clean", Seen: "none"},
			{Input: "pkg:deb/debian/openssl@3.0.11-1?distro=debian-12", Package: "deb/openssl", Version: "3.0.11-1", Distro: "debian", Release: "12",
				Status: "affected", WorstSeverity: "high", Advisories: 1},
			{Input: "pkg:deb/debian/zlib@1.2.13?distro=debian-12", Package: "deb/zlib", Version: "1.2.13", Distro: "debian", Release: "12", Status: "clean", Seen: "version"},
		},
	}
}

// TestRenderStackGrid opens a scan of more than five packages with the host grid's severity grid, a row per
// ecosystem and the image's OS packages as one row, then the unseen count and what was scanned; the list follows.
func TestRenderStackGrid(t *testing.T) {
	out := renderStackText(stackGridFixture(t), 10, scanSource{input: "package-lock.json"})
	want := `
  5 affected   1 known exploited   2 public exploit

  ECOSYSTEM  CRITICAL     HIGH         MEDIUM       LOW          EXPLOITED   CHECKED
  npm           2 ▆▆▆▆▆▆     1 ▆▆▆        1 ▆▆▆        -                 1         6
  debian 12     -            1 ▆▆▆        -            -                 -         2
  ────────────────────────────────────────────────────────────────────────────────
  total         2            2            1            0                 1         8

  Unseen         1 not in the index
  Scanned        package-lock.json · 8 packages

[AFFECTED] npm/lodash@4.17.20  critical, 1 advisories
`
	if !strings.HasPrefix(out, want) {
		t.Errorf("got\n%s\nwant a start of\n%s", out, want)
	}
	if strings.Contains(out, "8 packages: ") || !strings.Contains(out, "[UNSEEN] npm/left-pad@9.9.9\n") {
		t.Errorf("a one-line summary under the grid, or no list:\n%s", out)
	}
	short := stackGridFixture(t)
	short.Items, short.Summary = short.Items[:5], vulnx.StackSummary{Packages: 5, Affected: 4, Clean: 1}
	out = renderStackText(short, 10, scanSource{input: "package-lock.json"})
	if strings.Contains(out, "ECOSYSTEM") || !strings.HasSuffix(out, "\n5 packages: 4 affected, 1 clean, 0 undetermined, 0 unseen (1 with a known exploited CVE, 2 with a public exploit)\n") {
		t.Errorf("five packages: no grid, the one-line summary:\n%s", out)
	}
}
