package clis

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	got, err := scanEntries([]string{"npm/a@1,npm/b@2"})
	if err != nil || strings.Join(got, " ") != "npm/a@1 npm/b@2 npm/c@3" {
		t.Errorf("%q %v", got, err)
	}
	scanList = filepath.Join(t.TempDir(), "missing.txt")
	if _, err := scanEntries(nil); err == nil {
		t.Error("a missing --list file")
	}
}

// TestLooksLikeEntry takes a lone argument that is not a file as a package version only when it can be one.
func TestLooksLikeEntry(t *testing.T) {
	for arg, want := range map[string]bool{"npm/lodash@4.17.20": true, "pkg:npm/lodash@4.17.20": true, "cpe:2.3:a:x:y:1:*": true,
		"apache:tomcat@8.5.62": true, "a@1,b@2": true, "package-lock.jsn": false, "go.sum": false, "./requirements.txt": false} {
		if looksLikeEntry(arg) != want {
			t.Errorf("%s: want %v", arg, want)
		}
	}
}
