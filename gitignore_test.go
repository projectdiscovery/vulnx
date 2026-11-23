package vulnx

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

// TestIgnorePatterns matches gitignore patterns as git does: a name at any depth, a slash anchoring, a trailing
// slash for directories only, ** across directories, classes, escapes and a later negation winning.
func TestIgnorePatterns(t *testing.T) {
	f := parseIgnore("/r", []byte(`# comment
*.log
!keep.log
build/
/only-root.txt
docs/**/*.md
**/tmp
a/**
file[0-9].txt
\#hash
`+"trailing\\ \n"))
	for _, c := range []struct {
		path  string
		dir   bool
		want  bool
		match bool
	}{
		{"x.log", false, true, true},
		{"deep/dir/x.log", false, true, true},
		{"keep.log", false, false, true},
		{"build", true, true, true},
		{"build", false, false, false}, // a file named build: the pattern is for directories
		{"src/build", true, true, true},
		{"only-root.txt", false, true, true},
		{"sub/only-root.txt", false, false, false},
		{"docs/x.md", false, true, true},
		{"docs/a/b/x.md", false, true, true},
		{"other/docs/x.md", false, false, false},
		{"tmp", true, true, true},
		{"x/y/tmp", false, true, true},
		{"a/b/c", false, true, true},
		{"a", true, false, false}, // a/** is what is inside a, not a
		{"file7.txt", false, true, true},
		{"filex.txt", false, false, false},
		{"#hash", false, true, true},
		{"trailing ", false, true, true},
	} {
		m, excluded := f.match("/r/"+c.path, c.dir)
		if m != c.match || excluded != c.want {
			t.Errorf("%s (dir %v): matched %v excluded %v, want %v %v", c.path, c.dir, m, excluded, c.match, c.want)
		}
	}
}

// TestFolderIgnore skips what a repository ignores (.gitignore at each level, a deeper one winning, info/exclude,
// the global excludes file) and repositories and worktrees nested in the folder; --no-ignore reads them all.
func TestFolderIgnore(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	root := t.TempDir()
	lock := func(name string) string {
		return `{"lockfileVersion": 3, "packages": {"node_modules/` + name + `": {"version": "1.0.0"}}}`
	}
	for rel, body := range map[string]string{
		"../home/.gitconfig":              "[user]\n  name = x\n[core]\n  excludesFile = ~/global-ignore\n",
		".git/HEAD":                       "ref: refs/heads/main\n",
		".git/info/exclude":               "excluded/\n",
		".gitignore":                      "build/\n*.log\n/root-only/\n",
		"package-lock.json":               lock("top"),
		"build/package-lock.json":         lock("built"),
		"excluded/package-lock.json":      lock("excluded"),
		"globally/package-lock.json":      lock("global"),
		"root-only/package-lock.json":     lock("rootonly"),
		"sub/root-only/package-lock.json": lock("subrootonly"),
		"sub/.gitignore":                  "generated/\n!kept.log\n",
		"sub/kept.log":                    "x",
		"sub/other.log":                   "x",
		"sub/generated/package-lock.json": lock("generated"),
		"nested/.git/HEAD":                "ref: refs/heads/main\n",
		"nested/package-lock.json":        lock("nested"),
		"worktree/.git":                   "gitdir: /elsewhere/.git/worktrees/wt\n",
		"worktree/package-lock.json":      lock("worktree"),
	} {
		dir := root
		if after, ok := strings.CutPrefix(rel, "../home/"); ok {
			dir, rel = home, after
		}
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, "global-ignore"), []byte("globally/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	names := func(inv HostInventory) []string { return slices.Sorted(slices.Values(inv.Entries)) }
	inv, err := FolderEntries(context.Background(), root, FolderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := names(inv), []string{"pkg:npm/subrootonly@1.0.0", "pkg:npm/top@1.0.0"}; !slices.Equal(got, want) {
		t.Errorf("read %q, want %q", got, want)
	}
	sk := inv.Skipped
	if sk == nil || sk.Repositories != 2 || sk.Ignored != 6 {
		t.Fatalf("skipped %+v", sk)
	}
	paths := slices.Clone(sk.Paths)
	sort.Strings(paths)
	if want := []string{"build", "excluded", "globally", "nested", "root-only", "sub/generated", "sub/other.log", "worktree"}; !slices.Equal(paths, want) {
		t.Errorf("skipped paths %q, want %q", paths, want)
	}

	all, err := FolderEntries(context.Background(), root, FolderOptions{NoIgnore: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(names(all)); got != 9 || all.Skipped != nil {
		t.Errorf("--no-ignore read %d (%q), skipped %+v", got, names(all), all.Skipped)
	}
}

// TestFolderIgnoreOutsideRepository applies a folder's own .gitignore when it is in no repository.
func TestFolderIgnoreOutsideRepository(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	root := t.TempDir()
	for rel, body := range map[string]string{
		".gitignore":             "dist\n",
		"package-lock.json":      `{"lockfileVersion": 3, "packages": {"node_modules/a": {"version": "1.0.0"}}}`,
		"dist/package-lock.json": `{"lockfileVersion": 3, "packages": {"node_modules/b": {"version": "1.0.0"}}}`,
	} {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	inv, err := FolderEntries(context.Background(), root, FolderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(inv.Entries, []string{"pkg:npm/a@1.0.0"}) || inv.Skipped == nil || inv.Skipped.Ignored != 1 {
		t.Errorf("entries %q skipped %+v", inv.Entries, inv.Skipped)
	}
}
