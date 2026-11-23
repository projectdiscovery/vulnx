package vulnx

// Git's ignore rules, for a folder scan: what a repository ignores (build output, installed dependencies, local
// files) is not part of the project and is skipped unless --no-ignore. The rules are read as git reads them: the
// global excludes file, the repository's info/exclude, then each .gitignore from the top down, a later match
// winning, and a pattern's slashes anchoring it to its file's directory.

import (
	"bufio"
	"bytes"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// ignorePattern is one line of an ignore file.
type ignorePattern struct {
	re      *regexp.Regexp // matched against the path relative to the file's directory
	negate  bool           // !pattern: re-includes what an earlier pattern excluded
	dirOnly bool           // pattern/: matches directories only
}

// ignoreFile is an ignore file's patterns and the directory they are relative to (an absolute, slashed path).
type ignoreFile struct {
	base     string
	patterns []ignorePattern
}

// parseIgnore reads an ignore file whose patterns are relative to base.
func parseIgnore(base string, raw []byte) ignoreFile {
	f := ignoreFile{base: filepath.ToSlash(base)}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSuffix(sc.Text(), "\r")
		// trailing spaces are dropped unless escaped
		for strings.HasSuffix(line, " ") && !strings.HasSuffix(line, `\ `) {
			line = line[:len(line)-1]
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var p ignorePattern
		if strings.HasPrefix(line, "!") {
			p.negate, line = true, line[1:]
		} else if strings.HasPrefix(line, `\!`) || strings.HasPrefix(line, `\#`) {
			line = line[1:]
		}
		if strings.HasSuffix(line, "/") {
			p.dirOnly, line = true, strings.TrimRight(line, "/")
		}
		if line == "" {
			continue
		}
		// a slash before the end anchors the pattern to the file's directory; otherwise it matches at any depth
		anchored := strings.Contains(line, "/")
		line = strings.TrimPrefix(line, "/")
		expr := globRegexp(line)
		if anchored {
			expr = "^" + expr + "$"
		} else {
			expr = "(?:^|/)" + expr + "$"
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			continue // a malformed pattern matches nothing, as in git
		}
		p.re = re
		f.patterns = append(f.patterns, p)
	}
	return f
}

// globRegexp turns a gitignore glob into a regular expression: * and ? stop at a slash, ** crosses them, and a
// bracket expression is a character class.
func globRegexp(glob string) string {
	var b strings.Builder
	for i := 0; i < len(glob); i++ {
		c := glob[i]
		switch {
		case c == '*' && strings.HasPrefix(glob[i:], "**"):
			switch rest := glob[i+2:]; {
			case i == 0 && strings.HasPrefix(rest, "/"): // **/x: x in any directory
				b.WriteString("(?:.*/)?")
				i += 2
			case rest == "": // x/**: everything inside x
				b.WriteString(".*")
				i++
			case strings.HasPrefix(rest, "/"): // a/**/b: zero or more directories between
				b.WriteString("(?:.*/)?")
				i += 2
			default:
				b.WriteString("[^/]*")
				i++
			}
		case c == '*':
			b.WriteString("[^/]*")
		case c == '?':
			b.WriteString("[^/]")
		case c == '[':
			end := strings.IndexByte(glob[i+1:], ']')
			if end < 0 {
				b.WriteString(`\[`)
				continue
			}
			class := glob[i+1 : i+1+end]
			if strings.HasPrefix(class, "!") {
				class = "^" + class[1:]
			}
			b.WriteString("[" + strings.ReplaceAll(class, `\`, `\\`) + "]")
			i += end + 1
		case c == '\\' && i+1 < len(glob):
			i++
			b.WriteString(regexp.QuoteMeta(string(glob[i])))
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	return b.String()
}

// match is whether the file's last pattern to match abs (an absolute, slashed path) excludes it: matched is
// false when none does.
func (f ignoreFile) match(abs string, isDir bool) (matched, excluded bool) {
	rel, ok := strings.CutPrefix(abs, f.base+"/")
	if !ok || rel == "" {
		return false, false
	}
	for _, p := range f.patterns {
		if p.dirOnly && !isDir || !p.re.MatchString(rel) {
			continue
		}
		matched, excluded = true, !p.negate
	}
	return matched, excluded
}

// gitIgnore is the ignore rules that apply in a folder: those of the repository it is in (or is), with each
// .gitignore under the folder read as the walk enters its directory.
type gitIgnore struct {
	outer  []ignoreFile          // the global excludes file, info/exclude, .gitignore files above the folder
	perDir map[string]ignoreFile // a directory under the folder -> its .gitignore
	root   string
}

// newGitIgnore reads the rules that apply in root before any of its own .gitignore files: the global excludes
// file (core.excludesFile, else git's default), and, when root is in a repository, that repository's
// info/exclude and the .gitignore files between its top and root.
func newGitIgnore(root string) *gitIgnore {
	g := &gitIgnore{perDir: map[string]ignoreFile{}, root: filepath.ToSlash(root)}
	top, gitDir := repositoryOf(root)
	if global := globalExcludesFile(); global != "" {
		if raw, err := readCapped(global, maxConfigFile); err == nil {
			base := root
			if top != "" {
				base = top
			}
			g.outer = append(g.outer, parseIgnore(base, raw))
		}
	}
	if top == "" {
		return g
	}
	if raw, err := readCapped(filepath.Join(gitDir, "info", "exclude"), maxConfigFile); err == nil {
		g.outer = append(g.outer, parseIgnore(top, raw))
	}
	var above []string // the directories from the repository's top down to root's parent
	for dir := filepath.Dir(root); dir != top && strings.HasPrefix(dir, top); dir = filepath.Dir(dir) {
		above = append([]string{dir}, above...)
	}
	if root != top {
		above = append([]string{top}, above...)
	}
	for _, dir := range above {
		if raw, err := readCapped(filepath.Join(dir, ".gitignore"), maxConfigFile); err == nil {
			g.outer = append(g.outer, parseIgnore(dir, raw))
		}
	}
	return g
}

// load reads a directory's .gitignore, if it has one, as the walk enters it.
func (g *gitIgnore) load(dir string) {
	if raw, err := readCapped(filepath.Join(dir, ".gitignore"), maxConfigFile); err == nil {
		g.perDir[filepath.ToSlash(dir)] = parseIgnore(dir, raw)
	}
}

// ignored is whether the rules exclude a path under the folder: the last pattern to match it wins, a deeper
// .gitignore's over a shallower one's. A path inside an excluded directory is never reached: the walk skips the
// directory, as git does.
func (g *gitIgnore) ignored(abs string, isDir bool) bool {
	p := filepath.ToSlash(abs)
	excluded := false
	check := func(f ignoreFile) {
		if m, e := f.match(p, isDir); m {
			excluded = e
		}
	}
	for _, f := range g.outer {
		check(f)
	}
	var dirs []string
	for dir := path.Dir(p); ; dir = path.Dir(dir) {
		dirs = append([]string{dir}, dirs...)
		if dir == g.root || !strings.HasPrefix(dir, g.root) || dir == path.Dir(dir) {
			break
		}
	}
	for _, dir := range dirs {
		if f, ok := g.perDir[dir]; ok {
			check(f)
		}
	}
	return excluded
}

// repositoryOf finds the repository a directory is in: its top directory and its git directory (for a worktree,
// the common one, where info/exclude lives). Both are empty outside a repository.
func repositoryOf(dir string) (top, gitDir string) {
	for d := dir; ; d = filepath.Dir(d) {
		dotGit := filepath.Join(d, ".git")
		if st, err := os.Stat(dotGit); err == nil {
			if st.IsDir() {
				return d, dotGit
			}
			return d, worktreeCommonDir(d, dotGit)
		}
		if parent := filepath.Dir(d); parent == d {
			return "", ""
		}
	}
}

// worktreeCommonDir reads a worktree's .git file (gitdir: <path>) and that git directory's commondir.
func worktreeCommonDir(top, dotGit string) string {
	raw, err := readCapped(dotGit, maxConfigFile)
	if err != nil {
		return ""
	}
	gitDir, ok := strings.CutPrefix(strings.TrimSpace(string(raw)), "gitdir:")
	if !ok {
		return ""
	}
	gitDir = strings.TrimSpace(gitDir)
	if !filepath.IsAbs(gitDir) {
		gitDir = filepath.Join(top, gitDir)
	}
	if raw, err := readCapped(filepath.Join(gitDir, "commondir"), maxConfigFile); err == nil {
		common := strings.TrimSpace(string(raw))
		if !filepath.IsAbs(common) {
			common = filepath.Join(gitDir, common)
		}
		return common
	}
	return gitDir
}

// gitConfigExcludes is core.excludesFile in a git config file.
var gitConfigExcludes = regexp.MustCompile(`(?im)^\s*excludesfile\s*=\s*(.+?)\s*$`)

// globalExcludesFile is the user's global ignore file: core.excludesFile from ~/.gitconfig or the XDG git config,
// else git's default, $XDG_CONFIG_HOME/git/ignore.
func globalExcludesFile() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	xdg := os.Getenv("XDG_CONFIG_HOME")
	if xdg == "" {
		xdg = filepath.Join(home, ".config")
	}
	for _, cfg := range []string{filepath.Join(home, ".gitconfig"), filepath.Join(xdg, "git", "config")} {
		raw, err := readCapped(cfg, maxConfigFile)
		if err != nil {
			continue
		}
		if core := coreSection(raw); core != nil {
			if m := gitConfigExcludes.FindSubmatch(core); m != nil {
				file := strings.Trim(string(m[1]), `"`)
				if rest, ok := strings.CutPrefix(file, "~/"); ok {
					file = filepath.Join(home, rest)
				}
				return file
			}
		}
	}
	return filepath.Join(xdg, "git", "ignore")
}

// coreSection is the text of a git config file's [core] sections.
func coreSection(raw []byte) []byte {
	var out []byte
	in := false
	for _, line := range bytes.Split(raw, []byte("\n")) {
		t := bytes.TrimSpace(line)
		if bytes.HasPrefix(t, []byte("[")) {
			in = bytes.EqualFold(bytes.TrimSpace(bytes.Trim(t, "[]")), []byte("core"))
			continue
		}
		if in {
			out = append(append(out, line...), '\n')
		}
	}
	return out
}
