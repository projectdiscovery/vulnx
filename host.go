package vulnx

// The machine vulnx runs on, as check entries (vulnx scan --host): what is installed on it, each component under
// the identifier SecurityContext judges it by.
//
//   OS packages       Linux: /etc/os-release names the distribution and release; packages come from dpkg's status
//                     file, apk's installed database, or `rpm -qa`. Each becomes a purl with its release and source
//                     package (pkg:deb/debian/libc6@2.36-9+deb12u7?distro=debian-12&upstream=glibc), the form the
//                     distribution's advisories key on. macOS: the macOS version, as a CPE.
//   language packages Python site-packages, global node_modules and Ruby gems outside the distribution's own
//                     directories (those are OS packages already, judged by the distribution's backported fixes),
//                     as registry purls.
//   binaries          Go executables on PATH, from their embedded module list; Rust executables that embed their
//                     crate list. Each module or crate becomes a registry purl.
//   macOS extras      Homebrew formulae and application bundles have no package ecosystem: they are sent only when
//                     a table below names their NVD product, and listed as not assessed otherwise. A guessed CPE
//                     that names no product reads clean, so a component is never mapped by its name alone.
//
// Nothing is uploaded but these names and versions.

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"debug/buildinfo"
	"debug/elf"
	"debug/macho"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
)

// HostInventory is what vulnx found on a machine.
type HostInventory struct {
	OS          string       // "debian 12", "macOS 26.4", ...
	Source      string       // where the OS packages came from: dpkg, rpm, apk, sw_vers
	Entries     []string     // purls and CPEs, each once
	Sources     []HostSource // what each reader found
	NotAssessed []string     // "name version (source)": read, but with no identifier SecurityContext judges exactly
	Note        string       // per source counts, and what is not read
}

// HostSource is one reader's count: Sent components went into Entries, NotAssessed were read but not sent.
type HostSource struct {
	Name        string
	Sent        int
	NotAssessed int
	Detail      string // "9 binaries", ...
}

// HostEntries reads what is installed on the machine (or on a Linux filesystem mounted at root).
func HostEntries(root string) (HostInventory, error) {
	if root == "" {
		root = "/"
	}
	goos := runtime.GOOS
	if root != "/" {
		goos = "linux"
	}
	if goos != "linux" && goos != "darwin" {
		return HostInventory{}, fmt.Errorf("--host reads Linux and macOS machines (this is %s); scan an SBOM of it instead", goos)
	}
	h := &hostReader{root: root, goos: goos, seen: map[string]bool{}, binSeen: map[string]bool{}}
	var err error
	if goos == "darwin" {
		err = h.macOS()
	} else {
		err = h.linuxOS()
	}
	if err != nil {
		return h.inv, err
	}
	h.languagePackages()
	h.binaries()
	if goos == "darwin" || h.exists("home/linuxbrew/.linuxbrew/Cellar") {
		h.homebrew()
	}
	if goos == "darwin" {
		h.applications()
	}
	h.inv.Note = h.note()
	return h.inv, nil
}

type hostReader struct {
	root, goos string
	inv        HostInventory
	seen       map[string]bool // entries already sent
	binSeen    map[string]bool // executables already read, by real path: true when Go or Rust
	notRead    []string
}

func (h *hostReader) path(rel string) string { return filepath.Join(h.root, rel) }

func (h *hostReader) exists(rel string) bool {
	_, err := os.Stat(h.path(rel))
	return err == nil
}

// glob expands root-relative patterns to the existing paths they name, each once.
func (h *hostReader) glob(patterns ...string) []string {
	abs := make([]string, len(patterns))
	for i, p := range patterns {
		abs[i] = h.path(p)
	}
	return globAll(abs...)
}

// globAll expands patterns to existing paths, a directory reached through two symlinked paths once.
func globAll(patterns ...string) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range patterns {
		matches, _ := filepath.Glob(p) // the only error is a malformed pattern, and these are constants
		for _, m := range matches {
			if real, err := filepath.EvalSymlinks(m); err == nil && !seen[real] {
				seen[real] = true
				out = append(out, m)
			}
		}
	}
	return out
}

// homes are the user home directories under root, as root-relative patterns.
func (h *hostReader) homes() []string {
	if h.goos == "darwin" {
		return []string{"Users/*", "var/root"}
	}
	return []string{"home/*", "root"}
}

func (h *hostReader) inHomes(rel ...string) []string {
	var out []string
	for _, home := range h.homes() {
		for _, r := range rel {
			out = append(out, home+"/"+r)
		}
	}
	return out
}

// add records entries for one source; an entry another source already sent counts once, under the first.
func (h *hostReader) add(name, detail string, entries []string, notAssessed []string) {
	src := HostSource{Name: name, Detail: detail, NotAssessed: len(notAssessed)}
	for _, e := range entries {
		if !h.seen[e] {
			h.seen[e] = true
			h.inv.Entries = append(h.inv.Entries, e)
			src.Sent++
		}
	}
	for _, n := range notAssessed {
		h.inv.NotAssessed = append(h.inv.NotAssessed, n+" ("+name+")")
	}
	h.inv.Sources = append(h.inv.Sources, src) // a reader that found nothing is reported too
}

func (h *hostReader) note() string {
	var parts []string
	for _, s := range h.inv.Sources {
		p := fmt.Sprintf("%s %d", s.Name, s.Sent)
		if s.Detail != "" {
			p += " (" + s.Detail + ")"
		}
		if s.NotAssessed > 0 {
			p += fmt.Sprintf(", %d not assessed", s.NotAssessed)
		}
		parts = append(parts, p)
	}
	note := "read: " + strings.Join(parts, "; ")
	if len(h.notRead) > 0 {
		note += "\nnot read: " + strings.Join(h.notRead, "; ")
	}
	return note
}

func (h *hostReader) macOS() error {
	h.inv.Source = "sw_vers"
	out, err := exec.Command("sw_vers", "-productVersion").Output()
	if err != nil {
		return fmt.Errorf("sw_vers: %w", err)
	}
	ver := strings.TrimSpace(string(out))
	h.inv.OS = "macOS " + ver
	h.add("macOS", "", []string{fmt.Sprintf("cpe:2.3:o:apple:macos:%s:*:*:*:*:*:*:*", ver)}, nil)
	return nil
}

// osRelease reads ID and VERSION_ID from os-release.
func osRelease(root string) (id, version string, err error) {
	var f *os.File
	for _, p := range []string{"etc/os-release", "usr/lib/os-release"} {
		if f, err = os.Open(filepath.Join(root, p)); err == nil {
			break
		}
	}
	if f == nil {
		return "", "", fmt.Errorf("no os-release under %s: not a Linux root filesystem", root)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		switch k {
		case "ID":
			id = strings.ToLower(v)
		case "VERSION_ID":
			version = v
		}
	}
	return id, version, sc.Err()
}

// distroQualifier is SecurityContext's distro= value and the purl namespace for a distribution release.
func distroQualifier(id, version string) (namespace, qualifier string) {
	major := strings.SplitN(version, ".", 2)[0]
	switch id {
	case "debian":
		return "debian", "debian-" + major
	case "ubuntu":
		return "ubuntu", "ubuntu-" + version
	case "alpine":
		parts := strings.SplitN(version, ".", 3)
		if len(parts) >= 2 {
			return "alpine", "alpine-" + parts[0] + "." + parts[1]
		}
		return "alpine", "alpine-" + version
	case "rhel":
		return "redhat", "rhel-" + major
	case "rocky":
		return "rocky", "rocky-" + major
	case "almalinux":
		return "almalinux", "almalinux-" + major
	}
	return id, id + "-" + version
}

// linuxOS reads the distribution's package database. A root with none (a minimal image) is still read for the
// other sources; the gap is reported.
func (h *hostReader) linuxOS() error {
	id, version, err := osRelease(h.root)
	if err != nil {
		return err
	}
	h.inv.OS = strings.TrimSpace(id + " " + version)
	switch id {
	case "debian", "ubuntu", "rhel", "rocky", "almalinux", "alpine":
	default:
		h.notRead = append(h.notRead, fmt.Sprintf("SecurityContext has advisories for Debian, Ubuntu, Alpine, RHEL, Rocky and AlmaLinux; %s packages will come back undetermined", id))
	}
	source, entries, err := linuxPackages(h.root, id, version)
	if err != nil {
		h.notRead = append(h.notRead, err.Error())
		return nil
	}
	h.inv.Source = source
	h.add(source, "", entries, nil)
	return nil
}

func linuxPackages(root, id, version string) (string, []string, error) {
	ns, distro := distroQualifier(id, version)
	var entries []string
	q := func(extra url.Values) string {
		v := url.Values{"distro": {distro}}
		for k, vs := range extra {
			v[k] = vs
		}
		return v.Encode()
	}
	if f, err := os.Open(filepath.Join(root, "var/lib/dpkg/status")); err == nil {
		defer func() { _ = f.Close() }()
		for _, p := range dpkgInstalled(f) {
			extra := url.Values{}
			if p.arch != "" {
				extra.Set("arch", p.arch)
			}
			if p.source != "" && p.source != p.name {
				up := p.source
				if p.sourceVersion != "" {
					up += "@" + p.sourceVersion
				}
				extra.Set("upstream", up)
			}
			entries = append(entries, fmt.Sprintf("pkg:deb/%s/%s@%s?%s", ns, p.name, url.PathEscape(p.version), q(extra)))
		}
		return "dpkg", entries, nil
	}
	if f, err := os.Open(filepath.Join(root, "lib/apk/db/installed")); err == nil {
		defer func() { _ = f.Close() }()
		for _, p := range apkInstalled(f) {
			extra := url.Values{}
			if p.source != "" && p.source != p.name {
				extra.Set("upstream", p.source)
			}
			entries = append(entries, fmt.Sprintf("pkg:apk/alpine/%s@%s?%s", p.name, url.PathEscape(p.version), q(extra)))
		}
		return "apk", entries, nil
	}
	if root == "/" {
		if out, err := exec.Command("rpm", "-qa", "--qf", "%{NAME}|%{EPOCHNUM}|%{VERSION}-%{RELEASE}|%{ARCH}|%{SOURCERPM}\\n").Output(); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				f := strings.Split(strings.TrimSpace(line), "|")
				if len(f) != 5 || f[0] == "" || f[0] == "gpg-pubkey" {
					continue
				}
				extra := url.Values{}
				if f[1] != "" && f[1] != "0" {
					extra.Set("epoch", f[1])
				}
				if f[3] != "" && f[3] != "(none)" {
					extra.Set("arch", f[3])
				}
				if f[4] != "" && f[4] != "(none)" {
					extra.Set("upstream", f[4])
				}
				entries = append(entries, fmt.Sprintf("pkg:rpm/%s/%s@%s?%s", ns, f[0], url.PathEscape(f[2]), q(extra)))
			}
			return "rpm", entries, nil
		}
	}
	return "", nil, fmt.Errorf("OS packages: no dpkg, apk or rpm package database under %s", root)
}

type osPackage struct{ name, version, arch, source, sourceVersion string }

// dpkgInstalled reads dpkg's status file: installed packages with their source package.
func dpkgInstalled(f io.Reader) []osPackage {
	var out []osPackage
	var cur osPackage
	installed := false
	flush := func() {
		if installed && cur.name != "" && cur.version != "" {
			out = append(out, cur)
		}
		cur, installed = osPackage{}, false
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		k, v, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		switch k {
		case "Package":
			cur.name = v
		case "Version":
			cur.version = v
		case "Architecture":
			cur.arch = v
		case "Status":
			installed = strings.HasSuffix(v, " installed")
		case "Source": // "src" or "src (version)"
			src, ver, _ := strings.Cut(v, " (")
			cur.source, cur.sourceVersion = strings.TrimSpace(src), strings.TrimSuffix(ver, ")")
		}
	}
	flush()
	return out
}

// apkInstalled reads apk's installed database: P: name, V: version, o: origin (the source package).
func apkInstalled(f io.Reader) []osPackage {
	var out []osPackage
	var cur osPackage
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	flush := func() {
		if cur.name != "" && cur.version != "" {
			out = append(out, cur)
		}
		cur = osPackage{}
	}
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		switch line[0] {
		case 'P':
			cur.name = line[2:]
		case 'V':
			cur.version = line[2:]
		case 'A':
			cur.arch = line[2:]
		case 'o':
			cur.source = line[2:]
		}
	}
	flush()
	return out
}

// languagePackages reads installed Python, Node and Ruby packages. On Linux the distribution's own directories
// (/usr/lib/python3*, /usr/lib/node_modules, /usr/lib/ruby) are left out: their contents are OS packages, and
// judging them by upstream version would report fixes the distribution backported as open.
func (h *hostReader) languagePackages() {
	var pyDirs, nodeDirs, gemDirs []string
	pyDirs = append(pyDirs, "usr/local/lib/python3*/site-packages", "usr/local/lib/python3*/dist-packages")
	pyDirs = append(pyDirs, h.inHomes(".local/lib/python3*/site-packages", ".pyenv/versions/*/lib/python3*/site-packages")...)
	nodeDirs = append(nodeDirs, "usr/local/lib/node_modules")
	nodeDirs = append(nodeDirs, h.inHomes(".npm-global/lib/node_modules", ".nvm/versions/node/*/lib/node_modules")...)
	gemDirs = append(gemDirs, "usr/local/lib/ruby/gems/*/specifications", "usr/local/share/gems/specifications")
	gemDirs = append(gemDirs, h.inHomes(".gem/ruby/*/specifications", ".local/share/gem/ruby/*/specifications",
		".rbenv/versions/*/lib/ruby/gems/*/specifications", ".rvm/gems/*/specifications")...)
	if h.goos == "darwin" {
		pyDirs = append(pyDirs, "opt/homebrew/lib/python3*/site-packages",
			"Library/Frameworks/Python.framework/Versions/*/lib/python3*/site-packages",
			"Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/*/lib/python3*/site-packages")
		pyDirs = append(pyDirs, h.inHomes("Library/Python/*/lib/python/site-packages")...)
		nodeDirs = append(nodeDirs, "opt/homebrew/lib/node_modules")
		gemDirs = append(gemDirs, "opt/homebrew/lib/ruby/gems/*/specifications", "Library/Ruby/Gems/*/specifications",
			"System/Library/Frameworks/Ruby.framework/Versions/*/usr/lib/ruby/gems/*/specifications")
	} else {
		gemDirs = append(gemDirs, "var/lib/gems/*/specifications")
	}
	if h.goos == "darwin" || h.exists("home/linuxbrew/.linuxbrew") {
		pyDirs = append(pyDirs, "home/linuxbrew/.linuxbrew/lib/python3*/site-packages")
		nodeDirs = append(nodeDirs, "home/linuxbrew/.linuxbrew/lib/node_modules")
		gemDirs = append(gemDirs, "home/linuxbrew/.linuxbrew/lib/ruby/gems/*/specifications")
	}

	dirs := h.glob(pyDirs...)
	var py []string
	for _, d := range dirs {
		py = append(py, pythonPackages(d)...)
	}
	h.add("python", count(len(dirs), "site-packages dir", "site-packages dirs"), py, nil)

	dirs = h.glob(nodeDirs...)
	var node []string
	for _, d := range dirs {
		node = append(node, nodePackages(d, 0)...)
	}
	h.add("npm", count(len(dirs), "global node_modules", "global node_modules"), node, nil)

	dirs = h.glob(gemDirs...)
	var gems []string
	for _, d := range dirs {
		gems = append(gems, rubyGems(d)...)
		gems = append(gems, rubyGems(filepath.Join(d, "default"))...)
	}
	h.add("gems", count(len(dirs), "gem dir", "gem dirs"), gems, nil)
	h.notRead = append(h.notRead, "virtualenvs and project dependencies (scan their lockfiles)")
}

func count(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

var pypiNameSep = regexp.MustCompile(`[-_.]+`)

// pythonPackages reads a site-packages directory: each *.dist-info/METADATA or *.egg-info/PKG-INFO names one
// installed distribution.
func pythonPackages(dir string) []string {
	var out []string
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, e := range ents {
		var meta string
		switch {
		case strings.HasSuffix(e.Name(), ".dist-info"):
			meta = filepath.Join(dir, e.Name(), "METADATA")
		case strings.HasSuffix(e.Name(), ".egg-info") && e.IsDir():
			meta = filepath.Join(dir, e.Name(), "PKG-INFO")
		case strings.HasSuffix(e.Name(), ".egg-info"):
			meta = filepath.Join(dir, e.Name())
		default:
			continue
		}
		name, version := pythonMetadata(meta)
		if name == "" || version == "" {
			continue
		}
		name = pypiNameSep.ReplaceAllString(strings.ToLower(name), "-")
		out = append(out, fmt.Sprintf("pkg:pypi/%s@%s", name, url.PathEscape(version)))
	}
	return out
}

// pythonMetadata reads Name and Version from the header block of a core metadata file.
func pythonMetadata(path string) (name, version string) {
	f, err := os.Open(path)
	if err != nil {
		return "", ""
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() && (name == "" || version == "") {
		line := sc.Text()
		if line == "" {
			break
		}
		if v, ok := strings.CutPrefix(line, "Name:"); ok {
			name = strings.TrimSpace(v)
		} else if v, ok := strings.CutPrefix(line, "Version:"); ok {
			version = strings.TrimSpace(v)
		}
	}
	return name, version
}

// nodePackages reads a node_modules directory, scoped packages and nested node_modules included. Linked
// packages (symlinks to a working copy) are local code, not a registry release, and are not read.
func nodePackages(dir string, depth int) []string {
	if depth > 32 {
		return nil
	}
	var out []string
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, e := range ents {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		pkgDirs := []string{filepath.Join(dir, e.Name())}
		if strings.HasPrefix(e.Name(), "@") {
			pkgDirs = nil
			scoped, _ := os.ReadDir(filepath.Join(dir, e.Name()))
			for _, s := range scoped {
				if s.IsDir() {
					pkgDirs = append(pkgDirs, filepath.Join(dir, e.Name(), s.Name()))
				}
			}
		}
		for _, p := range pkgDirs {
			raw, err := os.ReadFile(filepath.Join(p, "package.json"))
			if err != nil {
				continue
			}
			var pj struct{ Name, Version string }
			if json.Unmarshal(raw, &pj) == nil && pj.Name != "" && pj.Version != "" {
				name := pj.Name
				if strings.HasPrefix(name, "@") {
					name = "%40" + strings.TrimPrefix(name, "@")
				}
				out = append(out, fmt.Sprintf("pkg:npm/%s@%s", name, url.PathEscape(pj.Version)))
			}
			out = append(out, nodePackages(filepath.Join(p, "node_modules"), depth+1)...)
		}
	}
	return out
}

var (
	gemspecName    = regexp.MustCompile(`\.name\s*=\s*["']([^"']+)["']`)
	gemspecVersion = regexp.MustCompile(`\.version\s*=\s*["']([^"']+)["']`)
)

// rubyGems reads a gem specifications directory: one name-version.gemspec per installed gem.
func rubyGems(dir string) []string {
	var out []string
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".gemspec") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		n, v := gemspecName.FindSubmatch(raw), gemspecVersion.FindSubmatch(raw)
		if n == nil || v == nil {
			continue
		}
		out = append(out, fmt.Sprintf("pkg:gem/%s@%s", n[1], url.PathEscape(string(v[1]))))
	}
	return out
}

// binaries reads the Go and Rust executables in the PATH directories.
func (h *hostReader) binaries() {
	dirs := []string{"usr/local/bin", "usr/local/sbin", "usr/bin", "usr/sbin", "bin", "sbin"}
	dirs = append(dirs, h.inHomes("go/bin", ".cargo/bin", ".local/bin", "bin")...)
	if h.goos == "darwin" {
		dirs = append(dirs, "opt/homebrew/bin", "opt/homebrew/sbin")
	}
	if h.goos == "darwin" || h.exists("home/linuxbrew/.linuxbrew") {
		dirs = append(dirs, "home/linuxbrew/.linuxbrew/bin")
	}
	if h.root == "/" {
		for _, d := range filepath.SplitList(os.Getenv("PATH")) {
			if filepath.IsAbs(d) {
				dirs = append(dirs, strings.TrimPrefix(d, "/"))
			}
		}
	}
	b := h.readBinaries(h.glob(dirs...))
	h.add("go binaries", count(b.goBins, "binary", "binaries"), b.goEntries, nil)
	h.add("rust binaries", count(b.rustBins, "binary", "binaries"), b.rustEntries, nil)
	h.notRead = append(h.notRead, "Rust binaries built without an embedded crate list; other compiled programs outside Homebrew")
}

type binaryModules struct {
	goEntries, rustEntries []string
	goBins, rustBins       int
	judged                 int // Go and Rust executables in dirs, counting those an earlier call read
}

// readBinaries reads the executables in dirs, each file once across calls (PATH links into Homebrew's Cellar).
func (h *hostReader) readBinaries(dirs []string) binaryModules {
	var b binaryModules
	for _, d := range dirs {
		ents, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range ents {
			real, err := filepath.EvalSymlinks(filepath.Join(d, e.Name()))
			if err != nil {
				continue
			}
			if judged, ok := h.binSeen[real]; ok {
				if judged {
					b.judged++
				}
				continue
			}
			h.binSeen[real] = false
			st, err := os.Stat(real)
			if err != nil || !st.Mode().IsRegular() || st.Mode()&0o111 == 0 {
				continue
			}
			if mods, ok := goModules(real); ok {
				b.goBins++
				b.goEntries = append(b.goEntries, mods...)
			} else if crates, ok := rustCrates(real); ok {
				b.rustBins++
				b.rustEntries = append(b.rustEntries, crates...)
			} else {
				continue
			}
			h.binSeen[real] = true
			b.judged++
		}
	}
	return b
}

// goModules reads a Go executable's build info: the toolchain as pkg:golang/stdlib and every module linked in
// (a replaced module as its replacement; one replaced by a local directory has no version and is left out).
func goModules(path string) ([]string, bool) {
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var out []string
	if v := strings.TrimPrefix(bi.GoVersion, "go"); v != "" {
		v, _, _ = strings.Cut(v, " ") // "go1.22.1 X:boringcrypto"
		out = append(out, "pkg:golang/stdlib@"+url.PathEscape(v))
	}
	mods := append([]*debug.Module{&bi.Main}, bi.Deps...)
	for _, m := range mods {
		if m.Replace != nil {
			m = m.Replace
		}
		if m.Path == "" || m.Version == "" || m.Version == "(devel)" {
			continue
		}
		out = append(out, fmt.Sprintf("pkg:golang/%s@%s", m.Path, url.PathEscape(m.Version)))
	}
	return out, true
}

// rustCrates reads the crate list a Rust executable embeds when built for auditing: a zlib-compressed JSON
// document in the .dep-v0 section (ELF) or __DATA,__dep_v0 (Mach-O). Only crates from crates.io are sent; git
// and path dependencies have no registry release to judge.
func rustCrates(path string) ([]string, bool) {
	raw := depV0Section(path)
	if raw == nil {
		return nil, false
	}
	zr, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, false
	}
	defer func() { _ = zr.Close() }()
	var doc struct {
		Packages []struct{ Name, Version, Source string }
	}
	if err := json.NewDecoder(io.LimitReader(zr, 64<<20)).Decode(&doc); err != nil {
		return nil, false
	}
	var out []string
	for _, p := range doc.Packages {
		if p.Source == "crates.io" && p.Name != "" && p.Version != "" {
			out = append(out, fmt.Sprintf("pkg:cargo/%s@%s", p.Name, url.PathEscape(p.Version)))
		}
	}
	return out, true
}

func depV0Section(path string) []byte {
	if f, err := elf.Open(path); err == nil {
		defer func() { _ = f.Close() }()
		if s := f.Section(".dep-v0"); s != nil {
			b, _ := s.Data() // a truncated section fails to inflate below
			return b
		}
		return nil
	}
	var mf *macho.File
	if ff, err := macho.OpenFat(path); err == nil {
		defer func() { _ = ff.Close() }()
		if len(ff.Arches) > 0 {
			mf = ff.Arches[0].File
		}
	} else if f, err := macho.Open(path); err == nil {
		defer func() { _ = f.Close() }()
		mf = f
	}
	if mf == nil {
		return nil
	}
	for _, s := range mf.Sections {
		if s.Name == "__dep_v0" && s.Seg == "__DATA" {
			b, _ := s.Data()
			return b
		}
	}
	return nil
}

// brewProducts names the NVD product of Homebrew formulae whose version is the upstream release version.
// Each entry was checked against SecurityContext's product index; a formula missing here is listed as not
// assessed. Versioned formulae (openssl@3, python@3.12) are looked up without the @ suffix.
var brewProducts = map[string][]string{
	"openssl":     {"openssl:openssl"},
	"curl":        {"haxx:curl"},
	"sqlite":      {"sqlite:sqlite"},
	"redis":       {"redis:redis"},
	"postgresql":  {"postgresql:postgresql"},
	"mysql":       {"oracle:mysql"},
	"php":         {"php:php"},
	"node":        {"nodejs:node.js"},
	"python":      {"python:python"},
	"go":          {"golang:go"},
	"wget":        {"gnu:wget"},
	"libssh2":     {"libssh2:libssh2"},
	"libssh":      {"libssh:libssh"},
	"xz":          {"tukaani:xz"},
	"libpng":      {"libpng:libpng"},
	"libtiff":     {"libtiff:libtiff"},
	"imagemagick": {"imagemagick:imagemagick"},
	"ffmpeg":      {"ffmpeg:ffmpeg"},
	"gnupg":       {"gnupg:gnupg"},
	"gnutls":      {"gnu:gnutls"},
	"nghttp2":     {"nghttp2:nghttp2"},
	"krb5":        {"mit:kerberos_5"},
	"pcre2":       {"pcre:pcre2"},
	"tor":         {"torproject:tor"},
	"unbound":     {"nlnetlabs:unbound"},
	"nmap":        {"nmap:nmap"},
	"ghostscript": {"artifex:ghostscript"},
	"lua":         {"lua:lua"},
	"c-ares":      {"c-ares:c-ares", "c-ares_project:c-ares"},
	"jq":          {"jqlang:jq"},
	"tcpdump":     {"tcpdump:tcpdump"},
	"libpcap":     {"tcpdump:libpcap"},
	"nss":         {"mozilla:nss"},
	"libarchive":  {"libarchive:libarchive"},
	"libgcrypt":   {"gnupg:libgcrypt"},
	"libde265":    {"struktur:libde265"},
	"libheif":     {"struktur:libheif"},
	"webp":        {"webmproject:libwebp"},
	"freetype":    {"freetype:freetype"},
	"glib":        {"gnome:glib"},
	"libidn2":     {"gnu:libidn2"},
	"libevent":    {"libevent_project:libevent"},
	"libuv":       {"libuv:libuv"},
	"zlib":        {"zlib:zlib"},
	"expat":       {"libexpat_project:libexpat"},
	"libxml2":     {"xmlsoft:libxml2"},
	"git":         {"git-scm:git"},
	"bash":        {"gnu:bash"},
	"openssh":     {"openbsd:openssh"},
	"unixodbc":    {"unixodbc:unixodbc"},
	"tmux":        {"tmux_project:tmux"},
}

// homebrew reads the installed formulae (Cellar/<formula>/<version>). A formula is judged by its NVD product when
// brewProducts names one, and in any case by what it installs that has an exact identifier: Python and Node
// packages it carries, and its Go and Rust executables (linked onto PATH or not). The rest are not assessed;
// casks are applications and read from their bundles.
func (h *hostReader) homebrew() {
	var entries, notAssessed []string
	formulae, byProduct, byContents := 0, 0, 0
	for _, cellar := range h.glob("opt/homebrew/Cellar", "usr/local/Cellar", "home/linuxbrew/.linuxbrew/Cellar") {
		names, _ := os.ReadDir(cellar)
		for _, n := range names {
			versions, _ := os.ReadDir(filepath.Join(cellar, n.Name()))
			for _, v := range versions {
				if !v.IsDir() || strings.HasPrefix(v.Name(), ".") {
					continue
				}
				formulae++
				keg := filepath.Join(cellar, n.Name(), v.Name())
				contents, read := h.kegContents(keg)
				entries = append(entries, contents...)
				base, _, _ := strings.Cut(n.Name(), "@")
				if products, ok := brewProducts[base]; ok {
					ver := brewRevision.ReplaceAllString(v.Name(), "")
					for _, p := range products {
						entries = append(entries, productCPE(p, ver))
					}
					byProduct++
					continue
				}
				if read {
					byContents++
					continue
				}
				notAssessed = append(notAssessed, n.Name()+" "+v.Name())
			}
		}
	}
	detail := fmt.Sprintf("%s: %d by product, %d by their packages or binaries", count(formulae, "formula", "formulae"), byProduct, byContents)
	h.add("homebrew", detail, entries, notAssessed)
}

// kegContents is what one installed formula carries with an exact identifier; read is false when it carries
// nothing (its executables already read from PATH count).
func (h *hostReader) kegContents(keg string) (out []string, read bool) {
	for _, d := range globAll(filepath.Join(keg, "lib/python3*/site-packages"), filepath.Join(keg, "libexec/lib/python3*/site-packages"),
		filepath.Join(keg, "libexec/venv/lib/python3*/site-packages"), filepath.Join(keg, "Frameworks/Python.framework/Versions/*/lib/python3*/site-packages")) {
		out = append(out, pythonPackages(d)...)
	}
	for _, d := range globAll(filepath.Join(keg, "lib/node_modules"), filepath.Join(keg, "libexec/lib/node_modules")) {
		out = append(out, nodePackages(d, 0)...)
	}
	b := h.readBinaries(globAll(filepath.Join(keg, "bin"), filepath.Join(keg, "sbin"), filepath.Join(keg, "libexec/bin")))
	out = append(out, b.goEntries...)
	out = append(out, b.rustEntries...)
	return out, len(out) > 0 || b.judged > 0
}

var brewRevision = regexp.MustCompile(`_\d+$`)

func productCPE(vendorProduct, version string) string {
	vendor, product, _ := strings.Cut(vendorProduct, ":")
	return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", vendor, product, cpeEscape(version))
}

// cpeEscape quotes the characters CPE 2.3 formatted strings reserve.
func cpeEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(`\:*?!"#$%&'()+,/;<=>@[]^{|}~ `, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// appProducts names the NVD product of applications by bundle identifier, where the bundle's short version is
// the version NVD records. Each entry was checked against SecurityContext's product index; any other bundle is
// listed as not assessed.
var appProducts = map[string]string{
	"com.apple.Safari":          "apple:safari",
	"com.apple.dt.Xcode":        "apple:xcode",
	"com.google.Chrome":         "google:chrome",
	"org.mozilla.firefox":       "mozilla:firefox",
	"com.microsoft.VSCode":      "microsoft:visual_studio_code",
	"com.docker.docker":         "docker:desktop",
	"org.wireshark.Wireshark":   "wireshark:wireshark",
	"org.videolan.vlc":          "videolan:vlc_media_player",
	"com.teamviewer.TeamViewer": "teamviewer:teamviewer",
	"io.tailscale.ipn.macsys":   "tailscale:tailscale",
	"io.tailscale.ipn.macos":    "tailscale:tailscale",
	"com.1password.1password":   "1password:1password",
	"com.tdesktop.Telegram":     "telegram:telegram_desktop",
	"com.postmanlabs.mac":       "postman:postman",
}

// applications reads the bundles in /Applications and each user's ~/Applications.
func (h *hostReader) applications() {
	var entries, notAssessed []string
	bundles := h.glob(append([]string{"Applications/*.app", "Applications/Utilities/*.app"}, h.inHomes("Applications/*.app")...)...)
	for _, b := range bundles {
		info := appInfo(filepath.Join(b, "Contents", "Info.plist"))
		id, ver := info["CFBundleIdentifier"], info["CFBundleShortVersionString"]
		if ver == "" {
			ver = info["CFBundleVersion"]
		}
		name := strings.TrimSuffix(filepath.Base(b), ".app")
		if p, ok := appProducts[id]; ok && ver != "" {
			entries = append(entries, productCPE(p, ver))
			continue
		}
		notAssessed = append(notAssessed, strings.TrimSpace(name+" "+ver))
	}
	h.add("applications", count(len(bundles), "bundle", "bundles"), entries, notAssessed)
}

// appInfo reads the string values of an Info.plist's top-level dictionary. Binary property lists are converted
// with plutil, which every macOS has.
func appInfo(path string) map[string]string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	if bytes.HasPrefix(raw, []byte("bplist")) {
		if raw, err = exec.Command("plutil", "-convert", "xml1", "-o", "-", path).Output(); err != nil {
			return nil
		}
	}
	return plistStrings(raw)
}

func plistStrings(raw []byte) map[string]string {
	out := map[string]string{}
	dec := xml.NewDecoder(bytes.NewReader(raw))
	dec.Strict = false
	depth, key := 0, ""
	for {
		tok, err := dec.Token()
		if err != nil {
			return out
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if depth != 3 { // plist > dict > key|value
				continue
			}
			var text string
			if t.Name.Local == "key" || t.Name.Local == "string" {
				if dec.DecodeElement(&text, &t) != nil {
					return out
				}
				depth--
			}
			switch t.Name.Local {
			case "key":
				key = text
			case "string":
				if key != "" {
					out[key] = strings.TrimSpace(text)
				}
				key = ""
			default:
				key = ""
			}
		case xml.EndElement:
			depth--
		}
	}
}
