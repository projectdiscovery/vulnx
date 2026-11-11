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
//                     a table below names their NVD product, and listed as not assessed otherwise. A component is
//                     never mapped by its name alone: a wrong product that exists would be judged in its place. A
//                     product the index does not know is listed as not checked (DropUnknownProducts). Applications
//                     built on the Electron framework are read too: the framework and their bundled npm packages.
//
// Nothing is uploaded but these names and versions.

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"debug/buildinfo"
	"debug/elf"
	"debug/gosym"
	"debug/macho"
	"encoding/binary"
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
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// HostInventory is what vulnx found on a machine.
type HostInventory struct {
	OS          string                  `json:"os"`                  // "debian 12", "macOS 26.4", ...
	Source      string                  `json:"os_source,omitempty"` // where the OS packages came from: dpkg, rpm, apk, sw_vers
	Entries     []string                `json:"-"`                   // purls and CPEs, each once (the result's items)
	FoundIn     map[string][]string     `json:"found_in"`            // entry -> where it was found: a binary, an app, a formula, a directory
	Sources     []HostSource            `json:"sources"`             // what each reader found
	NotAssessed []HostComponent         `json:"not_assessed"`        // read, but with no identifier SecurityContext judges exactly
	NotRead     []string                `json:"not_read"`            // what no reader covers
	GoBinaries  map[string][]HostBinary `json:"-"`                   // Go entry -> the binaries linking it, for MarkReachability
	Fixes       map[string]HostFix      `json:"fixes"`               // FoundIn label -> how to update what is there
	EntrySource map[string]string       `json:"-"`                   // entry -> the source (HostSource.Name) that counted it
	DataOnly    []HostComponent         `json:"data_only"`           // installed, but nothing in them runs: nothing to check
	Note        string                  `json:"-"`                   // per source counts, and what is not read, as text
}

// HostFix is how to update what was found in one place (a FoundIn label): a command the components or Target are
// appended to, or, with no command, Note says what to do.
type HostFix struct {
	Kind    string `json:"kind"`              // macos, app, brew, go-install, cargo, binary, pip, npm, gem, apt, dnf, apk, system
	Command string `json:"command,omitempty"` // "brew upgrade", "/opt/homebrew/bin/python3.12 -m pip install -U", ...
	Target  string `json:"target,omitempty"`  // what the command names for this place (a formula, a Go package); empty: the components
	Note    string `json:"note,omitempty"`    // what to do when there is no command ("update Wireshark")
}

// HostBinary is an executable vulnx read: its real path and the name it was found under (a PATH link's).
type HostBinary struct{ Path, Name string }

// HostComponent is an installed component vulnx read but could not identify exactly.
type HostComponent struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Source  string `json:"source"`
	Reason  string `json:"reason,omitempty"` // why, when it is not the usual "no exact identifier"
}

// HostSource is one reader's count: Sent components went into Entries, NotAssessed were read but not sent.
type HostSource struct {
	Name        string `json:"name"`
	Sent        int    `json:"checked"`
	NotAssessed int    `json:"not_assessed"`
	Detail      string `json:"read_from,omitempty"` // "9 binaries", ...
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
	h := newHostReader(root, goos)
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

func newHostReader(root, goos string) *hostReader {
	return &hostReader{root: root, goos: goos, seen: map[string]bool{}, binSeen: map[string]bool{},
		inv: HostInventory{FoundIn: map[string][]string{}, GoBinaries: map[string][]HostBinary{}, Fixes: map[string]HostFix{},
			EntrySource: map[string]string{}}}
}

type hostReader struct {
	root, goos string
	inv        HostInventory
	seen       map[string]bool // entries already sent
	binSeen    map[string]bool // executables already read, by real path: true when Go or Rust
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

var homePrefix = regexp.MustCompile(`^/(Users|home)/[^/]+|^/root|^/var/root`)

// label names a package directory for display: under a home as ~, cut at the interpreter's lib directory
// (~/.pyenv/versions/3.10.7, /opt/homebrew).
func (h *hostReader) label(dir string) string {
	rel, err := filepath.Rel(h.root, dir)
	if err != nil {
		rel = dir
	}
	p := homePrefix.ReplaceAllString("/"+filepath.ToSlash(rel), "~")
	for _, cut := range []string{"/lib/python", "/lib/node_modules", "/lib/ruby", "/specifications", "/site-packages"} {
		if i := strings.Index(p, cut); i > 0 {
			p = p[:i]
		}
	}
	return p
}

// fix records how to update a place, the first reader's word standing.
func (h *hostReader) fix(label string, f HostFix) {
	if _, ok := h.inv.Fixes[label]; !ok {
		h.inv.Fixes[label] = f
	}
}

var pythonLib = regexp.MustCompile(`/lib/(python3\.\d+)/(site|dist)-packages$`)

// pythonPlace labels a site-packages directory with its interpreter and says how its packages are updated: that
// interpreter's pip (a user site with --user); the Command Line Tools' Python comes with them.
func (h *hostReader) pythonPlace(dir string) (string, HostFix) {
	label := h.label(dir)
	path := filepath.ToSlash(dir)
	switch {
	case strings.Contains(path, "/Library/Developer/CommandLineTools/"):
		return label, HostFix{Kind: "system", Note: "comes with the Command Line Tools: Software Update updates it"}
	case strings.Contains(path, "/Library/Python/"): // ~/Library/Python/3.9/lib/python/site-packages
		v := filepath.Base(filepath.Dir(filepath.Dir(filepath.Dir(dir))))
		return label + " (python" + v + ")", HostFix{Kind: "pip", Command: "python" + v + " -m pip install --user -U"}
	}
	m := pythonLib.FindStringSubmatch(path)
	if m == nil {
		return label, HostFix{Kind: "pip", Command: "python3 -m pip install -U"}
	}
	label += " (" + m[1] + ")"
	if strings.Contains(path, "/.local/lib/") {
		return label, HostFix{Kind: "pip", Command: m[1] + " -m pip install --user -U"}
	}
	prefix := strings.TrimSuffix(path, m[0])
	if h.root != "/" {
		prefix = "/" + strings.TrimPrefix(strings.TrimPrefix(prefix, filepath.ToSlash(h.root)), "/")
	}
	return label, HostFix{Kind: "pip", Command: prefix + "/bin/" + m[1] + " -m pip install -U"}
}

// found is an entry and where it was found.
type found struct{ entry, in string }

func foundIn(in string, entries []string) []found {
	out := make([]found, len(entries))
	for i, e := range entries {
		out[i] = found{e, in}
	}
	return out
}

// add records entries for one source; an entry another source already sent counts once, under the first.
func (h *hostReader) add(name, detail string, entries []found, notAssessed []HostComponent) {
	src := HostSource{Name: name, Detail: detail, NotAssessed: len(notAssessed)}
	for _, f := range entries {
		if !h.seen[f.entry] {
			h.seen[f.entry] = true
			h.inv.Entries = append(h.inv.Entries, f.entry)
			h.inv.EntrySource[f.entry] = name
			src.Sent++
		}
		if f.in != "" && !slices.Contains(h.inv.FoundIn[f.entry], f.in) {
			h.inv.FoundIn[f.entry] = append(h.inv.FoundIn[f.entry], f.in)
		}
	}
	for _, c := range notAssessed {
		c.Source = name
		h.inv.NotAssessed = append(h.inv.NotAssessed, c)
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
	if len(h.inv.NotRead) > 0 {
		note += "\nnot read: " + strings.Join(h.inv.NotRead, "; ")
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
	h.fix("macOS", HostFix{Kind: "macos", Note: "Software Update (softwareupdate --install --all)"})
	h.add("macOS", "sw_vers", foundIn("macOS", []string{fmt.Sprintf("cpe:2.3:o:apple:macos:%s:*:*:*:*:*:*:*", ver)}), nil)
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
		h.inv.NotRead = append(h.inv.NotRead, fmt.Sprintf("SecurityContext has advisories for Debian, Ubuntu, Alpine, RHEL, Rocky and AlmaLinux; %s packages will come back undetermined", id))
	}
	source, entries, err := linuxPackages(h.root, id, version)
	if err != nil {
		h.inv.NotRead = append(h.inv.NotRead, err.Error())
		return nil
	}
	h.inv.Source = source
	h.fix(source, map[string]HostFix{
		"dpkg": {Kind: "apt", Command: "sudo apt-get install --only-upgrade"},
		"rpm":  {Kind: "dnf", Command: "sudo dnf upgrade"},
		"apk":  {Kind: "apk", Command: "sudo apk upgrade"},
	}[source])
	h.add(source, "", foundIn(source, entries), nil)
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
	var py []found
	for _, d := range dirs {
		label, f := h.pythonPlace(d)
		h.fix(label, f)
		py = append(py, foundIn(label, pythonPackages(d))...)
	}
	h.add("python", count(len(dirs), "site-packages dir", "site-packages dirs"), py, nil)

	dirs = h.glob(nodeDirs...)
	var node []found
	for _, d := range dirs {
		// a vulnerable dependency of a global tool is updated with the tool
		h.fix(h.label(d), HostFix{Kind: "npm", Command: "npm update -g"})
		node = append(node, foundIn(h.label(d), nodePackages(d, 0))...)
	}
	h.add("npm", count(len(dirs), "global node_modules", "global node_modules"), node, nil)

	dirs = h.glob(gemDirs...)
	var gems []found
	for _, d := range dirs {
		if strings.Contains(filepath.ToSlash(d), "/System/Library/") {
			h.fix(h.label(d), HostFix{Kind: "system", Note: "comes with macOS: updated with it"})
		} else {
			h.fix(h.label(d), HostFix{Kind: "gem", Command: "gem update"})
		}
		gems = append(gems, foundIn(h.label(d), rubyGems(d))...)
		gems = append(gems, foundIn(h.label(d), rubyGems(filepath.Join(d, "default")))...)
	}
	h.add("gems", count(len(dirs), "gem dir", "gem dirs"), gems, nil)
	h.inv.NotRead = append(h.inv.NotRead, "virtualenvs and project dependencies (scan their lockfiles)")
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
				out = append(out, npmPurl(pj.Name, pj.Version))
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
	h.inv.NotRead = append(h.inv.NotRead, "Rust binaries built without an embedded crate list; other compiled programs no package manager installed")
}

type binaryModules struct {
	goEntries, rustEntries []found
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
			if mods, renamed, main, ok := goModules(real); ok {
				h.fix(e.Name(), binaryFix(e.Name(), real, main))
				b.goBins++
				b.goEntries = append(b.goEntries, foundIn(e.Name(), mods)...)
				for _, m := range mods {
					if !renamed[m] {
						h.inv.GoBinaries[m] = append(h.inv.GoBinaries[m], HostBinary{Path: real, Name: e.Name()})
					}
				}
			} else if crates, ok := rustCrates(real); ok {
				h.fix(e.Name(), binaryFix(e.Name(), real, ""))
				b.rustBins++
				b.rustEntries = append(b.rustEntries, foundIn(e.Name(), crates)...)
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
// renamed holds the entries of modules replaced by another module path: their code is compiled under the original
// import paths, so an advisory's function names for the replacement cannot be looked up in the binary.
// main is the binary's main package path, what `go install` names.
func goModules(path string) (out []string, renamed map[string]bool, main string, ok bool) {
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		return nil, nil, "", false
	}
	renamed = map[string]bool{}
	if v := strings.TrimPrefix(bi.GoVersion, "go"); v != "" {
		v, _, _ = strings.Cut(v, " ") // "go1.22.1 X:boringcrypto"
		out = append(out, "pkg:golang/stdlib@"+url.PathEscape(v))
	}
	mods := append([]*debug.Module{&bi.Main}, bi.Deps...)
	for _, m := range mods {
		moved := m.Replace != nil && m.Replace.Path != m.Path
		if m.Replace != nil {
			m = m.Replace
		}
		if m.Path == "" || m.Version == "" || m.Version == "(devel)" {
			continue
		}
		entry := fmt.Sprintf("pkg:golang/%s@%s", m.Path, url.PathEscape(m.Version))
		out = append(out, entry)
		if moved {
			renamed[entry] = true
		}
	}
	return out, renamed, bi.Path, true
}

var cellarFormula = regexp.MustCompile(`/Cellar/([^/]+)/`)

// binaryFix says how a Go or Rust executable is updated: by its Homebrew formula when it lives in a Cellar,
// `go install <main package>@latest` from a Go bin directory, `cargo install` from Cargo's, else by hand.
func binaryFix(name, real, main string) HostFix {
	path := filepath.ToSlash(real)
	switch {
	case cellarFormula.MatchString(path):
		return HostFix{Kind: "brew", Command: "brew upgrade", Target: cellarFormula.FindStringSubmatch(path)[1]}
	case strings.Contains(path, "/go/bin/") && strings.Contains(strings.SplitN(main, "/", 2)[0], "."):
		// a main package with a module path (not command-line-arguments: a binary built from loose files)
		return HostFix{Kind: "go-install", Command: "go install", Target: main + "@latest"}
	case strings.Contains(path, "/.cargo/bin/"):
		return HostFix{Kind: "cargo", Command: "cargo install", Target: name}
	}
	return HostFix{Kind: "binary", Target: name, Note: "update " + name + " (" + real + ")"}
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
	// each product below lists the formula's own source repository (the top-level url, homepage or head of its
	// formula file) in SecurityContext's index: a join on the repository, not on the name
	"abseil":     {"abseil:common_libraries"},
	"brotli":     {"google:brotli"},
	"fmt":        {"fmt:fmt"},
	"fribidi":    {"gnu:fribidi"},
	"gd":         {"libgd:libgd"},
	"ghidra":     {"nsa:ghidra"},
	"graphite2":  {"sil:graphite2"},
	"harfbuzz":   {"harfbuzz_project:harfbuzz"},
	"icu4c":      {"icu-project:international_components_for_unicode", "unicode:international_components_for_unicode"},
	"jasper":     {"jasper_project:jasper"},
	"jbig2dec":   {"artifex:jbig2dec"},
	"jpeg-turbo": {"d.r.commander:libjpeg-turbo", "libjpeg-turbo:libjpeg-turbo"},
	"jpeg-xl":    {"libjxl_project:libjxl"},
	"leptonica":  {"leptonica:leptonica"},
	"libavif":    {"aomedia:libavif"},
	"libnghttp2": {"nghttp2:nghttp2"},
	"libngtcp2":  {"tatsuhiro-t:ngtcp2"},
	"libusb":     {"libusb:libusb"},
	"libvpx":     {"webmproject:libvpx"},
	"llama.cpp":  {"ggml:llama.cpp"},
	"lz4":        {"lz4_project:lz4"},
	"net-snmp":   {"net-snmp:net-snmp"},
	"nvm":        {"openjsf:node_version_manager"},
	"oniguruma":  {"oniguruma_project:oniguruma"},
	"openexr":    {"openexr:openexr"},
	"openjpeg":   {"uclouvain:openjpeg"},
	"p11-kit":    {"p11-kit_project:p11-kit"},
	"pnpm":       {"pnpm:pnpm"},
	"pyenv":      {"pyenv:pyenv"},
	"sdl2":       {"libsdl:simple_directmedia_layer"},
	"squashfs":   {"squashfs-tools_project:squashfs-tools", "squashfs_project:squashfs"},
	"tesseract":  {"tesseract-ocr:tesseract_ocr"},
	"tidy-html5": {"htacg:tidy"},
	"uv":         {"astral:uv"},
	"z3":         {"microsoft:z3"},
	"zstd":       {"facebook:zstandard"},
}

// homebrew reads the installed formulae (Cellar/<formula>/<version>). A formula is judged by its NVD product when
// brewProducts names one, and in any case by what it installs that has an exact identifier: Python and Node
// packages it carries, and its Go and Rust executables (linked onto PATH or not). The rest are not assessed;
// casks are applications and read from their bundles.
func (h *hostReader) homebrew() {
	var entries []found
	var notAssessed []HostComponent
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
				in := n.Name() + " (formula)"
				h.fix(in, HostFix{Kind: "brew", Command: "brew upgrade", Target: n.Name()})
				base, _, _ := strings.Cut(n.Name(), "@")
				if products, ok := brewProducts[base]; ok {
					ver := brewRevision.ReplaceAllString(v.Name(), "")
					for _, p := range products {
						entries = append(entries, found{productCPE(p, ver), in})
					}
					byProduct++
					continue
				}
				if read {
					byContents++
					continue
				}
				if !hasExecutable(keg) {
					h.inv.DataOnly = append(h.inv.DataOnly, HostComponent{Name: n.Name(), Version: v.Name(), Source: "homebrew"})
					continue
				}
				notAssessed = append(notAssessed, HostComponent{Name: n.Name(), Version: v.Name()})
			}
		}
	}
	detail := fmt.Sprintf("%s: %d by product, %d by their packages or binaries", count(formulae, "formula", "formulae"), byProduct, byContents)
	h.add("homebrew", detail, entries, notAssessed)
}

// kegContents is what one installed formula carries with an exact identifier; read is false when it carries
// nothing (its executables already read from PATH count).
func (h *hostReader) kegContents(keg string) (out []found, read bool) {
	in := filepath.Base(filepath.Dir(keg)) + " (formula)"
	h.fix(in, HostFix{Kind: "brew", Command: "brew upgrade", Target: filepath.Base(filepath.Dir(keg))})
	for _, d := range globAll(filepath.Join(keg, "lib/python3*/site-packages"), filepath.Join(keg, "libexec/lib/python3*/site-packages"),
		filepath.Join(keg, "libexec/venv/lib/python3*/site-packages"), filepath.Join(keg, "Frameworks/Python.framework/Versions/*/lib/python3*/site-packages")) {
		out = append(out, foundIn(in, pythonPackages(d))...)
	}
	for _, d := range globAll(filepath.Join(keg, "lib/node_modules"), filepath.Join(keg, "libexec/lib/node_modules")) {
		out = append(out, foundIn(in, nodePackages(d, 0))...)
	}
	b := h.readBinaries(globAll(filepath.Join(keg, "bin"), filepath.Join(keg, "sbin"), filepath.Join(keg, "libexec/bin")))
	out = append(out, b.goEntries...)
	out = append(out, b.rustEntries...)
	return out, len(out) > 0 || b.judged > 0
}

// hasExecutable is whether anything under dir can run: a regular file with an execute bit, or a library.
// A keg without one (certificates, schemas, headers) is data: there is nothing in it to check.
func hasExecutable(dir string) bool {
	found := false
	walked := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if found {
			return filepath.SkipAll
		}
		if d.Type().IsRegular() {
			ext := filepath.Ext(path)
			if st, err := d.Info(); err == nil && (st.Mode()&0o111 != 0 || ext == ".dylib" || ext == ".so" || ext == ".a") {
				found = true
			}
		}
		return nil
	})
	// a keg that could not be read through is not called data: it stays "not checked"
	return found || walked != nil
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
	var entries []found
	var notAssessed []HostComponent
	bundles := h.glob(append([]string{"Applications/*.app", "Applications/Utilities/*.app"}, h.inHomes("Applications/*.app")...)...)
	for _, b := range bundles {
		info := appInfo(filepath.Join(b, "Contents", "Info.plist"))
		id, ver := info["CFBundleIdentifier"], info["CFBundleShortVersionString"]
		if ver == "" {
			ver = info["CFBundleVersion"]
		}
		name := strings.TrimSuffix(filepath.Base(b), ".app")
		bundled := electronContents(b)
		if len(bundled) > 0 {
			h.fix(name+".app", HostFix{Kind: "app", Target: name, Note: "update " + name})
			entries = append(entries, foundIn(name+".app", bundled)...)
		}
		if p, ok := appProducts[id]; ok && ver != "" {
			if id == "com.apple.Safari" {
				h.fix(name+".app", HostFix{Kind: "macos", Note: "Software Update (softwareupdate --install --all)"})
			} else {
				h.fix(name+".app", HostFix{Kind: "app", Target: name, Note: "update " + name})
			}
			entries = append(entries, found{productCPE(p, ver), name + ".app"})
			continue
		}
		if len(bundled) > 0 {
			continue
		}
		notAssessed = append(notAssessed, HostComponent{Name: name, Version: ver})
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

// MarkReachability marks a host scan's Go findings by what each binary links, from the advisories' function lists
// (res.GoFunctions). A row is reachable when a binary carrying the module version links a function its advisory
// names as affected, and not_reachable when none of those binaries links any function of the packages it names; it
// stays unmarked (unknown) without a list, or when a binary links the package but none of the functions by name
// (goFunctions.verdict). Each item gets, per binary, reachable / not_reachable / unknown. Binaries are read one at
// a time: a large Go binary links tens of thousands of functions.
func (inv HostInventory) MarkReachability(res *StackResult) {
	type use struct {
		item int
		bin  HostBinary
	}
	byPath := map[string][]use{}
	for i, it := range res.Items {
		if it.Status != "affected" {
			continue
		}
		for _, b := range inv.GoBinaries[it.Input] {
			byPath[b.Path] = append(byPath[b.Path], use{i, b})
		}
	}
	rowState := map[int]map[int]string{} // item -> row -> the most reachable verdict over its binaries
	rank := map[string]int{"reachable": 0, "unknown": 1, "not_reachable": 2}
	for path, uses := range byPath {
		fns, err := goFunctionTable(path)
		for _, u := range uses {
			it := &res.Items[u.item]
			if it.Reachability == nil {
				it.Reachability = &ItemReachability{}
			}
			if rowState[u.item] == nil {
				rowState[u.item] = map[int]string{}
			}
			state := "not_reachable" // the binary's: the most reachable of its rows
			for r, row := range it.AdvisoryRows {
				v := "unknown"
				if lists, ok := res.GoFunctions[it.Package][row.AdvisoryID]; ok && err == nil {
					v = fns.verdict(lists)
				}
				if prev, ok := rowState[u.item][r]; !ok || rank[v] < rank[prev] {
					rowState[u.item][r] = v
				}
				if rank[v] < rank[state] {
					state = v
				}
			}
			switch state {
			case "reachable":
				it.Reachability.Reachable = append(it.Reachability.Reachable, u.bin.Name)
			case "not_reachable":
				it.Reachability.NotReachable = append(it.Reachability.NotReachable, u.bin.Name)
			default:
				it.Reachability.Unknown = append(it.Reachability.Unknown, u.bin.Name)
			}
		}
	}
	for i, rows := range rowState {
		for r, v := range rows {
			if v != "unknown" {
				res.Items[i].AdvisoryRows[r].Reachability = v
			}
		}
	}
}

// goFunctions is a Go binary's function table: every function it links, as the advisories name them
// (path.Func, path.Type.Method), and the packages they are in.
type goFunctions struct{ funcs, packages map[string]bool }

var goTypeParams = regexp.MustCompile(`\[[^\]]*\]`)

// goFunctionTable reads a Go executable's pclntab (present in stripped binaries too: the runtime needs it).
func goFunctionTable(path string) (goFunctions, error) {
	tab, text, err := pclntab(path)
	if err != nil {
		return goFunctions{}, err
	}
	t, err := gosym.NewTable(nil, gosym.NewLineTable(tab, text))
	if err != nil {
		return goFunctions{}, err
	}
	out := goFunctions{funcs: map[string]bool{}, packages: map[string]bool{}}
	for _, f := range t.Funcs {
		// "net/http.(*Client).Do" -> "net/http.Client.Do"; "pkg.Map[...].Get" -> "pkg.Map.Get"; a closure
		// ("pkg.F.func1") or method value ("pkg.T.M-fm") counts as its function
		name := strings.NewReplacer("(*", "", ")", "").Replace(goTypeParams.ReplaceAllString(f.Name, ""))
		name = strings.TrimSuffix(name, "-fm")
		if i := strings.Index(name, ".func"); i > 0 {
			name = name[:i]
		}
		out.funcs[name] = true
		slash := strings.LastIndex(name, "/")
		if dot := strings.Index(name[slash+1:], "."); dot > 0 {
			out.packages[name[:slash+1+dot]] = true
		}
	}
	return out, nil
}

// verdict is what the binary's function table says of an advisory's lists: reachable when it links a listed
// function (a package listed with no functions: any of it), not_reachable when it links no function of any listed
// package, and unknown when it links the package but none of the listed functions by name: a function the compiler
// inlined at every call has no entry of its own, so its absence proves nothing (strings.Contains is in no table).
func (g goFunctions) verdict(lists []AffectedPackage) string {
	linkedPackage := false
	for _, l := range lists {
		if !g.packages[l.Package] {
			continue
		}
		if len(l.Functions) == 0 {
			return "reachable"
		}
		linkedPackage = true
		for _, f := range l.Functions {
			if g.funcs[l.Package+"."+f] {
				return "reachable"
			}
		}
	}
	if linkedPackage {
		return "unknown"
	}
	return "not_reachable"
}

// pclntab returns a Go executable's pclntab section and the address of its text section (ELF, Mach-O, universal).
func pclntab(path string) (tab []byte, text uint64, err error) {
	if f, err := elf.Open(path); err == nil {
		defer func() { _ = f.Close() }()
		s, t := f.Section(".gopclntab"), f.Section(".text")
		if s == nil || t == nil {
			return nil, 0, fmt.Errorf("%s: no Go function table", path)
		}
		tab, err := s.Data()
		return tab, t.Addr, err
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
		return nil, 0, fmt.Errorf("%s: not an ELF or Mach-O executable", path)
	}
	s, t := mf.Section("__gopclntab"), mf.Section("__text")
	if s == nil || t == nil {
		return nil, 0, fmt.Errorf("%s: no Go function table", path)
	}
	tab, err = s.Data()
	return tab, t.Addr, err
}

// CycloneDX is the inventory as a CycloneDX 1.5 JSON SBOM: one component per entry, by its purl or CPE, with where
// it was found as properties. It is what --host checked, in a form other tools read and SecurityContext stores.
func (inv HostInventory) CycloneDX(now time.Time) ([]byte, error) {
	type property struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	type component struct {
		Type       string     `json:"type"`
		BOMRef     string     `json:"bom-ref"`
		Name       string     `json:"name"`
		Version    string     `json:"version,omitempty"`
		PURL       string     `json:"purl,omitempty"`
		CPE        string     `json:"cpe,omitempty"`
		Properties []property `json:"properties,omitempty"`
	}
	components := make([]component, 0, len(inv.Entries))
	for _, e := range inv.Entries {
		c := component{Type: "library", BOMRef: e}
		if strings.HasPrefix(e, "cpe:2.3:") {
			f := strings.Split(e, ":")
			c.CPE, c.Type = e, "application"
			if len(f) > 5 {
				c.Name, c.Version = f[4], strings.ReplaceAll(f[5], `\`, "")
				if f[2] == "o" {
					c.Type = "operating-system"
				}
			}
		} else {
			c.PURL = e
			body, _, _ := strings.Cut(strings.TrimPrefix(e, "pkg:"), "?")
			_, rest, _ := strings.Cut(body, "/")
			c.Name = rest
			if at := strings.LastIndex(rest, "@"); at > 0 {
				c.Name, c.Version = rest[:at], rest[at+1:]
			}
			if u, err := url.PathUnescape(c.Name); err == nil {
				c.Name = u
			}
			if u, err := url.PathUnescape(c.Version); err == nil {
				c.Version = u
			}
		}
		if src := inv.EntrySource[e]; src != "" {
			c.Properties = append(c.Properties, property{"vulnx:source", src})
		}
		for _, in := range inv.FoundIn[e] {
			c.Properties = append(c.Properties, property{"vulnx:found_in", in})
		}
		components = append(components, c)
	}
	return json.MarshalIndent(map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"version":     1,
		"metadata": map[string]any{
			"timestamp": now.UTC().Format(time.RFC3339),
			"tools":     []map[string]string{{"name": "vulnx"}},
			"component": map[string]string{"type": "device", "bom-ref": "host", "name": inv.OS},
		},
		"components": components,
	}, "", "  ")
}

// electronContents is what an application built on the Electron framework carries with an exact identifier: the
// framework itself, as the npm package electron at the framework's version, and the npm packages in its bundle
// (the app.asar archive, its unpacked directory, or a plain app directory). nil for any other application. The
// browser engine inside the framework is not sent: the framework backports fixes, so its engine version says
// nothing exact.
func electronContents(bundle string) []string {
	info := appInfo(filepath.Join(bundle, "Contents/Frameworks/Electron Framework.framework/Resources/Info.plist"))
	version := info["CFBundleVersion"]
	if version == "" {
		return nil
	}
	out := []string{"pkg:npm/electron@" + url.PathEscape(version)}
	res := filepath.Join(bundle, "Contents/Resources")
	out = append(out, asarPackages(filepath.Join(res, "app.asar"))...)
	out = append(out, nodePackages(filepath.Join(res, "app.asar.unpacked/node_modules"), 0)...)
	return append(out, nodePackages(filepath.Join(res, "app/node_modules"), 0)...)
}

// asarPackages reads the npm packages inside an asar archive without unpacking it: the archive starts with a JSON
// index of its files (offset and size each), and every package.json under a node_modules directory names one.
func asarPackages(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	var head [16]byte
	if _, err := io.ReadFull(f, head[:]); err != nil {
		return nil
	}
	headerSize, jsonSize := binary.LittleEndian.Uint32(head[4:8]), binary.LittleEndian.Uint32(head[12:16])
	if jsonSize == 0 || jsonSize > 64<<20 || jsonSize > headerSize {
		return nil
	}
	raw := make([]byte, jsonSize)
	if _, err := io.ReadFull(f, raw); err != nil {
		return nil
	}
	type node struct {
		Files  map[string]*node `json:"files"`
		Offset string           `json:"offset"`
		Size   int64            `json:"size"`
	}
	var root node
	if json.Unmarshal(raw, &root) != nil {
		return nil
	}
	base := int64(8) + int64(headerSize)
	var out []string
	var walk func(n *node, inModules bool, depth int)
	walk = func(n *node, inModules bool, depth int) {
		if n == nil || depth > 64 {
			return
		}
		for name, child := range n.Files {
			if child == nil {
				continue
			}
			if child.Files != nil {
				walk(child, inModules || name == "node_modules", depth+1)
				continue
			}
			// a file packed in the archive (one kept beside it has no offset and is read from the unpacked directory)
			if !inModules || name != "package.json" || child.Offset == "" || child.Size <= 0 || child.Size > 1<<20 {
				continue
			}
			offset, err := strconv.ParseInt(child.Offset, 10, 64)
			if err != nil {
				continue
			}
			body := make([]byte, child.Size)
			if _, err := f.ReadAt(body, base+offset); err != nil {
				continue
			}
			var pj struct{ Name, Version string }
			if json.Unmarshal(body, &pj) == nil && pj.Name != "" && pj.Version != "" {
				out = append(out, npmPurl(pj.Name, pj.Version))
			}
		}
	}
	walk(&root, false, 0)
	sort.Strings(out)
	return out
}

func npmPurl(name, version string) string {
	if strings.HasPrefix(name, "@") {
		name = "%40" + strings.TrimPrefix(name, "@")
	}
	return fmt.Sprintf("pkg:npm/%s@%s", name, url.PathEscape(version))
}

// DropUnknownProducts takes out of a checked result the products SecurityContext does not know (an item it marks
// seen: none). Such a product reads clean only because no rule names it: it was not checked, and is listed so.
func (inv *HostInventory) DropUnknownProducts(res *StackResult) {
	unknown := map[string]bool{}
	kept := res.Items[:0]
	for _, it := range res.Items {
		if it.Seen != "none" || it.Status != "clean" || !strings.HasPrefix(it.Input, "cpe:") {
			kept = append(kept, it)
			continue
		}
		unknown[it.Input] = true
		src := inv.EntrySource[it.Input]
		name := strings.TrimPrefix(it.Package, "cpe/")
		if in := inv.FoundIn[it.Input]; len(in) > 0 {
			name = in[0]
		}
		inv.NotAssessed = append(inv.NotAssessed, HostComponent{Name: name, Version: it.Version, Source: src,
			Reason: "its product (" + strings.TrimPrefix(it.Package, "cpe/") + ") is not in the index"})
		for i := range inv.Sources {
			if inv.Sources[i].Name == src {
				inv.Sources[i].Sent--
				inv.Sources[i].NotAssessed++
			}
		}
		res.Summary.Clean--
		res.Summary.Packages--
		res.Total--
	}
	res.Items = kept
	if len(unknown) == 0 {
		return
	}
	entries := inv.Entries[:0]
	for _, e := range inv.Entries {
		if !unknown[e] {
			entries = append(entries, e)
		}
	}
	inv.Entries = entries
}
