package vulnx

// Lockfiles and manifests read here, for a folder scan: each names the package versions a project installs, as
// purls. A dependency that is not a registry release (a git checkout, a local path, a link) has no version
// SecurityContext can judge; it is returned as not checked, with why.

import (
	"bufio"
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// lockResult is what one lockfile names: purls to check and dependencies that cannot be.
type lockResult struct {
	entries []string
	skipped []HostComponent
}

func (r *lockResult) add(purl string) {
	if purl != "" && !slices.Contains(r.entries, purl) {
		r.entries = append(r.entries, purl)
	}
}

func (r *lockResult) skip(name, version, reason string) {
	for _, c := range r.skipped {
		if c.Name == name && c.Version == version {
			return
		}
	}
	r.skipped = append(r.skipped, HostComponent{Name: name, Version: version, Reason: reason})
}

// sortedKeys is a map's keys in order, so a lockfile reads the same way every time.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// lockParser parses one kind of lockfile.
type lockParser func(raw []byte) (lockResult, error)

// lockParsers are the lockfiles read, by file name.
var lockParsers = map[string]lockParser{
	"package-lock.json":   parseNPMLock,
	"npm-shrinkwrap.json": parseNPMLock,
	"yarn.lock":           parseYarnLock,
	"pnpm-lock.yaml":      parsePNPMLock,
	"Pipfile.lock":        parsePipfileLock,
	"poetry.lock":         parsePoetryLock,
	"uv.lock":             parseUVLock,
	"go.mod":              parseGoMod,
	"Cargo.lock":          parseCargoLock,
	"Gemfile.lock":        parseGemfileLock,
	"composer.lock":       parseComposerLock,
}

// lockParserFor is the parser for a file name: a lockfile's, or requirements*.txt's.
func lockParserFor(name string) lockParser {
	if p := lockParsers[name]; p != nil {
		return p
	}
	if strings.HasPrefix(name, "requirements") && strings.HasSuffix(name, ".txt") {
		return parseRequirements
	}
	return nil
}

// npmVersionSource is why an npm dependency's version is not a registry release ("" when it is one).
func npmVersionSource(spec string) string {
	switch {
	case strings.HasPrefix(spec, "file:"), strings.HasPrefix(spec, "link:"), strings.HasPrefix(spec, "portal:"),
		strings.HasPrefix(spec, "workspace:"):
		return "a local path"
	case strings.HasPrefix(spec, "git"), strings.HasPrefix(spec, "github:"), strings.HasPrefix(spec, "gitlab:"),
		strings.HasPrefix(spec, "bitbucket:"), strings.Contains(spec, "codeload.github.com"), strings.Contains(spec, ".git#"):
		return "a git dependency"
	case strings.HasPrefix(spec, "http:"), strings.HasPrefix(spec, "https:"):
		return "a tarball URL"
	}
	return ""
}

// parseNPMLock reads package-lock.json and npm-shrinkwrap.json: lockfile v2 and v3 list every installed package
// under "packages", by its node_modules path; v1 nests "dependencies". Workspace members and linked packages are
// local code and are left out.
func parseNPMLock(raw []byte) (lockResult, error) {
	var lock struct {
		Packages map[string]struct {
			Name     string `json:"name"`
			Version  string `json:"version"`
			Resolved string `json:"resolved"`
			Link     bool   `json:"link"`
		} `json:"packages"`
		Dependencies map[string]npmV1Dep `json:"dependencies"`
	}
	if err := json.Unmarshal(raw, &lock); err != nil {
		return lockResult{}, err
	}
	var r lockResult
	if len(lock.Packages) > 0 {
		for _, key := range sortedKeys(lock.Packages) {
			p := lock.Packages[key]
			i := strings.LastIndex(key, "node_modules/")
			if i < 0 || p.Link {
				continue // the root project, a workspace member, or a link to one
			}
			name := key[i+len("node_modules/"):]
			if p.Name != "" {
				name = p.Name // an alias installs another package under its own name
			}
			// a registry tarball is a release; a git checkout or a local path is not
			if why := npmVersionSource(p.Resolved); why == "a git dependency" || why == "a local path" {
				r.skip(name, p.Version, why)
				continue
			}
			if why := npmVersionSource(p.Version); why != "" {
				r.skip(name, p.Version, why)
				continue
			}
			if p.Version != "" {
				r.add(npmPurl(name, p.Version))
			}
		}
		return r, nil
	}
	var walk func(deps map[string]npmV1Dep, depth int)
	walk = func(deps map[string]npmV1Dep, depth int) {
		if depth > 64 {
			return
		}
		for _, name := range sortedKeys(deps) {
			d := deps[name]
			version := d.Version
			if real, ok := strings.CutPrefix(version, "npm:"); ok { // an alias: npm:real@1.2.3
				if at := strings.LastIndex(real, "@"); at > 0 {
					name, version = real[:at], real[at+1:]
				}
			}
			if why := npmVersionSource(version); why != "" {
				r.skip(name, version, why)
			} else if version != "" {
				r.add(npmPurl(name, version))
			}
			walk(d.Dependencies, depth+1)
		}
	}
	walk(lock.Dependencies, 0)
	return r, nil
}

type npmV1Dep struct {
	Version      string              `json:"version"`
	Dependencies map[string]npmV1Dep `json:"dependencies"`
}

// splitDescriptor splits a name@range descriptor at the @ after the name (a scope's leading @ is the name's).
func splitDescriptor(d string) (name, rest string) {
	if i := strings.Index(d[min(1, len(d)):], "@"); i >= 0 {
		return d[:i+1], d[i+2:]
	}
	return d, ""
}

// parseYarnLock reads yarn.lock: the classic format (a block per resolved version, "version" under its
// descriptors) or the YAML of yarn 2 and later, whose "resolution" names what was installed (a patched package
// as the package it patches).
func parseYarnLock(raw []byte) (lockResult, error) {
	if bytes.Contains(raw, []byte("\n__metadata:")) || bytes.HasPrefix(raw, []byte("__metadata:")) {
		return parseYarnBerry(raw)
	}
	var r lockResult
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	var name, spec, version, resolved string
	flush := func() {
		if name == "" {
			return
		}
		switch {
		case npmVersionSource(spec) != "":
			r.skip(name, version, npmVersionSource(spec))
		case npmVersionSource(resolved) == "a git dependency" || npmVersionSource(resolved) == "a local path":
			r.skip(name, version, npmVersionSource(resolved))
		case version != "":
			r.add(npmPurl(name, version))
		}
		name, spec, version, resolved = "", "", "", ""
	}
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, " ") {
			flush()
			first, _, _ := strings.Cut(strings.TrimSuffix(line, ":"), ",")
			name, spec = splitDescriptor(strings.Trim(strings.TrimSpace(first), `"`))
			if real, ok := strings.CutPrefix(spec, "npm:"); ok { // an alias: alias@npm:real@^1
				name, spec = splitDescriptor(real)
			}
			continue
		}
		field := strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(field, "version "); ok && strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") {
			version = strings.Trim(v, `"`)
		} else if v, ok := strings.CutPrefix(field, "resolved "); ok {
			resolved = strings.Trim(v, `"`)
		}
	}
	flush()
	return r, sc.Err()
}

func parseYarnBerry(raw []byte) (lockResult, error) {
	var lock map[string]struct {
		Version    string `yaml:"version"`
		Resolution string `yaml:"resolution"`
	}
	if err := yaml.Unmarshal(raw, &lock); err != nil {
		return lockResult{}, err
	}
	var r lockResult
	for _, key := range sortedKeys(lock) {
		if key == "__metadata" {
			continue
		}
		e := lock[key]
		name, how := splitDescriptor(e.Resolution)
		if inner, ok := strings.CutPrefix(how, "patch:"); ok { // patch:name@npm%3A1.2.3#...: the package patched
			inner, _, _ = strings.Cut(inner, "#")
			if dec, err := url.PathUnescape(inner); err == nil {
				inner = dec
			}
			name, how = splitDescriptor(inner)
		}
		switch {
		case strings.HasPrefix(how, "workspace:"):
			continue // a member of this project
		case strings.HasPrefix(how, "npm:"):
			r.add(npmPurl(name, strings.TrimPrefix(how, "npm:")))
		case npmVersionSource(how) != "":
			r.skip(name, e.Version, npmVersionSource(how))
		default:
			r.skip(name, e.Version, "not from the npm registry")
		}
	}
	return r, nil
}

// pnpmPeers is a dependency path's peer suffix: (react@18.2.0) from lockfile v6 on, _react@18.2.0 before.
var pnpmPeers = regexp.MustCompile(`\(.*$`)

// parsePNPMLock reads pnpm-lock.yaml: each "packages" key is a package at a version, /name/1.2.3 before lockfile
// v6, /name@1.2.3 in v6 and name@1.2.3 from v9, any with a peer suffix.
func parsePNPMLock(raw []byte) (lockResult, error) {
	var lock struct {
		LockfileVersion any `yaml:"lockfileVersion"`
		Packages        map[string]struct {
			Name       string `yaml:"name"`
			Version    string `yaml:"version"`
			Resolution struct {
				Tarball string `yaml:"tarball"`
				Type    string `yaml:"type"`
				Repo    string `yaml:"repo"`
			} `yaml:"resolution"`
		} `yaml:"packages"`
	}
	if err := yaml.Unmarshal(raw, &lock); err != nil {
		return lockResult{}, err
	}
	major := 0
	if f, err := strconv.ParseFloat(fmt.Sprint(lock.LockfileVersion), 64); err == nil {
		major = int(f)
	}
	var r lockResult
	for _, key := range sortedKeys(lock.Packages) {
		p := lock.Packages[key]
		k := strings.TrimPrefix(pnpmPeers.ReplaceAllString(key, ""), "/")
		var name, version string
		if major > 0 && major < 6 {
			i := strings.LastIndex(k, "/")
			if i < 0 {
				continue
			}
			name, version = k[:i], k[i+1:]
			version, _, _ = strings.Cut(version, "_")
		} else {
			name, version = splitDescriptor(k)
		}
		if p.Name != "" {
			name = p.Name
		}
		if p.Version != "" && npmVersionSource(version) != "" {
			version = p.Version
		}
		switch {
		case p.Resolution.Type == "git" || p.Resolution.Repo != "":
			r.skip(name, version, "a git dependency")
		case p.Resolution.Type == "directory" || npmVersionSource(version) == "a local path":
			r.skip(name, version, "a local path")
		case p.Resolution.Tarball != "" && !strings.Contains(p.Resolution.Tarball, "/-/"):
			r.skip(name, version, "a tarball URL")
		case npmVersionSource(version) != "" || strings.Contains(name, ".com/"):
			r.skip(name, version, "a git dependency")
		case name != "" && version != "":
			r.add(npmPurl(name, version))
		}
	}
	return r, nil
}

func pypiPurl(name, version string) string {
	name = pypiNameSep.ReplaceAllString(strings.ToLower(name), "-")
	return fmt.Sprintf("pkg:pypi/%s@%s", name, url.PathEscape(version))
}

// pinnedRequirement is name[extras]==version, the only form a requirements file pins a version with.
var pinnedRequirement = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9!+._-]+)$`)

var requirementName = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)`)

// parseRequirements reads a pip requirements file: name==version lines are checked; a range, a bare name, a URL
// or an editable install pins no release and is listed as not checked. Options and -r includes are skipped (an
// included file is read where it lies).
func parseRequirements(raw []byte) (lockResult, error) {
	var r lockResult
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" || strings.HasPrefix(line, "#") || strings.HasSuffix(line, `\`) && !strings.Contains(line, "=") {
			continue
		}
		line = strings.TrimSpace(strings.TrimSuffix(line, `\`))
		if rest, ok := strings.CutPrefix(line, "-e "); ok {
			r.skip(strings.TrimSpace(rest), "", "an editable install")
			continue
		}
		if strings.HasPrefix(line, "-") {
			continue
		}
		req, _, _ := strings.Cut(line, ";") // an environment marker
		req = strings.TrimSpace(strings.Split(req, " --hash")[0])
		if m := pinnedRequirement.FindStringSubmatch(req); m != nil && !strings.Contains(m[2], "*") {
			r.add(pypiPurl(m[1], m[2]))
			continue
		}
		name := req
		if m := requirementName.FindString(req); m != "" {
			name = m
		}
		reason := "no version pinned"
		if strings.Contains(req, "://") || strings.Contains(req, " @ ") {
			reason = "a URL or local path"
		}
		r.skip(name, "", reason)
	}
	return r, sc.Err()
}

// parsePipfileLock reads Pipfile.lock's default and develop packages: ==version, or a git or path source.
func parsePipfileLock(raw []byte) (lockResult, error) {
	var lock map[string]json.RawMessage
	if err := json.Unmarshal(raw, &lock); err != nil {
		return lockResult{}, err
	}
	var r lockResult
	for _, group := range []string{"default", "develop"} {
		var pkgs map[string]struct {
			Version string `json:"version"`
			Git     string `json:"git"`
			Path    string `json:"path"`
			File    string `json:"file"`
		}
		if lock[group] == nil {
			continue
		}
		if err := json.Unmarshal(lock[group], &pkgs); err != nil {
			return lockResult{}, err
		}
		for _, name := range sortedKeys(pkgs) {
			p := pkgs[name]
			switch {
			case p.Git != "":
				r.skip(name, "", "a git dependency")
			case p.Path != "" || p.File != "":
				r.skip(name, "", "a URL or local path")
			case strings.HasPrefix(p.Version, "=="):
				r.add(pypiPurl(name, strings.TrimPrefix(strings.TrimPrefix(p.Version, "=="), "=")))
			}
		}
	}
	return r, nil
}

// tomlPackage is one [[package]] table of a TOML lockfile: its top-level string keys, the [package.source]
// subtable's as source.<key>, and an inline source table as "source" (its raw text).
type tomlPackage map[string]string

var (
	tomlKey        = regexp.MustCompile(`^([A-Za-z0-9_-]+)\s*=\s*(.*)$`)
	tomlLockString = regexp.MustCompile(`^"((?:[^"\\]|\\.)*)"`)
)

// tomlPackages reads the [[package]] tables of poetry.lock, uv.lock and Cargo.lock. Only what these need is
// read: string values at the start of a line, in [[package]] itself or its [package.source] table; arrays,
// other subtables and continuation lines are passed over.
func tomlPackages(raw []byte) ([]tomlPackage, error) {
	var out []tomlPackage
	var cur tomlPackage
	table := ""
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "[") {
			table = strings.TrimSpace(line)
			if table == "[[package]]" {
				cur = tomlPackage{}
				out = append(out, cur)
			}
			continue
		}
		if cur == nil || (table != "[[package]]" && table != "[package.source]") {
			continue
		}
		m := tomlKey.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key := m[1]
		if table == "[package.source]" {
			key = "source." + key
		}
		value := strings.TrimSpace(m[2])
		if s := tomlLockString.FindStringSubmatch(value); s != nil {
			cur[key] = s[1]
		} else if strings.HasPrefix(value, "{") {
			cur[key] = value
		}
	}
	return out, sc.Err()
}

// parsePoetryLock reads poetry.lock: a package from a git, directory, file or URL source is not a release.
func parsePoetryLock(raw []byte) (lockResult, error) {
	pkgs, err := tomlPackages(raw)
	if err != nil {
		return lockResult{}, err
	}
	var r lockResult
	for _, p := range pkgs {
		switch p["source.type"] {
		case "git":
			r.skip(p["name"], p["version"], "a git dependency")
		case "directory", "file", "url":
			r.skip(p["name"], p["version"], "a URL or local path")
		default:
			if p["name"] != "" && p["version"] != "" {
				r.add(pypiPurl(p["name"], p["version"]))
			}
		}
	}
	return r, nil
}

// parseUVLock reads uv.lock: a package from a registry is a release; the project itself (editable or virtual)
// is left out, and a git, path or URL source is not checked.
func parseUVLock(raw []byte) (lockResult, error) {
	pkgs, err := tomlPackages(raw)
	if err != nil {
		return lockResult{}, err
	}
	var r lockResult
	for _, p := range pkgs {
		source := p["source"]
		switch {
		case strings.Contains(source, "editable") || strings.Contains(source, "virtual"):
			continue
		case strings.Contains(source, "git"):
			r.skip(p["name"], p["version"], "a git dependency")
		case strings.Contains(source, "path") || strings.Contains(source, "directory") || strings.Contains(source, "url"):
			r.skip(p["name"], p["version"], "a URL or local path")
		case p["name"] != "" && p["version"] != "":
			r.add(pypiPurl(p["name"], p["version"]))
		}
	}
	return r, nil
}

// parseCargoLock reads Cargo.lock: a crate from a registry is a release; one with no source is this workspace's
// own, and a git source is not checked.
func parseCargoLock(raw []byte) (lockResult, error) {
	pkgs, err := tomlPackages(raw)
	if err != nil {
		return lockResult{}, err
	}
	var r lockResult
	for _, p := range pkgs {
		switch source := p["source"]; {
		case source == "":
			continue
		case strings.HasPrefix(source, "git+"):
			r.skip(p["name"], p["version"], "a git dependency")
		case strings.HasPrefix(source, "registry+") || strings.HasPrefix(source, "sparse+"):
			r.add(fmt.Sprintf("pkg:cargo/%s@%s", p["name"], url.PathEscape(p["version"])))
		default:
			r.skip(p["name"], p["version"], "not from a registry")
		}
	}
	return r, nil
}

// parseGoMod reads go.mod's requirements, with replace directives applied: a module replaced by another is that
// module; one replaced by a local directory is not checked. The toolchain (its toolchain line, else the go line,
// as SecurityContext reads an uploaded go.mod) is the standard library's version. go.sum is not read: it lists
// versions a build may never use.
func parseGoMod(raw []byte) (lockResult, error) {
	type mod struct{ path, version string }
	var requires []mod
	goLine, toolchain := "", ""
	replace := map[string][2]string{} // path or path@version -> new path, new version ("" for a directory)
	block := ""
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if block != "" && fields[0] == ")" {
			block = ""
			continue
		}
		directive := block
		if block == "" {
			directive, fields = fields[0], fields[1:]
			if len(fields) == 1 && fields[0] == "(" {
				block = directive
				continue
			}
		}
		unquote := func(s string) string {
			if u, err := strconv.Unquote(s); err == nil {
				return u
			}
			return s
		}
		switch directive {
		case "go":
			if len(fields) == 1 {
				goLine = fields[0]
			}
		case "toolchain":
			if len(fields) == 1 {
				toolchain = strings.TrimPrefix(fields[0], "go")
			}
		case "require":
			if len(fields) >= 2 {
				requires = append(requires, mod{unquote(fields[0]), fields[1]})
			}
		case "replace":
			arrow := -1
			for i, f := range fields {
				if f == "=>" {
					arrow = i
				}
			}
			if arrow < 1 || arrow+1 >= len(fields) {
				continue
			}
			from := unquote(fields[0])
			if arrow == 2 {
				from += "@" + fields[1]
			}
			to := [2]string{unquote(fields[arrow+1]), ""}
			if arrow+2 < len(fields) {
				to[1] = fields[arrow+2]
			}
			replace[from] = to
		}
	}
	var r lockResult
	if v := cmp.Or(toolchain, goLine); goToolchain.MatchString(v) {
		if strings.Count(v, ".") == 1 {
			v += ".0" // go 1.20 is the release 1.20.0
		}
		r.add("pkg:golang/stdlib@" + v)
	}
	for _, m := range requires {
		to, ok := replace[m.path+"@"+m.version]
		if !ok {
			to, ok = replace[m.path]
		}
		if ok {
			if to[1] == "" {
				r.skip(m.path, m.version, "replaced by a local directory")
				continue
			}
			m = mod{to[0], to[1]}
		}
		r.add(fmt.Sprintf("pkg:golang/%s@%s", m.path, url.PathEscape(m.version)))
	}
	return r, sc.Err()
}

// goToolchain is a released Go version: 1.20, 1.21.4 (not a development name such as 1.22rc1).
var goToolchain = regexp.MustCompile(`^1\.\d+(\.\d+)?$`)

// gemPlatform is a platform-specific gem's suffix: 1.15.4-x86_64-linux, 1.15.4-arm64-darwin, 9.4.3.0-java.
var gemPlatform = regexp.MustCompile(`-(x86|x64|i[3-6]86|arm|aarch64|universal|java|jruby|mingw|mswin|ppc|s390|darwin|linux|wasm)[A-Za-z0-9_.-]*$`)

var gemSpec = regexp.MustCompile(`^    ([A-Za-z0-9_.-]+) \(([^)]+)\)$`)

// parseGemfileLock reads Gemfile.lock's GEM specs (four spaces in: a gem and the version installed, a platform
// gem's version without its platform); GIT and PATH gems are not releases.
func parseGemfileLock(raw []byte) (lockResult, error) {
	var r lockResult
	section := ""
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line != "" && !strings.HasPrefix(line, " ") {
			section = line
			continue
		}
		m := gemSpec.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		version := gemPlatform.ReplaceAllString(m[2], "")
		switch section {
		case "GEM":
			r.add(fmt.Sprintf("pkg:gem/%s@%s", m[1], url.PathEscape(version)))
		case "GIT":
			r.skip(m[1], version, "a git dependency")
		case "PATH":
			r.skip(m[1], version, "a local path")
		}
	}
	return r, sc.Err()
}

// parseComposerLock reads composer.lock's packages and packages-dev: a release version (v1.2.3 read as 1.2.3);
// a branch (dev-main) or a path repository is not a release.
func parseComposerLock(raw []byte) (lockResult, error) {
	var lock struct {
		Packages    []composerPackage `json:"packages"`
		PackagesDev []composerPackage `json:"packages-dev"`
	}
	if err := json.Unmarshal(raw, &lock); err != nil {
		return lockResult{}, err
	}
	var r lockResult
	for _, p := range append(lock.Packages, lock.PackagesDev...) {
		version := strings.TrimPrefix(p.Version, "v")
		switch {
		case p.Dist.Type == "path":
			r.skip(p.Name, p.Version, "a local path")
		case strings.HasPrefix(p.Version, "dev-") || strings.HasSuffix(p.Version, "-dev"):
			r.skip(p.Name, p.Version, "a branch, not a release")
		case p.Name != "" && version != "" && strings.Contains(p.Name, "/"):
			vendor, name := path.Split(p.Name)
			r.add(fmt.Sprintf("pkg:composer/%s%s@%s", strings.ToLower(vendor), strings.ToLower(name), url.PathEscape(version)))
		}
	}
	return r, nil
}

type composerPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Dist    struct {
		Type string `json:"type"`
	} `json:"dist"`
}
