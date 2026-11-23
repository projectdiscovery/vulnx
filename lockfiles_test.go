package vulnx

import (
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

// TestLockParsers reads each lockfile kind: the releases as purls, and the dependencies that are not releases as
// not checked.
func TestLockParsers(t *testing.T) {
	for _, c := range []struct {
		file, body string
		entries    []string
		skipped    []string // name, reason
	}{
		{"package-lock.json", `{"lockfileVersion": 3, "packages": {
			"": {"name": "app", "version": "1.0.0", "workspaces": ["packages/*"]},
			"node_modules/lodash": {"version": "4.17.20", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"},
			"node_modules/@babel/core": {"version": "7.22.0"},
			"node_modules/a/node_modules/lodash": {"version": "4.17.21"},
			"node_modules/my-alias": {"name": "minimist", "version": "1.2.0"},
			"node_modules/local-lib": {"resolved": "packages/local-lib", "link": true},
			"packages/local-lib": {"name": "local-lib", "version": "0.1.0"},
			"node_modules/from-git": {"version": "1.0.0", "resolved": "git+ssh://git@github.com/o/r.git#abc"},
			"node_modules/from-file": {"version": "1.0.0", "resolved": "file:../vendor/x"}}}`,
			[]string{"pkg:npm/%40babel/core@7.22.0", "pkg:npm/lodash@4.17.21", "pkg:npm/lodash@4.17.20", "pkg:npm/minimist@1.2.0"},
			[]string{"from-file: a local path", "from-git: a git dependency"}},
		{"package-lock.json", `{"lockfileVersion": 1, "dependencies": {
			"express": {"version": "4.17.1", "dependencies": {"qs": {"version": "6.7.0"}}},
			"aliased": {"version": "npm:ws@7.4.0"},
			"gitdep": {"version": "github:o/r#abc"}}}`,
			[]string{"pkg:npm/express@4.17.1", "pkg:npm/qs@6.7.0", "pkg:npm/ws@7.4.0"},
			[]string{"gitdep: a git dependency"}},
		{"yarn.lock", `# yarn lockfile v1


"@scope/pkg@^1.0.0", "@scope/pkg@^1.1.0":
  version "1.2.0"
  resolved "https://registry.yarnpkg.com/@scope/pkg/-/pkg-1.2.0.tgz#abc"
  dependencies:
    lodash "^4.17.0"

lodash@^4.17.0:
  version "4.17.20"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.20.tgz"

alias@npm:minimist@^1.2.0:
  version "1.2.0"

"gitdep@git+https://github.com/o/r.git":
  version "0.0.1"
  resolved "git+https://github.com/o/r.git#abc"
`,
			[]string{"pkg:npm/%40scope/pkg@1.2.0", "pkg:npm/lodash@4.17.20", "pkg:npm/minimist@1.2.0"},
			[]string{"gitdep: a git dependency"}},
		{"yarn.lock", `__metadata:
  version: 8
  cacheKey: 10

"app@workspace:.":
  version: 0.0.0-use.local
  resolution: "app@workspace:."

"lodash@npm:^4.17.20":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"

"resolve@patch:resolve@npm%3A^1.22.1#~builtin<compat/resolve>":
  version: 1.22.8
  resolution: "resolve@patch:resolve@npm%3A1.22.8#~builtin<compat/resolve>::version=1.22.8&hash=c3c19d"

"@types/node@npm:20.1.0":
  version: 20.1.0
  resolution: "@types/node@npm:20.1.0"

"lib@portal:../lib::locator=app%40workspace%3A.":
  version: 0.0.0-use.local
  resolution: "lib@portal:../lib::locator=app%40workspace%3A."
`,
			[]string{"pkg:npm/%40types/node@20.1.0", "pkg:npm/lodash@4.17.21", "pkg:npm/resolve@1.22.8"},
			[]string{"lib: a local path"}},
		{"pnpm-lock.yaml", `lockfileVersion: '6.0'
packages:
  /lodash@4.17.20:
    resolution: {integrity: sha512-x}
  /@babel/core@7.22.0(supports-color@8.1.1):
    resolution: {integrity: sha512-y}
  /react-dom@18.2.0(react@18.2.0):
    resolution: {integrity: sha512-z}
  github.com/o/r/abc123:
    resolution: {tarball: https://codeload.github.com/o/r/tar.gz/abc123}
    name: r
    version: 1.0.0
`,
			[]string{"pkg:npm/%40babel/core@7.22.0", "pkg:npm/lodash@4.17.20", "pkg:npm/react-dom@18.2.0"},
			[]string{"r: a tarball URL"}},
		{"pnpm-lock.yaml", `lockfileVersion: '9.0'
packages:
  lodash@4.17.20:
    resolution: {integrity: sha512-x}
  '@scope/a@2.0.0':
    resolution: {integrity: sha512-y}
  local@file:../local:
    resolution: {directory: ../local, type: directory}
snapshots:
  lodash@4.17.20: {}
`,
			[]string{"pkg:npm/%40scope/a@2.0.0", "pkg:npm/lodash@4.17.20"},
			[]string{"local: a local path"}},
		{"pnpm-lock.yaml", `lockfileVersion: 5.4
packages:
  /lodash/4.17.20:
    resolution: {integrity: sha512-x}
  /@babel/core/7.22.0_supports-color@8.1.1:
    resolution: {integrity: sha512-y}
`,
			[]string{"pkg:npm/%40babel/core@7.22.0", "pkg:npm/lodash@4.17.20"}, nil},
		{"requirements-dev.txt", `# pinned
Django==3.2.0
requests[socks] == 2.25.1 ; python_version >= "3.6"
urllib3==1.26.4 --hash=sha256:abc
flask>=2.0
numpy
-r base.txt
--index-url https://example.org/simple
-e git+https://github.com/o/r.git#egg=r
pkg @ https://example.org/pkg-1.0.tar.gz
`,
			[]string{"pkg:pypi/django@3.2.0", "pkg:pypi/requests@2.25.1", "pkg:pypi/urllib3@1.26.4"},
			[]string{"flask: no version pinned", "git+https://github.com/o/r.git#egg=r: an editable install", "numpy: no version pinned", "pkg: a URL or local path"}},
		{"Pipfile.lock", `{"_meta": {}, "default": {"Django": {"version": "==3.2.0"}, "mylib": {"git": "https://github.com/o/r.git"}},
			"develop": {"pytest": {"version": "==7.0.0"}}}`,
			[]string{"pkg:pypi/django@3.2.0", "pkg:pypi/pytest@7.0.0"}, []string{"mylib: a git dependency"}},
		{"poetry.lock", `[[package]]
name = "Requests"
version = "2.25.1"
description = "x"
optional = false

[package.dependencies]
urllib3 = ">=1.21.1"

[package.extras]
socks = ["PySocks (>=1.5.6)"]

[[package]]
name = "mylib"
version = "0.1.0"

[package.source]
type = "git"
url = "https://github.com/o/r.git"
reference = "main"
`,
			[]string{"pkg:pypi/requests@2.25.1"}, []string{"mylib: a git dependency"}},
		{"uv.lock", `version = 1
requires-python = ">=3.11"

[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }
dependencies = [
    { name = "httpx", extra = ["socks"] },
]

[[package]]
name = "httpx"
version = "0.27.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/x.tar.gz", hash = "sha256:x" }

[package.optional-dependencies]
socks = [
    { name = "socksio" },
]

[[package]]
name = "gitdep"
version = "1.0.0"
source = { git = "https://github.com/o/r?rev=main#abc" }
`,
			[]string{"pkg:pypi/httpx@0.27.0"}, []string{"gitdep: a git dependency"}},
		{"go.mod", `module example.com/app

go 1.22

require github.com/a/b v1.2.3

require (
	golang.org/x/net v0.7.0 // indirect
	github.com/old/mod v1.0.0
	github.com/local/mod v0.1.0
)

replace github.com/old/mod => github.com/new/mod v1.1.0

replace github.com/local/mod v0.1.0 => ../mod
`,
			[]string{"pkg:golang/github.com/a/b@v1.2.3", "pkg:golang/github.com/new/mod@v1.1.0", "pkg:golang/golang.org/x/net@v0.7.0",
				"pkg:golang/stdlib@1.22.0"},
			[]string{"github.com/local/mod: replaced by a local directory"}},
		{"go.mod", "module x\n\ngo 1.21.0\n\ntoolchain go1.22.3\n", []string{"pkg:golang/stdlib@1.22.3"}, nil},
		{"Cargo.lock", `version = 3

[[package]]
name = "app"
version = "0.1.0"
dependencies = [
 "serde",
]

[[package]]
name = "serde"
version = "1.0.150"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc"

[[package]]
name = "forked"
version = "0.2.0"
source = "git+https://github.com/o/forked?branch=main#abc"
`,
			[]string{"pkg:cargo/serde@1.0.150"}, []string{"forked: a git dependency"}},
		{"Gemfile.lock", `GIT
  remote: https://github.com/o/r.git
  revision: abc
  specs:
    mygem (0.1.0)

PATH
  remote: .
  specs:
    app (1.0.0)

GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.15.4-x86_64-linux)
      racc (~> 1.4)
    nokogiri (1.15.4-arm64-darwin)
    racc (1.7.1)
    rails (7.0.4)

PLATFORMS
  arm64-darwin
  x86_64-linux

BUNDLED WITH
   2.4.10
`,
			[]string{"pkg:gem/nokogiri@1.15.4", "pkg:gem/racc@1.7.1", "pkg:gem/rails@7.0.4"},
			[]string{"app: a local path", "mygem: a git dependency"}},
		{"composer.lock", `{"packages": [{"name": "monolog/monolog", "version": "2.3.0"}, {"name": "Symfony/Console", "version": "v5.4.0"},
			{"name": "acme/lib", "version": "dev-main"}], "packages-dev": [{"name": "acme/local", "version": "1.0.0", "dist": {"type": "path"}}]}`,
			[]string{"pkg:composer/monolog/monolog@2.3.0", "pkg:composer/symfony/console@5.4.0"},
			[]string{"acme/lib: a branch, not a release", "acme/local: a local path"}},
	} {
		parse := lockParserFor(c.file)
		if parse == nil {
			t.Fatalf("no parser for %s", c.file)
		}
		r, err := parse([]byte(c.body))
		if err != nil {
			t.Fatalf("%s: %v", c.file, err)
		}
		got := slices.Clone(r.entries)
		sort.Strings(got)
		want := slices.Clone(c.entries)
		sort.Strings(want)
		if !slices.Equal(got, want) {
			t.Errorf("%s entries\n got %q\nwant %q", c.file, got, want)
		}
		var skipped []string
		for _, s := range r.skipped {
			skipped = append(skipped, s.Name+": "+s.Reason)
		}
		sort.Strings(skipped)
		if !slices.Equal(skipped, c.skipped) {
			t.Errorf("%s not checked\n got %q\nwant %q", c.file, skipped, c.skipped)
		}
	}
}

func TestLockParserFor(t *testing.T) {
	for name, want := range map[string]bool{"requirements.txt": true, "requirements-dev.txt": true, "requirements.in": false,
		"package.json": false, "go.sum": false, "Cargo.lock": true} {
		if got := lockParserFor(name) != nil; got != want {
			t.Errorf("%s: %v", name, got)
		}
	}
	if _, err := parseNPMLock([]byte("{")); err == nil || !strings.Contains(err.Error(), "unexpected") {
		t.Errorf("a broken lockfile: %v", err)
	}
}

// TestLockParsersMatchServer parses the lockfiles under testdata/lockparity and compares each one's package
// versions with SecurityContext's own reading of the same file, recorded in server.txt (each file uploaded with
// vulnx scan <file> --json, one name@version per item). The one recorded difference is deliberate: the server
// sends a requirements range (flask>=2.0) as an item, read here as not checked, so server.txt leaves it out.
func TestLockParsersMatchServer(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "lockparity", "server.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		kind, want, _ := strings.Cut(line, "\t")
		files, err := filepath.Glob(filepath.Join("testdata", "lockparity", kind, "*"))
		if err != nil || len(files) != 1 {
			t.Fatalf("%s: %v %v", kind, files, err)
		}
		body, err := os.ReadFile(files[0])
		if err != nil {
			t.Fatal(err)
		}
		r, err := lockParserFor(filepath.Base(files[0]))(body)
		if err != nil {
			t.Fatalf("%s: %v", files[0], err)
		}
		var got []string
		for _, e := range r.entries {
			_, rest, _ := strings.Cut(strings.TrimPrefix(e, "pkg:"), "/")
			at := strings.LastIndex(rest, "@")
			name, err := url.PathUnescape(rest[:at])
			if err != nil {
				t.Fatal(err)
			}
			version, err := url.PathUnescape(rest[at+1:])
			if err != nil {
				t.Fatal(err)
			}
			if name == "stdlib" {
				version = "v" + version // the server writes a Go release as a module version
			}
			got = append(got, strings.ToLower(name)+"@"+version)
		}
		sort.Strings(got)
		if strings.Join(got, " ") != want {
			t.Errorf("%s:\n local  %s\n server %s", files[0], strings.Join(got, " "), want)
		}
	}
}
