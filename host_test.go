package vulnx

import (
	"bytes"
	"compress/zlib"
	"context"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

// skipOnWindows skips a test of what --host reads on a Unix machine: --host reads Linux and macOS only, and the test
// needs Unix executables (ELF or Mach-O, execute bits) or renames a file it holds open.
func skipOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("--host reads Linux and macOS; this test needs Unix executables or file semantics")
	}
}

func writeFile(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestHostDebian(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "etc/os-release", "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\n")
	writeFile(t, root, "var/lib/dpkg/status", `Package: libc6
Status: install ok installed
Architecture: arm64
Source: glibc
Version: 2.36-9+deb12u14

Package: zlib1g
Status: install ok installed
Architecture: arm64
Source: zlib (1:1.2.13.dfsg-1)
Version: 1:1.2.13.dfsg-1

Package: removed-pkg
Status: deinstall ok config-files
Version: 1.0

Package: bash
Status: install ok installed
Architecture: arm64
Version: 5.2.15-2+b8
`)
	inv, err := HostEntries(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"pkg:deb/debian/libc6@2.36-9+deb12u14?arch=arm64&distro=debian-12&upstream=glibc",
		"pkg:deb/debian/zlib1g@1:1.2.13.dfsg-1?arch=arm64&distro=debian-12&upstream=zlib%401%3A1.2.13.dfsg-1",
		"pkg:deb/debian/bash@5.2.15-2+b8?arch=arm64&distro=debian-12",
	}
	if inv.Source != "dpkg" || inv.OS != "debian 12" || strings.Join(inv.Entries, "\n") != strings.Join(want, "\n") {
		t.Errorf("got %s %q\n%s", inv.Source, inv.OS, strings.Join(inv.Entries, "\n"))
	}
}

// TestHostUnknownDistribution reads but does not send the packages of a distribution SecurityContext has no
// advisories for: the API refuses them, and with them the whole list.
func TestHostUnknownDistribution(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "etc/os-release", "ID=arch\nVERSION_ID=20240101\n")
	writeFile(t, root, "var/lib/dpkg/status", "Package: bash\nStatus: install ok installed\nVersion: 5.2.15-2\n\n")
	inv, err := HostEntries(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Entries) != 0 || len(inv.NotAssessed) != 1 || !strings.Contains(inv.NotAssessed[0].Reason, "not arch") {
		t.Errorf("%q %+v", inv.Entries, inv.NotAssessed)
	}
}

// TestHostNoVersionID reads but does not send the OS packages of a release without VERSION_ID (a rolling or
// testing one): a distribution's advisories are per release, and the API refuses a package without one.
func TestHostNoVersionID(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "etc/os-release", "ID=debian\nPRETTY_NAME=\"Debian GNU/Linux trixie/sid\"\n")
	writeFile(t, root, "var/lib/dpkg/status", "Package: bash\nStatus: install ok installed\nVersion: 5.2.15-2\n\n")
	inv, err := HostEntries(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Entries) != 0 || inv.OS != "debian" || len(inv.NotAssessed) != 1 || inv.NotAssessed[0].Name != "bash" ||
		inv.NotAssessed[0].Version != "5.2.15-2" || !strings.Contains(inv.NotAssessed[0].Reason, "VERSION_ID") || inv.Sources[0].NotAssessed != 1 {
		t.Errorf("%q %q %+v %+v", inv.OS, inv.Entries, inv.NotAssessed, inv.Sources)
	}
}

// TestHostUserHomes keeps two users' places apart: each home is named, and only an upload masks them to ~.
func TestHostUserHomes(t *testing.T) {
	root := t.TempDir()
	for _, user := range []string{"alice", "bob"} {
		writeFile(t, root, "home/"+user+"/.cursor/mcp.json", `{"mcpServers":{"fs":{"command":"npx","args":["-y","fs-server@1.0.0"]}}}`)
	}
	h := newHostReader(root, "linux")
	servers := h.mcpServers()
	if len(servers) != 2 || servers[0].config == servers[1].config {
		t.Fatalf("%+v", servers)
	}
	if got := h.label(filepath.Join(root, "home/bob/.npm-global/lib/node_modules")); got != "~bob/.npm-global" {
		t.Errorf("label %q", got)
	}
	h.home = "/home/alice" // as when scanning / as alice
	if got := h.label(filepath.Join(root, "home/alice/.npm-global/lib/node_modules")); got != "~/.npm-global" {
		t.Errorf("own label %q", got)
	}
	for in, want := range map[string]string{"~bob/.codex/config.toml": "~/.codex/config.toml", "~/.local (python3.10)": "~/.local (python3.10)",
		"update act (/Users/sam/go/bin/act)": "update act (~/go/bin/act)", "caddy": "caddy", "update tool (~sam/bin/tool)": "update tool (~/bin/tool)"} {
		if got := maskHomes(in); got != want {
			t.Errorf("maskHomes(%q) = %q", in, got)
		}
	}
}

// TestHostCycloneDXPrivate keeps users and what only the runtime snapshot saw out of the SBOM, and names an OS
// package by its own name with the distribution as its group.
func TestHostCycloneDXPrivate(t *testing.T) {
	deb := "pkg:deb/debian/libc6@2.36-9?arch=arm64&distro=debian-12"
	inv := HostInventory{OS: "debian 12", Entries: []string{deb, "pkg:golang/example.com/tool@v1.0.0"},
		FoundIn:       map[string][]string{deb: {"dpkg"}, "pkg:golang/example.com/tool@v1.0.0": {"~bob/go/bin", "/opt/srv/tool"}},
		EntrySource:   map[string]string{deb: "dpkg", "pkg:golang/example.com/tool@v1.0.0": runtimeInventorySource},
		Paths:         map[string]string{"~bob/go/bin": "/home/bob/go/bin", "/opt/srv/tool": "/opt/srv/tool"},
		runtimePlaces: map[string]bool{"/opt/srv/tool": true}}
	raw, err := inv.CycloneDX(time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"group": "debian"`, `"name": "libc6"`, `"value": "~/go/bin"`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("missing %s", want)
		}
	}
	for _, never := range []string{"bob", "/opt/srv", runtimeInventorySource, `"name": "debian/libc6"`} {
		if strings.Contains(string(raw), never) {
			t.Errorf("the SBOM holds %s", never)
		}
	}
}

func TestHostAlpine(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "etc/os-release", "ID=alpine\nVERSION_ID=3.19.4\n")
	writeFile(t, root, "lib/apk/db/installed", "C:Q1abc\nP:libcrypto3\nV:3.1.8-r0\nA:aarch64\no:openssl\n\nP:musl\nV:1.2.4_git20230717-r5\no:musl\n")
	inv, err := HostEntries(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"pkg:apk/alpine/libcrypto3@3.1.8-r0?distro=alpine-3.19&upstream=openssl",
		"pkg:apk/alpine/musl@1.2.4_git20230717-r5?distro=alpine-3.19",
	}
	if strings.Join(inv.Entries, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s", strings.Join(inv.Entries, "\n"))
	}
}

func TestDistroQualifier(t *testing.T) {
	for _, c := range []struct{ id, ver, ns, q string }{
		{"debian", "12", "debian", "debian-12"},
		{"ubuntu", "22.04", "ubuntu", "ubuntu-22.04"},
		{"alpine", "3.20.3", "alpine", "alpine-3.20"},
		{"rhel", "9.4", "redhat", "rhel-9"},
		{"rocky", "9.5", "rocky", "rocky-9"},
		{"almalinux", "8.10", "almalinux", "almalinux-8"},
	} {
		ns, q := distroQualifier(c.id, c.ver)
		if ns != c.ns || q != c.q {
			t.Errorf("%s %s: %s %s", c.id, c.ver, ns, q)
		}
	}
}

func TestWithUpstream(t *testing.T) {
	cases := []struct {
		purl  string
		props map[string]string
		want  string
	}{
		{"pkg:deb/debian/libc6@2.36-9%2Bdeb12u14?arch=arm64&distro=debian-12.15",
			map[string]string{"SrcName": "glibc", "SrcVersion": "2.36", "SrcRelease": "9+deb12u14"},
			"pkg:deb/debian/libc6@2.36-9%2Bdeb12u14?arch=arm64&distro=debian-12.15&upstream=glibc%402.36-9%2Bdeb12u14"},
		{"pkg:deb/debian/zlib1g@1.2.13.dfsg-1?distro=debian-12&epoch=1",
			map[string]string{"SrcName": "zlib", "SrcEpoch": "1", "SrcVersion": "1.2.13.dfsg", "SrcRelease": "1"},
			"pkg:deb/debian/zlib1g@1.2.13.dfsg-1?distro=debian-12&epoch=1&upstream=zlib%401%3A1.2.13.dfsg-1"},
		{"pkg:rpm/rocky/curl@7.76.1-26.el9?distro=rocky-9",
			map[string]string{"SrcName": "curl", "SrcVersion": "7.76.1", "SrcRelease": "26.el9"},
			"pkg:rpm/rocky/curl@7.76.1-26.el9?distro=rocky-9&upstream=curl-7.76.1-26.el9.src.rpm"},
		{"pkg:apk/alpine/libcrypto3@3.1.8-r0?distro=alpine-3.19", map[string]string{"SrcName": "openssl"},
			"pkg:apk/alpine/libcrypto3@3.1.8-r0?distro=alpine-3.19&upstream=openssl"},
		{"pkg:deb/debian/x@1?upstream=y", map[string]string{"SrcName": "z"}, "pkg:deb/debian/x@1?upstream=y"},
		{"pkg:npm/a@1", map[string]string{"SrcName": "z"}, "pkg:npm/a@1"},
	}
	for _, c := range cases {
		if got := withUpstream(c.purl, c.props); got != c.want {
			t.Errorf("%s:\n got  %s\n want %s", c.purl, got, c.want)
		}
	}
}

// copyTestBinary puts this test binary, a Go executable with build info, at root/rel.
func copyTestBinary(t *testing.T, root, rel string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, raw, 0o755); err != nil {
		t.Fatal(err)
	}
}

// writeRustBinary writes a minimal ELF executable whose .dep-v0 section holds a crate list, compressed as Rust's
// auditable builds embed it.
func writeRustBinary(t *testing.T, root, rel, crates string) {
	t.Helper()
	var dep bytes.Buffer
	zw := zlib.NewWriter(&dep)
	if _, err := zw.Write([]byte(crates)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	strtab := []byte("\x00.dep-v0\x00.shstrtab\x00")
	depOff := uint64(64)
	strOff := depOff + uint64(dep.Len())
	shOff := strOff + uint64(len(strtab))
	var out bytes.Buffer
	hdr := elf.Header64{Type: uint16(elf.ET_EXEC), Machine: uint16(elf.EM_X86_64), Version: 1, Shoff: shOff,
		Ehsize: 64, Phentsize: 56, Shentsize: 64, Shnum: 3, Shstrndx: 2}
	copy(hdr.Ident[:], []byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), 1})
	sections := []elf.Section64{
		{},
		{Name: 1, Type: uint32(elf.SHT_PROGBITS), Off: depOff, Size: uint64(dep.Len()), Addralign: 1},
		{Name: 9, Type: uint32(elf.SHT_STRTAB), Off: strOff, Size: uint64(len(strtab)), Addralign: 1},
	}
	for _, part := range []any{hdr, dep.Bytes(), strtab, sections} {
		if err := binary.Write(&out, binary.LittleEndian, part); err != nil {
			t.Fatal(err)
		}
	}
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, out.Bytes(), 0o755); err != nil {
		t.Fatal(err)
	}
}

func goStdlib() string { return "pkg:golang/stdlib@" + strings.TrimPrefix(runtime.Version(), "go") }

func hasAll(t *testing.T, got []string, want ...string) {
	t.Helper()
	set := map[string]bool{}
	for _, g := range got {
		set[g] = true
	}
	for _, w := range want {
		if !set[w] {
			t.Errorf("missing %s in\n%s", w, strings.Join(got, "\n"))
		}
	}
}

func hasNone(t *testing.T, got []string, unwanted ...string) {
	t.Helper()
	for _, g := range got {
		for _, u := range unwanted {
			if strings.Contains(g, u) {
				t.Errorf("unexpected %s", g)
			}
		}
	}
}

// TestHostLinuxSources reads a Linux root with every source: OS packages, Python, npm, gems, Go and Rust binaries.
func TestHostLinuxSources(t *testing.T) {
	skipOnWindows(t)
	root := t.TempDir()
	writeFile(t, root, "etc/os-release", "ID=ubuntu\nVERSION_ID=\"22.04\"\n")
	writeFile(t, root, "var/lib/dpkg/status", "Package: bash\nStatus: install ok installed\nArchitecture: amd64\nVersion: 5.1-6ubuntu1\n")
	// pip into the system interpreter and into a user's home; the distribution's own directory is an OS package
	writeFile(t, root, "usr/local/lib/python3.10/dist-packages/requests-2.19.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: requests\nVersion: 2.19.0\n\nName: not-a-header\n")
	writeFile(t, root, "home/alice/.local/lib/python3.10/site-packages/Foo_Bar.Baz-1.0.egg-info/PKG-INFO", "Name: Foo_Bar.Baz\nVersion: 1.0\n")
	writeFile(t, root, "home/alice/.local/lib/python3.10/site-packages/legacy-0.3.egg-info", "Name: legacy\nVersion: 0.3\n")
	writeFile(t, root, "usr/lib/python3/dist-packages/distro_owned-1.0.dist-info/METADATA", "Name: distro-owned\nVersion: 1.0\n")
	// a global npm install with a scoped package and a nested dependency
	writeFile(t, root, "usr/local/lib/node_modules/npm/package.json", `{"name":"npm","version":"10.2.0"}`)
	writeFile(t, root, "usr/local/lib/node_modules/@scope/tool/package.json", `{"name":"@scope/tool","version":"1.2.3"}`)
	writeFile(t, root, "usr/local/lib/node_modules/@scope/tool/node_modules/lodash/package.json", `{"name":"lodash","version":"4.17.20"}`)
	writeFile(t, root, "home/alice/.nvm/versions/node/v20.1.0/lib/node_modules/corepack/package.json", `{"name":"corepack","version":"0.18.0"}`)
	writeFile(t, root, "usr/lib/node_modules/distro-owned/package.json", `{"name":"distro-owned","version":"1.0.0"}`)
	// gems installed with `gem install`, a default gem, and the distribution's own
	writeFile(t, root, "var/lib/gems/3.0.0/specifications/rack-2.0.0.gemspec", "Gem::Specification.new do |s|\n  s.name = \"rack\".freeze\n  s.version = \"2.0.0\"\nend\n")
	writeFile(t, root, "var/lib/gems/3.0.0/specifications/default/json-2.6.1.gemspec", "Gem::Specification.new do |s|\n  s.name = \"json\".freeze\n  s.version = \"2.6.1\".freeze\nend\n")
	writeFile(t, root, "usr/lib/ruby/gems/3.0.0/specifications/distro-owned-1.0.gemspec", "s.name = \"distro-owned\"\ns.version = \"1.0\"\n")
	// a Go binary on PATH, the same binary linked from a user's bin, a Rust binary with its crate list, a script
	copyTestBinary(t, root, "usr/local/bin/gotool")
	if err := os.MkdirAll(filepath.Join(root, "home/alice/go/bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "usr/local/bin/gotool"), filepath.Join(root, "home/alice/go/bin/gotool")); err != nil {
		t.Fatal(err)
	}
	writeRustBinary(t, root, "home/alice/.cargo/bin/rusttool", `{"packages":[`+
		`{"name":"rusttool","version":"0.1.0","source":"local","root":true},`+
		`{"name":"hyper","version":"0.14.10","source":"crates.io"},`+
		`{"name":"forked","version":"1.0.0","source":"git"}]}`)
	writeFile(t, root, "usr/bin/script.sh", "#!/bin/sh\n")

	inv, err := HostEntries(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	hasAll(t, inv.Entries,
		"pkg:deb/ubuntu/bash@5.1-6ubuntu1?arch=amd64&distro=ubuntu-22.04",
		"pkg:pypi/requests@2.19.0", "pkg:pypi/foo-bar-baz@1.0", "pkg:pypi/legacy@0.3",
		"pkg:npm/npm@10.2.0", "pkg:npm/%40scope/tool@1.2.3", "pkg:npm/lodash@4.17.20", "pkg:npm/corepack@0.18.0",
		"pkg:gem/rack@2.0.0", "pkg:gem/json@2.6.1",
		goStdlib(), "pkg:cargo/hyper@0.14.10")
	hasNone(t, inv.Entries, "distro-owned", "not-a-header", "forked", "rusttool")
	for entry, want := range map[string]string{
		"pkg:pypi/requests@2.19.0": "/usr/local (python3.10)",
		"pkg:pypi/legacy@0.3":      "~alice/.local (python3.10)", // a mounted root has no scanning user: every home is named
		"pkg:npm/corepack@0.18.0":  "~alice/.nvm/versions/node/v20.1.0",
		"pkg:gem/json@2.6.1":       "/var/lib/gems/3.0.0",
		"pkg:cargo/hyper@0.14.10":  "rusttool",
		goStdlib():                 "gotool",
		"pkg:deb/ubuntu/bash@5.1-6ubuntu1?arch=amd64&distro=ubuntu-22.04": "dpkg",
	} {
		if got := strings.Join(inv.FoundIn[entry], ","); got != want {
			t.Errorf("%s found in %q, want %q", entry, got, want)
		}
	}
	// how each place is updated: the interpreter's pip (--user for a user site), npm, gem, the OS package manager,
	// go install for a Go bin directory, cargo for Cargo's
	for label, want := range map[string]HostFix{
		"/usr/local (python3.10)":    {Kind: "pip", Command: "/usr/local/bin/python3.10 -m pip install -U"},
		"~alice/.local (python3.10)": {Kind: "pip", Command: "python3.10 -m pip install --user -U"},
		"/usr/local":                 {Kind: "npm", Command: "npm update -g"},
		"/var/lib/gems/3.0.0":        {Kind: "gem", Command: "gem update"},
		"dpkg":                       {Kind: "apt", Command: "sudo apt-get install --only-upgrade"},
		"rusttool":                   {Kind: "cargo", Command: "cargo install", Target: "rusttool"},
	} {
		if got := inv.Fixes[label]; got != want {
			t.Errorf("fix for %q: %+v, want %+v", label, got, want)
		}
	}
	if f := inv.Fixes["gotool"]; f.Kind != "binary" || f.Target != "gotool" {
		t.Errorf("gotool outside a Go bin directory: %+v", f)
	}
	if inv.Source != "dpkg" || len(inv.NotAssessed) != 0 {
		t.Errorf("source %q, not assessed %v", inv.Source, inv.NotAssessed)
	}
	sources := map[string]string{}
	for _, s := range inv.Sources {
		sources[s.Name] = fmt.Sprintf("%d (%s)", s.Sent, s.Detail)
	}
	for name, want := range map[string]string{"dpkg": "1 ()", "python": "3 (2 site-packages dirs)", "npm": "4 (2 global node_modules)",
		"gems": "2 (1 gem dir)", "rust binaries": "1 (1 binary)"} {
		if sources[name] != want {
			t.Errorf("%s: %q, want %q", name, sources[name], want)
		}
	}
	if !strings.HasSuffix(sources["go binaries"], "(1 binary)") || len(inv.NotRead) == 0 {
		t.Errorf("go binaries %q, not read %q", sources["go binaries"], inv.NotRead)
	}
}

// TestHostNoPackageDatabase still reads the other sources of a root without dpkg, apk or rpm, and says so.
func TestHostNoPackageDatabase(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "etc/os-release", "ID=debian\nVERSION_ID=12\n")
	writeFile(t, root, "usr/local/lib/python3.11/site-packages/flask-2.0.0.dist-info/METADATA", "Name: Flask\nVersion: 2.0.0\n")
	inv, err := HostEntries(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(inv.Entries, ",") != "pkg:pypi/flask@2.0.0" || !strings.Contains(strings.Join(inv.NotRead, "\n"), "no dpkg, apk or rpm package database") {
		t.Errorf("%v\n%s", inv.Entries, inv.NotRead)
	}
	if _, err := HostEntries(context.Background(), t.TempDir()); err == nil {
		t.Error("a root without os-release should fail")
	}
}

func appPlist(id, version string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDocumentTypes</key>
	<array><dict><key>CFBundleIdentifier</key><string>nested.ignored</string></dict></array>
	<key>LSRequiresNativeExecution</key>
	<true/>
	<key>CFBundleIdentifier</key>
	<string>` + id + `</string>
	<key>CFBundleShortVersionString</key>
	<string>` + version + `</string>
</dict>
</plist>`
}

// TestHostHomebrew judges a formula by its NVD product when the table names one, else by the packages and
// binaries it carries, and lists the rest as not assessed.
func TestHostHomebrew(t *testing.T) {
	skipOnWindows(t)
	root := t.TempDir()
	cellar := "opt/homebrew/Cellar/"
	writeFile(t, root, cellar+"openssl@3/3.4.0_1/lib/libssl.dylib", "")
	writeFile(t, root, cellar+"c-ares/1.34.4/lib/libcares.dylib", "")
	writeFile(t, root, cellar+"awscli/2.13.25/libexec/lib/python3.11/site-packages/botocore-1.31.0.dist-info/METADATA", "Name: botocore\nVersion: 1.31.0\n")
	writeFile(t, root, cellar+"prettier/3.0.0/libexec/lib/node_modules/prettier/package.json", `{"name":"prettier","version":"3.0.0"}`)
	copyTestBinary(t, root, cellar+"gotool/1.0/bin/gotool")
	copyTestBinary(t, root, cellar+"linked/2.0/bin/linked")
	writeFile(t, root, cellar+"cairo/1.18.4/lib/libcairo.dylib", "")
	writeFile(t, root, cellar+"ca-certificates/2026-10-20/share/ca-certificates/cacert.pem", "-----BEGIN")
	h := newHostReader(root, "darwin")
	// linked's executable is on PATH and read there first; the formula still counts as read
	if err := os.MkdirAll(filepath.Join(root, "opt/homebrew/bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, cellar+"linked/2.0/bin/linked"), filepath.Join(root, "opt/homebrew/bin/linked")); err != nil {
		t.Fatal(err)
	}
	h.binaries()
	h.homebrew()
	if got := strings.Join(h.inv.FoundIn["pkg:pypi/botocore@1.31.0"], ","); got != "awscli (formula)" {
		t.Errorf("botocore found in %q", got)
	}
	// a formula is upgraded by name; a Go binary linked from the Cellar is upgraded with its formula
	if f := h.inv.Fixes["awscli (formula)"]; f != (HostFix{Kind: "brew", Command: "brew upgrade", Target: "awscli"}) {
		t.Errorf("awscli: %+v", f)
	}
	if f := h.inv.Fixes["linked"]; f.Kind != "brew" || f.Target != "linked" {
		t.Errorf("linked: %+v", f)
	}
	hasAll(t, h.inv.Entries,
		"cpe:2.3:a:openssl:openssl:3.4.0:*:*:*:*:*:*:*",
		"cpe:2.3:a:c-ares:c-ares:1.34.4:*:*:*:*:*:*:*", "cpe:2.3:a:c-ares_project:c-ares:1.34.4:*:*:*:*:*:*:*",
		"pkg:pypi/botocore@1.31.0", "pkg:npm/prettier@3.0.0", goStdlib())
	if fmt.Sprint(h.inv.NotAssessed) != "[{cairo 1.18.4 homebrew }]" {
		t.Errorf("not assessed: %v", h.inv.NotAssessed)
	}
	if fmt.Sprint(h.inv.DataOnly) != "[{ca-certificates 2026-10-20 homebrew }]" {
		t.Errorf("data only: %v", h.inv.DataOnly)
	}
	if s := h.inv.Sources[len(h.inv.Sources)-1]; s.Name != "homebrew" || s.Detail != "8 formulae: 2 by product, 4 by their packages or binaries" || s.NotAssessed != 1 {
		t.Errorf("source: %+v", s)
	}
}

// TestHostApplications sends a bundle with a known product as its CPE and lists the others.
func TestHostApplications(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "Applications/Google Chrome.app/Contents/Info.plist", appPlist("com.google.Chrome", "131.0.6778.86"))
	writeFile(t, root, "Applications/Utilities/Wireshark.app/Contents/Info.plist", appPlist("org.wireshark.Wireshark", "4.4.2"))
	writeFile(t, root, "Users/alice/Applications/Editor.app/Contents/Info.plist", appPlist("com.example.editor", "2.1 (300)"))
	writeFile(t, root, "Applications/Broken.app/Contents/MacOS/broken", "")
	h := newHostReader(root, "darwin")
	h.applications()
	want := []string{"cpe:2.3:a:google:chrome:131.0.6778.86:*:*:*:*:*:*:*", "cpe:2.3:a:wireshark:wireshark:4.4.2:*:*:*:*:*:*:*"}
	if strings.Join(h.inv.Entries, "\n") != strings.Join(want, "\n") {
		t.Errorf("entries:\n%s", strings.Join(h.inv.Entries, "\n"))
	}
	if got := h.inv.FoundIn[want[0]]; len(got) != 1 || got[0] != "Google Chrome.app" {
		t.Errorf("found in %v", got)
	}
	if f := h.inv.Fixes["Google Chrome.app"]; f.Kind != "app" || f.Note != "update Google Chrome" {
		t.Errorf("Chrome: %+v", f)
	}
	if fmt.Sprint(h.inv.NotAssessed) != "[{Broken  applications } {Editor 2.1 (300) applications }]" {
		t.Errorf("not assessed: %v", h.inv.NotAssessed)
	}
	if s := h.inv.Sources[0]; s.Name != "applications" || s.Sent != 2 || s.Detail != "4 bundles" || s.NotAssessed != 2 {
		t.Errorf("source: %+v", s)
	}
}

func TestCPEEscape(t *testing.T) {
	if got := productCPE("vendor:product", "1.0 (2)"); got != `cpe:2.3:a:vendor:product:1.0\ \(2\):*:*:*:*:*:*:*` {
		t.Error(got)
	}
}

// TestGoFunctionTable reads this test binary's own function table, as advisories name functions.
func TestGoFunctionTable(t *testing.T) {
	skipOnWindows(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	fns, err := goFunctionTable(self)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"testing.T.Run", "github.com/projectdiscovery/vulnx/v2.goFunctionTable"} {
		if !fns.funcs[f] {
			t.Errorf("%s not in the table", f)
		}
	}
	// the linker writes this package as gopkg.in/yaml%2ev3
	if !fns.packages["gopkg.in/yaml.v3"] || fns.packages["gopkg.in/yaml"] || fns.packages["gopkg.in/yaml%2ev3"] {
		t.Error("a package whose last path element has a dot is not read back by its import path")
	}
	if got := fns.verdict([]AffectedPackage{{Package: "gopkg.in/yaml.v3", Functions: []string{"Node.ShortTag"}}}); got != "reachable" {
		t.Errorf("yaml.v3 Node.ShortTag: %s", got)
	}
	escaped := goFunctions{funcs: map[string]bool{}, packages: map[string]bool{}}
	escaped.add("gopkg.in/yaml%2ev3.(*decoder).unmarshal")
	if !escaped.packages["gopkg.in/yaml.v3"] || !escaped.funcs["gopkg.in/yaml.v3.decoder.unmarshal"] {
		t.Errorf("escaped symbol: %+v", escaped)
	}
	// a function inlined at every call has no entry: why a linked package with no listed function is unknown
	if fns.funcs["strings.Contains"] || !fns.packages["strings"] {
		t.Error("strings.Contains is expected to be inlined away while package strings is linked")
	}
	for _, c := range []struct {
		lists []AffectedPackage
		want  string
	}{
		{[]AffectedPackage{{Package: "example.com/never", Functions: []string{"F"}}, {Package: "testing"}}, "reachable"},
		{[]AffectedPackage{{Package: "testing", Functions: []string{"T.Run"}}}, "reachable"},
		{[]AffectedPackage{{Package: "strings", Functions: []string{"Contains"}}}, "unknown"},
		{[]AffectedPackage{{Package: "example.com/never", Functions: []string{"F"}}}, "not_reachable"},
	} {
		if got := fns.verdict(c.lists); got != c.want {
			t.Errorf("%v: %s, want %s", c.lists, got, c.want)
		}
	}
	if _, err := goFunctionTable(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("a missing file should fail")
	}
}

// TestMarkReachability marks each row and binary by what the binary links: a listed function it links, a package
// it does not link at all, and an advisory with no list (unknown).
func TestMarkReachability(t *testing.T) {
	skipOnWindows(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	mod := "pkg:golang/example.com/m@v1.0.0"
	inv := HostInventory{GoBinaries: map[string][]HostBinary{mod: {{Path: self, Name: "tool"}}}}
	res := StackResult{
		Items: []StackItem{{Input: mod, Package: "go/example.com/m", Status: "affected", AdvisoryRows: []StackAdvisory{
			{AdvisoryID: "GO-LINKED"}, {AdvisoryID: "GO-NOT"}, {AdvisoryID: "GO-NOLIST"}}}},
		GoFunctions: GoFunctions{"go/example.com/m": {
			"GO-LINKED": {{Package: "testing", Functions: []string{"T.Run"}}},
			"GO-NOT":    {{Package: "example.com/m/parse", Functions: []string{"Parse"}}},
		}},
	}
	inv.MarkReachability(&res)
	rows := res.Items[0].AdvisoryRows
	if rows[0].Reachability != "reachable" || rows[1].Reachability != "not_reachable" || rows[2].Reachability != "" {
		t.Errorf("rows: %q %q %q", rows[0].Reachability, rows[1].Reachability, rows[2].Reachability)
	}
	if r := res.Items[0].Reachability; r == nil || fmt.Sprint(r.Reachable) != "[tool]" {
		t.Errorf("item: %+v", r)
	}
	// without the linked row, an advisory with no list keeps the binary unknown, not "not reachable"
	res.Items[0].AdvisoryRows, res.Items[0].Reachability = rows[1:], nil
	inv.MarkReachability(&res)
	if r := res.Items[0].Reachability; fmt.Sprint(r.Unknown) != "[tool]" || len(r.NotReachable) != 0 {
		t.Errorf("item: %+v", r)
	}
	// every listed row unreachable: not reachable, unless rows were left out of the answer or none was listed
	for _, c := range []struct {
		rows  []StackAdvisory
		total int
		want  string
	}{
		{[]StackAdvisory{{AdvisoryID: "GO-NOT"}}, 1, "[] [tool] []"},
		{[]StackAdvisory{{AdvisoryID: "GO-NOT"}}, 11, "[] [] [tool]"},
		{nil, 0, "[] [] [tool]"},
		{[]StackAdvisory{{AdvisoryID: "GO-NOT"}, {AdvisoryID: "GO-LINKED"}}, 11, "[tool] [] []"},
	} {
		res.Items[0].AdvisoryRows, res.Items[0].AdvisoryRowsTotal, res.Items[0].Reachability = c.rows, c.total, nil
		inv.MarkReachability(&res)
		r := res.Items[0].Reachability
		if got := fmt.Sprint(r.Reachable, r.NotReachable, r.Unknown); got != c.want {
			t.Errorf("%d of %d rows: %s, want %s", len(c.rows), c.total, got, c.want)
		}
	}
}

func TestBinaryFix(t *testing.T) {
	for _, c := range []struct {
		real, main string
		want       HostFix
	}{
		{"/opt/homebrew/Cellar/nuclei/3.11.1/bin/nuclei", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei",
			HostFix{Kind: "brew", Command: "brew upgrade", Target: "nuclei"}},
		{"/Users/a/go/bin/air", "github.com/air-verse/air", HostFix{Kind: "go-install", Command: "go install", Target: "github.com/air-verse/air@latest"}},
		// built from loose files: no module to install from
		{"/Users/a/go/bin/tool", "command-line-arguments", HostFix{Kind: "binary", Target: "tool", Note: "update tool (/Users/a/go/bin/tool)"}},
		{"/Users/a/.cargo/bin/rg", "", HostFix{Kind: "cargo", Command: "cargo install", Target: "rg"}},
		{"/usr/local/bin/terraform", "github.com/hashicorp/terraform", HostFix{Kind: "binary", Target: "terraform", Note: "update terraform (/usr/local/bin/terraform)"}},
	} {
		name := filepath.Base(c.real)
		if got := binaryFix(name, c.real, c.main); got != c.want {
			t.Errorf("%s: %+v, want %+v", c.real, got, c.want)
		}
	}
}

// TestHostCycloneDX writes the inventory as an SBOM that reads back as the same entries.
func TestHostCycloneDX(t *testing.T) {
	inv := HostInventory{OS: "macOS 26.4",
		Entries:     []string{"cpe:2.3:o:apple:macos:26.4:*:*:*:*:*:*:*", "pkg:npm/%40scope/tool@1.2.3", "pkg:golang/golang.org/x/net@v0.7.0"},
		FoundIn:     map[string][]string{"pkg:golang/golang.org/x/net@v0.7.0": {"caddy", "act"}},
		EntrySource: map[string]string{"pkg:golang/golang.org/x/net@v0.7.0": "go binaries"},
		Paths:       map[string]string{"caddy": "/opt/homebrew/bin/caddy", "act": "/Users/sam/go/bin/act"},
		Fixes: map[string]HostFix{"caddy": {Kind: "brew", Command: "brew upgrade", Target: "caddy"},
			"act":    {Kind: "binary", Target: "act", Note: "update act (/Users/sam/go/bin/act)"},
			"unused": {Kind: "brew", Command: "brew upgrade", Target: "unused"}}}
	raw, err := inv.CycloneDX(time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	entries, format, ok := SBOMEntries(raw)
	if !ok || format != "cyclonedx" || strings.Join(entries, "\n") != strings.Join(inv.Entries, "\n") {
		t.Errorf("%s %v\n%s", format, ok, strings.Join(entries, "\n"))
	}
	for _, want := range []string{`"group": "@scope"`, `"name": "tool"`, `"version": "1.2.3"`, `"type": "operating-system"`, `"name": "macos"`,
		`"group": "golang.org/x"`, `"name": "net"`, `"value": "go binaries"`, `"value": "caddy"`, `"name": "macOS 26.4"`,
		// each place a component names: where it is and how it is updated, home directories as ~
		`"value": "{\"name\":\"caddy\",\"path\":\"/opt/homebrew/bin/caddy\",\"kind\":\"brew\",\"fix\":\"brew upgrade caddy\"}"`,
		`"value": "{\"name\":\"act\",\"path\":\"~/go/bin/act\",\"kind\":\"binary\",\"fix\":\"update act (~/go/bin/act)\"}"`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("missing %s", want)
		}
	}
	for _, never := range []string{"/Users/sam", "unused"} {
		if strings.Contains(string(raw), never) {
			t.Errorf("the SBOM holds %s", never)
		}
	}
}

// writeAsar writes an asar archive: its JSON index of files (offset and size) and the files' bytes after it.
func writeAsar(t *testing.T, path string, files map[string]string) {
	t.Helper()
	type node map[string]any
	root := node{"files": node{}}
	var data bytes.Buffer
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		dir := root["files"].(node)
		parts := strings.Split(name, "/")
		for _, p := range parts[:len(parts)-1] {
			if dir[p] == nil {
				dir[p] = node{"files": node{}}
			}
			dir = dir[p].(node)["files"].(node)
		}
		dir[parts[len(parts)-1]] = node{"offset": fmt.Sprint(data.Len()), "size": len(files[name])}
		data.WriteString(files[name])
	}
	index, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	padded := (len(index) + 3) / 4 * 4
	for _, v := range []uint32{4, uint32(padded + 8), uint32(padded + 4), uint32(len(index))} {
		if err := binary.Write(&out, binary.LittleEndian, v); err != nil {
			t.Fatal(err)
		}
	}
	out.Write(index)
	out.Write(make([]byte, padded-len(index)))
	out.Write(data.Bytes())
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestHostElectronApp reads an Electron application: the framework's version as the npm package electron, and the
// npm packages in its archive and unpacked directory. An application with neither a product nor a framework is
// still not assessed.
func TestHostElectronApp(t *testing.T) {
	root := t.TempDir()
	app := "Applications/Chat.app/Contents/"
	writeFile(t, root, app+"Info.plist", appPlist("com.example.chat", "1.2.0"))
	writeFile(t, root, app+"Frameworks/Electron Framework.framework/Resources/Info.plist",
		strings.Replace(appPlist("com.github.Electron.framework", "x"), "CFBundleShortVersionString", "CFBundleVersion", 1))
	writeAsar(t, filepath.Join(root, app, "Resources/app.asar"), map[string]string{
		"package.json":                                `{"name":"chat","version":"1.2.0"}`, // the app itself: no registry release
		"node_modules/lodash/package.json":            `{"name":"lodash","version":"4.17.20"}`,
		"node_modules/@scope/pkg/package.json":        `{"name":"@scope/pkg","version":"2.0.0"}`,
		"node_modules/a/node_modules/ms/package.json": `{"name":"ms","version":"2.0.0"}`,
		"node_modules/lodash/lodash.js":               "module.exports = {}",
		// a package.json inside a package's own files names no installed package
		"node_modules/lodash/test/fixture/package.json": `{"name":"fixture","version":"9.9.9"}`,
		"node_modules/@scope/package.json":              `{"name":"not-a-package","version":"1.0.0"}`,
	})
	writeFile(t, root, app+"Resources/app.asar.unpacked/node_modules/sharp/package.json", `{"name":"sharp","version":"0.32.0"}`)
	writeFile(t, root, "Applications/Plain.app/Contents/Info.plist", appPlist("com.example.plain", "3.0"))
	h := newHostReader(root, "darwin")
	h.applications()
	want := []string{"pkg:npm/electron@x", "pkg:npm/%40scope/pkg@2.0.0", "pkg:npm/lodash@4.17.20", "pkg:npm/ms@2.0.0", "pkg:npm/sharp@0.32.0"}
	if strings.Join(h.inv.Entries, "\n") != strings.Join(want, "\n") {
		t.Errorf("entries:\n%s", strings.Join(h.inv.Entries, "\n"))
	}
	if fmt.Sprint(h.inv.NotAssessed) != "[{Plain 3.0 applications }]" || h.inv.Fixes["Chat.app"].Note != "update Chat" ||
		strings.Join(h.inv.FoundIn["pkg:npm/lodash@4.17.20"], ",") != "Chat.app" {
		t.Errorf("not assessed %v, fix %+v", h.inv.NotAssessed, h.inv.Fixes["Chat.app"])
	}
}

// TestDropUnknownProducts lists a product the index does not know as not checked instead of clean.
func TestDropUnknownProducts(t *testing.T) {
	unknown, known := "cpe:2.3:a:nosuch:thing:1.0:*:*:*:*:*:*:*", "cpe:2.3:a:haxx:curl:8.18.0:*:*:*:*:*:*:*"
	inv := HostInventory{Entries: []string{unknown, known, "pkg:npm/never-heard-of@1.0.0"},
		EntrySource: map[string]string{unknown: "homebrew", known: "homebrew"},
		FoundIn:     map[string][]string{unknown: {"thing (formula)"}},
		Sources:     []HostSource{{Name: "homebrew", Sent: 2}}}
	res := StackResult{Total: 3, Summary: StackSummary{Packages: 3, Clean: 3}, Items: []StackItem{
		{Input: unknown, Package: "cpe/nosuch:thing", Version: "1.0", Status: "clean", Seen: "none"},
		{Input: known, Package: "cpe/haxx:curl", Version: "8.18.0", Status: "clean", Seen: "version"},
		// a registry package the index has not seen stays, as unseen
		{Input: "pkg:npm/never-heard-of@1.0.0", Status: "clean", Seen: "none"}}}
	countVerdicts(&res) // as CheckManyWith answers
	inv.DropUnknownProducts(&res)
	if s := res.Summary; len(res.Items) != 2 || s.Clean != 1 || s.Unseen != 1 || s.Packages != 2 || res.Total != 2 || len(inv.Entries) != 2 {
		t.Errorf("items %d summary %+v entries %d", len(res.Items), s, len(inv.Entries))
	}
	want := "[{thing (formula) 1.0 homebrew its product (nosuch:thing) is not in the index}]"
	if fmt.Sprint(inv.NotAssessed) != want || inv.Sources[0] != (HostSource{Name: "homebrew", Sent: 1, NotAssessed: 1}) {
		t.Errorf("%v %+v", inv.NotAssessed, inv.Sources[0])
	}
}

func TestHasExecutable(t *testing.T) {
	data, code := t.TempDir(), t.TempDir()
	writeFile(t, data, "share/ca-certificates/cacert.pem", "-----BEGIN")
	writeFile(t, code, "lib/libfoo.dylib", "")
	if hasExecutable(data) || !hasExecutable(code) {
		t.Error("a keg of data has nothing to run; a library does")
	}
}

// TestHostFormulaByRepository reads a formula's source repository from its own formula file (top-level lines
// only) and checks it as the products that list that repository; without one it is not assessed.
func TestHostFormulaByRepository(t *testing.T) {
	root := t.TempDir()
	cellar := "opt/homebrew/Cellar/"
	writeFile(t, root, cellar+"unitext@78/78.3_1/lib/libunitext.dylib", "")
	writeFile(t, root, cellar+"unitext@78/78.3_1/.brew/unitext@78.rb", `class Icu4cAT78 < Formula
  desc "C/C++ and Java libraries for Unicode"
  homepage "https://icu.unicode.org/home"
  url "https://github.com/Unicode-Org/ICU/releases/download/release-78.3/icu4c-78.3-sources.tgz"

  test do
    resource "data" do
      url "https://github.com/other/project/raw/main/file.bin"
    end
  end
end
`)
	writeFile(t, root, cellar+"orphan/1.0/lib/liborphan.dylib", "")
	writeFile(t, root, cellar+"orphan/1.0/.brew/orphan.rb", "class Orphan < Formula\n  head \"https://github.com/nobody/orphan.git\", branch: \"main\"\nend\n")
	writeFile(t, root, cellar+"libomp/17.0.2/lib/libomp.dylib", "") // a slice of its repository: never joined
	writeFile(t, root, cellar+"libomp/17.0.2/.brew/libomp.rb", "class Libomp < Formula\n  url \"https://github.com/llvm/llvm-project/releases/x.tar.xz\"\nend\n")
	h := newHostReader(root, "darwin")
	h.homebrew()
	inv := h.inv
	if got := strings.Join(inv.PendingRepositories(), ","); got != "nobody/orphan,unicode-org/icu" {
		t.Fatalf("pending repositories: %s", got)
	}
	inv.ResolvePending(map[string][]string{"unicode-org/icu": {"icu-project:international_components_for_unicode", "unicode:international_components_for_unicode"}})
	hasAll(t, inv.Entries, "cpe:2.3:a:icu-project:international_components_for_unicode:78.3:*:*:*:*:*:*:*",
		"cpe:2.3:a:unicode:international_components_for_unicode:78.3:*:*:*:*:*:*:*")
	if fmt.Sprint(inv.NotAssessed) != "[{libomp 17.0.2 homebrew } {orphan 1.0 homebrew }]" || len(inv.Pending) != 0 {
		t.Errorf("not assessed: %v", inv.NotAssessed)
	}
	if got := inv.FoundIn[inv.Entries[0]]; len(got) != 1 || got[0] != "unitext@78 (formula)" {
		t.Errorf("found in %v", got)
	}
	if src := inv.Sources[0]; src.Sent != 2 || src.NotAssessed != 2 {
		t.Errorf("source %+v", src)
	}
}

func TestDropOtherSchemes(t *testing.T) {
	res := StackResult{Summary: StackSummary{Affected: 3, Clean: 0}, Items: []StackItem{
		{Input: "cpe:2.3:a:anysphere:cursor:3.29.9:*", Version: "3.29.9", Status: "affected", Advisories: 2, WorstSeverity: "high",
			AdvisoryRows: []StackAdvisory{{CVE: "CVE-1", Severity: "high", Ranges: []string{"< 2025.09.17-25b418f"}},
				{CVE: "CVE-2", Severity: "medium", Ranges: []string{">= 1.0, < 3.30.0"}}}},
		{Input: "cpe:2.3:a:x:agent:3.1:*", Version: "3.1", Status: "affected", Advisories: 1, WorstSeverity: "critical",
			AdvisoryRows: []StackAdvisory{{CVE: "CVE-3", Severity: "critical", Ranges: []string{"< 2025.9.1", "= 2025.10.2"}}}},
		{Input: "cpe:2.3:a:x:cal:2024.1.2:*", Version: "2024.1.2", Status: "affected", Advisories: 1, WorstSeverity: "low",
			AdvisoryRows: []StackAdvisory{{CVE: "CVE-4", Severity: "low", Ranges: []string{"< 2025.1"}}}},
		{Input: "pkg:npm/a@3.0.0", Version: "3.0.0", Status: "affected", Advisories: 1,
			AdvisoryRows: []StackAdvisory{{CVE: "CVE-5", Ranges: []string{"< 2025.1.1"}}}},
		{Input: "cpe:2.3:a:x:all:1.0:*", Version: "1.0", Status: "affected", Advisories: 1,
			AdvisoryRows: []StackAdvisory{{CVE: "CVE-6", Ranges: []string{"all versions"}}}},
	}}
	DropOtherSchemes(&res)
	cursor, agent := res.Items[0], res.Items[1]
	if len(cursor.AdvisoryRows) != 1 || cursor.AdvisoryRows[0].CVE != "CVE-2" || cursor.Advisories != 1 || cursor.WorstSeverity != "medium" || cursor.Status != "affected" {
		t.Fatalf("cursor %+v", cursor)
	}
	if agent.Status != "clean" || len(agent.AdvisoryRows) != 0 || agent.WorstSeverity != "" {
		t.Fatalf("agent %+v", agent)
	}
	for _, it := range res.Items[2:] {
		if it.Status != "affected" || len(it.AdvisoryRows) != 1 {
			t.Fatalf("kept as it was: %+v", it)
		}
	}
	if res.Summary.Affected != 2 || res.Summary.Clean != 1 {
		t.Fatalf("summary %+v", res.Summary)
	}
}

func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{"caddy": "caddy", "github.com/x/y@latest": "github.com/x/y@latest",
		"/Users/a b/bin/python3": `'/Users/a b/bin/python3'`, "x;y": `'x;y'`, "it's": `'it'\''s'`, "": `''`} {
		if got := ShellQuote(in); got != want {
			t.Errorf("ShellQuote(%q) = %s, want %s", in, got, want)
		}
	}
	if got := (HostFix{Command: "brew upgrade", Target: "a b"}).Line(); got != "brew upgrade 'a b'" {
		t.Errorf("Line %s", got)
	}
}

// TestHostRPMRoot asks rpm about a root with an RPM database: when the host's rpm cannot read it, the gap says so
// rather than that there is no database.
func TestHostRPMRoot(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "etc/os-release", "ID=rocky\nVERSION_ID=9.4\n")
	writeFile(t, root, "var/lib/rpm/rpmdb.sqlite", "")
	inv, err := HostEntries(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if notRead := strings.Join(inv.NotRead, "\n"); inv.Source != "rpm" && !strings.Contains(notRead, "an RPM database is under") {
		t.Errorf("source %q, not read %q", inv.Source, notRead)
	}
}

// TestHostPackageDatabaseCutShort reads no OS packages from a database the scanner stops in (a line over its
// 1 MiB buffer): a part of it would read as all of it.
func TestHostPackageDatabaseCutShort(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "etc/os-release", "ID=debian\nVERSION_ID=12\n")
	writeFile(t, root, "var/lib/dpkg/status", "Package: bash\nStatus: install ok installed\nVersion: 5.2.15-2\n\n"+
		"Description: "+strings.Repeat("x", 2<<20)+"\n\nPackage: zlib1g\nStatus: install ok installed\nVersion: 1.2.13\n\n")
	inv, err := HostEntries(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Entries) != 0 || !strings.Contains(strings.Join(inv.NotRead, "\n"), "could not be read whole") {
		t.Errorf("%q %q", inv.Entries, inv.NotRead)
	}
	if _, err := apkInstalled(strings.NewReader("P:musl\nV:" + strings.Repeat("1", 2<<20) + "\n")); err == nil {
		t.Error("apk: a line over the buffer read as the whole database")
	}
}
