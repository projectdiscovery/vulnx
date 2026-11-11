package vulnx

import (
	"bytes"
	"compress/zlib"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

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
	inv, err := HostEntries(root)
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

func TestHostAlpine(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "etc/os-release", "ID=alpine\nVERSION_ID=3.19.4\n")
	writeFile(t, root, "lib/apk/db/installed", "C:Q1abc\nP:libcrypto3\nV:3.1.8-r0\nA:aarch64\no:openssl\n\nP:musl\nV:1.2.4_git20230717-r5\no:musl\n")
	inv, err := HostEntries(root)
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

	inv, err := HostEntries(root)
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
	if inv.Source != "dpkg" || len(inv.NotAssessed) != 0 {
		t.Errorf("source %q, not assessed %v", inv.Source, inv.NotAssessed)
	}
	for _, want := range []string{"dpkg 1", "python 3 (2 site-packages dirs)", "npm 4 (2 global node_modules)",
		"gems 2 (1 gem dir)", "go binaries", "(1 binary)", "rust binaries 1 (1 binary)", "not read: "} {
		if !strings.Contains(inv.Note, want) {
			t.Errorf("note lacks %q:\n%s", want, inv.Note)
		}
	}
}

// TestHostNoPackageDatabase still reads the other sources of a root without dpkg, apk or rpm, and says so.
func TestHostNoPackageDatabase(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "etc/os-release", "ID=debian\nVERSION_ID=12\n")
	writeFile(t, root, "usr/local/lib/python3.11/site-packages/flask-2.0.0.dist-info/METADATA", "Name: Flask\nVersion: 2.0.0\n")
	inv, err := HostEntries(root)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(inv.Entries, ",") != "pkg:pypi/flask@2.0.0" || !strings.Contains(inv.Note, "no dpkg, apk or rpm package database") {
		t.Errorf("%v\n%s", inv.Entries, inv.Note)
	}
	if _, err := HostEntries(t.TempDir()); err == nil {
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
	root := t.TempDir()
	cellar := "opt/homebrew/Cellar/"
	writeFile(t, root, cellar+"openssl@3/3.4.0_1/lib/libssl.dylib", "")
	writeFile(t, root, cellar+"c-ares/1.34.4/lib/libcares.dylib", "")
	writeFile(t, root, cellar+"awscli/2.13.25/libexec/lib/python3.11/site-packages/botocore-1.31.0.dist-info/METADATA", "Name: botocore\nVersion: 1.31.0\n")
	writeFile(t, root, cellar+"prettier/3.0.0/libexec/lib/node_modules/prettier/package.json", `{"name":"prettier","version":"3.0.0"}`)
	copyTestBinary(t, root, cellar+"gotool/1.0/bin/gotool")
	copyTestBinary(t, root, cellar+"linked/2.0/bin/linked")
	writeFile(t, root, cellar+"cairo/1.18.4/lib/libcairo.dylib", "")
	h := &hostReader{root: root, goos: "darwin", seen: map[string]bool{}, binSeen: map[string]bool{}}
	// linked's executable is on PATH and read there first; the formula still counts as read
	if err := os.MkdirAll(filepath.Join(root, "opt/homebrew/bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, cellar+"linked/2.0/bin/linked"), filepath.Join(root, "opt/homebrew/bin/linked")); err != nil {
		t.Fatal(err)
	}
	h.binaries()
	h.homebrew()
	hasAll(t, h.inv.Entries,
		"cpe:2.3:a:openssl:openssl:3.4.0:*:*:*:*:*:*:*",
		"cpe:2.3:a:c-ares:c-ares:1.34.4:*:*:*:*:*:*:*", "cpe:2.3:a:c-ares_project:c-ares:1.34.4:*:*:*:*:*:*:*",
		"pkg:pypi/botocore@1.31.0", "pkg:npm/prettier@3.0.0", goStdlib())
	if strings.Join(h.inv.NotAssessed, ",") != "cairo 1.18.4 (homebrew)" {
		t.Errorf("not assessed: %v", h.inv.NotAssessed)
	}
	if n := h.note(); !strings.Contains(n, "7 formulae: 2 by product, 4 by their packages or binaries), 1 not assessed") {
		t.Errorf("note: %s", n)
	}
}

// TestHostApplications sends a bundle with a known product as its CPE and lists the others.
func TestHostApplications(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "Applications/Google Chrome.app/Contents/Info.plist", appPlist("com.google.Chrome", "131.0.6778.86"))
	writeFile(t, root, "Applications/Utilities/Wireshark.app/Contents/Info.plist", appPlist("org.wireshark.Wireshark", "4.4.2"))
	writeFile(t, root, "Users/alice/Applications/Editor.app/Contents/Info.plist", appPlist("com.example.editor", "2.1 (300)"))
	writeFile(t, root, "Applications/Broken.app/Contents/MacOS/broken", "")
	h := &hostReader{root: root, goos: "darwin", seen: map[string]bool{}, binSeen: map[string]bool{}}
	h.applications()
	want := []string{"cpe:2.3:a:google:chrome:131.0.6778.86:*:*:*:*:*:*:*", "cpe:2.3:a:wireshark:wireshark:4.4.2:*:*:*:*:*:*:*"}
	if strings.Join(h.inv.Entries, "\n") != strings.Join(want, "\n") {
		t.Errorf("entries:\n%s", strings.Join(h.inv.Entries, "\n"))
	}
	if strings.Join(h.inv.NotAssessed, ",") != "Broken (applications),Editor 2.1 (300) (applications)" {
		t.Errorf("not assessed: %v", h.inv.NotAssessed)
	}
	if n := h.note(); !strings.Contains(n, "applications 2 (4 bundles), 2 not assessed") {
		t.Errorf("note: %s", n)
	}
}

func TestCPEEscape(t *testing.T) {
	if got := productCPE("vendor:product", "1.0 (2)"); got != `cpe:2.3:a:vendor:product:1.0\ \(2\):*:*:*:*:*:*:*` {
		t.Error(got)
	}
}
