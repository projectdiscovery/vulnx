package vulnx

import (
	"os"
	"path/filepath"
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
