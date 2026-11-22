package vulnx

// The machine vulnx runs on, as check entries (vulnx scan --host): its OS packages, judged by the distribution's own
// advisories on SecurityContext (Debian, Ubuntu, Alpine, Red Hat Enterprise Linux, Rocky Linux, AlmaLinux).
//
//   Linux  /etc/os-release names the distribution and release; packages come from dpkg's status file, apk's
//          installed database, or `rpm -qa`. Each becomes a purl with its release and source package
//          (pkg:deb/debian/libc6@2.36-9+deb12u7?distro=debian-12&upstream=glibc), the form the advisories key on.
//   macOS  the macOS and Safari versions, as CPEs (Apple's per-line fixes judge them).
//
// Nothing is uploaded but these names and versions.

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// HostInventory is what vulnx found on a machine.
type HostInventory struct {
	OS      string   // "debian 12", "macOS 26.4", ...
	Source  string   // dpkg, rpm, apk, sw_vers
	Entries []string // purls and CPEs
	Note    string   // what is not covered
}

// HostEntries reads the OS packages of the machine (or of a filesystem mounted at root, Linux only).
func HostEntries(root string) (HostInventory, error) {
	if root == "" {
		root = "/"
	}
	if runtime.GOOS == "darwin" && root == "/" {
		return macEntries()
	}
	if runtime.GOOS != "linux" && root == "/" {
		return HostInventory{}, fmt.Errorf("--host reads Linux and macOS machines (this is %s); scan an SBOM of it instead", runtime.GOOS)
	}
	return linuxEntries(root)
}

func macEntries() (HostInventory, error) {
	inv := HostInventory{Source: "sw_vers", Note: "macOS and Safari only: Homebrew packages and other applications are not read"}
	out, err := exec.Command("sw_vers", "-productVersion").Output()
	if err != nil {
		return inv, fmt.Errorf("sw_vers: %w", err)
	}
	ver := strings.TrimSpace(string(out))
	inv.OS = "macOS " + ver
	inv.Entries = append(inv.Entries, fmt.Sprintf("cpe:2.3:o:apple:macos:%s:*:*:*:*:*:*:*", ver))
	if out, err := exec.Command("defaults", "read", "/Applications/Safari.app/Contents/Info.plist", "CFBundleShortVersionString").Output(); err == nil {
		if v := strings.TrimSpace(string(out)); v != "" {
			inv.Entries = append(inv.Entries, fmt.Sprintf("cpe:2.3:a:apple:safari:%s:*:*:*:*:*:*:*", v))
		}
	}
	return inv, nil
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

func linuxEntries(root string) (HostInventory, error) {
	id, version, err := osRelease(root)
	if err != nil {
		return HostInventory{}, err
	}
	ns, distro := distroQualifier(id, version)
	inv := HostInventory{OS: strings.TrimSpace(id + " " + version)}
	switch id {
	case "debian", "ubuntu", "rhel", "rocky", "almalinux", "alpine":
	default:
		inv.Note = fmt.Sprintf("SecurityContext has advisories for Debian, Ubuntu, Alpine, RHEL, Rocky and AlmaLinux; %s packages will come back undetermined", id)
	}
	q := func(extra url.Values) string {
		v := url.Values{"distro": {distro}}
		for k, vs := range extra {
			v[k] = vs
		}
		return v.Encode()
	}
	if f, err := os.Open(filepath.Join(root, "var/lib/dpkg/status")); err == nil {
		defer func() { _ = f.Close() }()
		inv.Source = "dpkg"
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
			inv.Entries = append(inv.Entries, fmt.Sprintf("pkg:deb/%s/%s@%s?%s", ns, p.name, url.PathEscape(p.version), q(extra)))
		}
		return inv, nil
	}
	if f, err := os.Open(filepath.Join(root, "lib/apk/db/installed")); err == nil {
		defer func() { _ = f.Close() }()
		inv.Source = "apk"
		for _, p := range apkInstalled(f) {
			extra := url.Values{}
			if p.source != "" && p.source != p.name {
				extra.Set("upstream", p.source)
			}
			inv.Entries = append(inv.Entries, fmt.Sprintf("pkg:apk/alpine/%s@%s?%s", p.name, url.PathEscape(p.version), q(extra)))
		}
		return inv, nil
	}
	if root == "/" {
		if out, err := exec.Command("rpm", "-qa", "--qf", "%{NAME}|%{EPOCHNUM}|%{VERSION}-%{RELEASE}|%{ARCH}|%{SOURCERPM}\\n").Output(); err == nil {
			inv.Source = "rpm"
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
				inv.Entries = append(inv.Entries, fmt.Sprintf("pkg:rpm/%s/%s@%s?%s", ns, f[0], url.PathEscape(f[2]), q(extra)))
			}
			return inv, nil
		}
	}
	return inv, fmt.Errorf("no dpkg, apk or rpm package database found under %s", root)
}

type osPackage struct{ name, version, arch, source, sourceVersion string }

// dpkgInstalled reads dpkg's status file: installed packages with their source package.
func dpkgInstalled(f *os.File) []osPackage {
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
func apkInstalled(f *os.File) []osPackage {
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
