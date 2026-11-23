package vulnx

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// TestFolderEntries walks a project folder: each lockfile is a source of its own, installed trees are read whole
// and not entered, a package found twice is checked once with both places, and the walk stays inside the folder
// (version control and links are not followed).
func TestFolderEntries(t *testing.T) {
	skipOnWindows(t) // symlinks need a privilege there, and an executable is told by its name
	root, outside := t.TempDir(), t.TempDir()
	write := func(dir, rel, body string) {
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(root, "package-lock.json", `{"lockfileVersion": 3, "packages": {"": {}, "node_modules/lodash": {"version": "4.17.20"}}}`)
	write(root, "node_modules/lodash/package.json", `{"name": "lodash", "version": "4.17.20"}`)
	write(root, "node_modules/lodash/package-lock.json", `{"lockfileVersion": 3, "packages": {"node_modules/inside": {"version": "1.0.0"}}}`)
	write(root, "web/yarn.lock", "# yarn lockfile v1\n\nminimist@^1.2.0:\n  version \"1.2.0\"\n")
	write(root, "api/requirements.txt", "django==3.2.0\nflask>=2\n")
	write(root, "api/.venv/lib/python3.12/site-packages/requests-2.25.1.dist-info/METADATA", "Name: requests\nVersion: 2.25.1\n\n")
	write(root, ".git/package-lock.json", `{"lockfileVersion": 3, "packages": {"node_modules/hidden": {"version": "1.0.0"}}}`)
	write(root, "sbom/app.cdx.json", `{"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{"type": "library", "name": "ws", "version": "7.4.0", "purl": "pkg:npm/ws@7.4.0"}]}`)
	write(root, ".mcp.json", `{"mcpServers": {"files": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.1.14"]}, "web": {"url": "https://example.org/mcp"}}}`)
	write(outside, "Cargo.lock", "[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n")
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	// a Go program: this test binary
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	dst, err := os.OpenFile(filepath.Join(root, "bin", "tool"), os.O_CREATE|os.O_WRONLY, 0o755)
	if os.IsNotExist(err) {
		if err = os.MkdirAll(filepath.Join(root, "bin"), 0o755); err == nil {
			dst, err = os.OpenFile(filepath.Join(root, "bin", "tool"), os.O_CREATE|os.O_WRONLY, 0o755)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(dst, src)
	if closeErr := dst.Close(); err == nil {
		err = closeErr
	}
	if closeErr := src.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}

	inv, err := FolderEntries(context.Background(), root, FolderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"pkg:npm/lodash@4.17.20", "pkg:npm/minimist@1.2.0", "pkg:pypi/django@3.2.0", "pkg:pypi/requests@2.25.1",
		"pkg:npm/ws@7.4.0", "pkg:npm/%40modelcontextprotocol/server-filesystem@2025.1.14"} {
		if !slices.Contains(inv.Entries, want) {
			t.Errorf("no %s in %q", want, inv.Entries)
		}
	}
	for _, unwanted := range []string{"pkg:npm/inside@1.0.0", "pkg:npm/hidden@1.0.0", "pkg:cargo/serde@1.0.0"} {
		if slices.Contains(inv.Entries, unwanted) {
			t.Errorf("%s was read: the walk left the folder or entered an installed tree", unwanted)
		}
	}
	if got := inv.FoundIn["pkg:npm/lodash@4.17.20"]; !slices.Equal(got, []string{"node_modules", "package-lock.json"}) &&
		!slices.Equal(got, []string{"package-lock.json", "node_modules"}) {
		t.Errorf("lodash found in %q", got)
	}
	sources := map[string]HostSource{}
	for _, s := range inv.Sources {
		sources[s.Name] = s
	}
	for _, name := range []string{"package-lock.json", "web/yarn.lock", "api/requirements.txt", "installed npm", "installed python",
		"sbom/app.cdx.json", "mcp servers", "go binaries"} {
		if _, ok := sources[name]; !ok {
			t.Errorf("no source %s in %+v", name, inv.Sources)
		}
	}
	if s := sources["api/requirements.txt"]; s.Sent != 1 || s.NotAssessed != 1 {
		t.Errorf("requirements: %+v", s)
	}
	goEntries := 0
	for _, e := range inv.Entries {
		if strings.HasPrefix(e, "pkg:golang/stdlib@") && inv.EntrySource[e] == "go binaries" {
			goEntries++
			if len(inv.GoBinaries[e]) == 0 || inv.GoBinaries[e][0].Name != "bin/tool" {
				t.Errorf("stdlib's binary: %+v", inv.GoBinaries[e])
			}
		}
	}
	if goEntries != 1 && runtime.GOOS != "windows" {
		t.Errorf("the Go program's toolchain: %d entries", goEntries)
	}
	if _, err := FolderEntries(context.Background(), filepath.Join(root, "package-lock.json"), FolderOptions{}); err == nil {
		t.Error("a file read as a folder")
	}
}
