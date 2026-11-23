package clis

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/projectdiscovery/vulnx/v2"
	"github.com/projectdiscovery/vulnx/v2/pkg/tools/renderer"
)

// folderServer answers a compact check: lodash affected (high, a public exploit), anything else clean.
func folderServer(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			zr, err := gzip.NewReader(r.Body)
			if err != nil {
				t.Error(err)
				return
			}
			body = zr
		}
		var req struct{ Packages []string }
		if err := json.NewDecoder(body).Decode(&req); err != nil {
			t.Error(err)
			return
		}
		var items []map[string]any
		affected := 0
		for _, p := range req.Packages {
			it := map[string]any{"input": p, "status": "clean", "seen": "version"}
			if strings.HasPrefix(p, "pkg:npm/lodash@") {
				affected++
				it = map[string]any{"input": p, "package": "npm/lodash", "version": "4.17.20", "status": "affected", "worst_severity": "high",
					"advisories": 1, "fixed_version": "4.17.21", "advisory_rows": []map[string]any{{"cve": "CVE-2021-23337", "severity": "high",
						"cvss_score": 7.2, "name": "Command Injection", "exploitation": map[string]any{"public_exploit": true}}}}
			}
			items = append(items, it)
		}
		out := map[string]any{"total": len(items), "summary": map[string]any{"packages": len(items), "affected": affected,
			"clean": len(items) - affected}, "items": items}
		if err := json.NewEncoder(w).Encode(out); err != nil {
			t.Error(err)
		}
	}))
}

// folderFixture is a project: a lockfile, a requirements file with a range, and its node_modules.
func folderFixture(t *testing.T) string {
	dir := t.TempDir()
	for rel, body := range map[string]string{
		"package-lock.json":                `{"lockfileVersion": 3, "packages": {"": {}, "node_modules/lodash": {"version": "4.17.20"}}}`,
		"node_modules/lodash/package.json": `{"name": "lodash", "version": "4.17.20"}`,
		"api/requirements.txt":             "django==3.2.0\nflask>=2\n",
	} {
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestRenderFolder draws a folder scan: a grid row per source, the dependency not checked and what was scanned,
// then the affected package; a clean one is listed only with --show-all.
func TestRenderFolder(t *testing.T) {
	srv := folderServer(t)
	defer srv.Close()
	client, err := vulnx.New(vulnx.WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	saved := vulnxClient
	t.Cleanup(func() { vulnxClient, scanShowAll = saved, false })
	vulnxClient = client
	dir := folderFixture(t)
	inv, err := vulnx.FolderEntries(t.Context(), dir, vulnx.FolderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := checkInventory(t.Context(), inv)
	if err != nil {
		t.Fatal(err)
	}
	out := renderFolder(inv, res, scanSource{input: "app"}, 10, renderer.NoColorConfig())
	want := `
  1 affected   1 reachable   0 known exploited   1 public exploit

  SOURCE                CRITICAL     HIGH         MEDIUM       LOW          EXPLOITED   CHECKED
  package-lock.json        -            1 ▆▆▆▆▆▆     -            -                 -         1
  api/requirements.txt     -            -            -            -                 -         1
  ───────────────────────────────────────────────────────────────────────────────────────────
  total                    0            1            0            0                 -         2

  Not checked    1 git, local or unpinned dependency: 1 api/requirements.txt
  Scanned        app · 2 packages

[AFFECTED] npm/lodash@4.17.20  high, 1 advisories  fix: 4.17.21
  ↳ CVE-2021-23337   high     7.2 POC  Command Injection

  1 package clean or not in the index, not listed (--show-all lists them)
`
	if out != want {
		t.Errorf("got\n%s\nwant\n%s", out, want)
	}
	scanShowAll = true
	if out := renderFolder(inv, res, scanSource{input: "app"}, 10, renderer.NoColorConfig()); !strings.Contains(out, "[CLEAN] pypi/django@3.2.0") {
		t.Errorf("--show-all lists no clean package:\n%s", out)
	}
}

// TestRunFolderScanJSON scans a folder to --json with --fail-on decided on that path too, and leaves no file in
// the working directory.
func TestRunFolderScanJSON(t *testing.T) {
	srv := folderServer(t)
	defer srv.Close()
	client, err := vulnx.New(vulnx.WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	saved := vulnxClient
	t.Cleanup(func() {
		vulnxClient = saved
		scanFailOn, jsonOutput, outputFile = "", false, ""
	})
	vulnxClient, jsonOutput = client, true
	t.Chdir(t.TempDir())
	outputFile = filepath.Join(t.TempDir(), "folder.json")
	dir := folderFixture(t)
	for level, want := range map[string]bool{"high": true, "kev": false} {
		if err := os.RemoveAll(outputFile); err != nil {
			t.Fatal(err)
		}
		scanFailOn = level
		failed, err := runFolderScan(t.Context(), dir, 10)
		if err != nil || failed != want {
			t.Errorf("--fail-on %s: failed %v err %v", level, failed, err)
		}
	}
	raw, err := os.ReadFile(outputFile)
	if err != nil || !bytes.Contains(raw, []byte(`"folder": {`)) || !bytes.Contains(raw, []byte(`"CVE-2021-23337"`)) {
		t.Errorf("%v\n%s", err, raw)
	}
	if left, err := filepath.Glob("vulnx-*"); err != nil || len(left) > 0 {
		t.Errorf("--json left %v (%v)", left, err)
	}
}

// imageServer answers a package check (all clean) and image scans: alpine:3.20 with one affected package, any
// other image refused by its registry.
func imageServer(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		write := func(v any) {
			if err := json.NewEncoder(w).Encode(v); err != nil {
				t.Error(err)
			}
		}
		if r.Method == http.MethodGet {
			if strings.HasSuffix(r.URL.Path, "/alpine") {
				write(map[string]any{"id": "alpine", "status": "ready", "total": 1, "summary": map[string]any{"packages": 1, "affected": 1},
					"items": []map[string]any{{"input": "alpine:3.20/busybox@1.36.1-r29", "package": "apk/busybox", "version": "1.36.1-r29",
						"status": "affected", "worst_severity": "medium", "advisories": 1, "distro": "alpine", "release": "3.20"}}})
				return
			}
			write(map[string]any{"id": "other", "status": "failed", "error": "the registry refused the image: it is private or does not exist"})
			return
		}
		var body io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			zr, err := gzip.NewReader(r.Body)
			if err != nil {
				t.Error(err)
				return
			}
			body = zr
		}
		var req struct {
			Packages []string
			Image    string
		}
		if err := json.NewDecoder(body).Decode(&req); err != nil {
			t.Error(err)
			return
		}
		if req.Image != "" {
			id := "other"
			if req.Image == "alpine:3.20" {
				id = "alpine"
			}
			write(map[string]any{"id": id, "status": "queued"})
			return
		}
		var items []map[string]any
		for _, p := range req.Packages {
			items = append(items, map[string]any{"input": p, "status": "clean", "seen": "version"})
		}
		write(map[string]any{"total": len(items), "summary": map[string]any{"packages": len(items), "clean": len(items)}, "items": items})
	}))
}

// TestFolderImages lists the images a folder's Dockerfile and Compose file name without scanning them, and with
// --images scans each: one scanned is a row of its own, one refused or unresolved is not checked, with why.
func TestFolderImages(t *testing.T) {
	srv := imageServer(t)
	defer srv.Close()
	client, err := vulnx.New(vulnx.WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	saved := vulnxClient
	t.Cleanup(func() { vulnxClient, scanImages = saved, false })
	vulnxClient = client
	dir := t.TempDir()
	for rel, body := range map[string]string{
		"Dockerfile":          "FROM alpine:3.20 AS base\nFROM base\nFROM ${REGISTRY}/tools:1\n",
		"deploy/compose.yaml": "services:\n  app:\n    build: .\n  db:\n    image: ghcr.io/acme/private:1\n  cache:\n    image: alpine:3.20\n",
		"package-lock.json":   `{"lockfileVersion": 3, "packages": {"": {}, "node_modules/ms": {"version": "2.1.3"}}}`,
	} {
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	inv, err := vulnx.FolderEntries(t.Context(), dir, vulnx.FolderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := checkInventory(t.Context(), inv)
	if err != nil {
		t.Fatal(err)
	}
	out := renderFolder(inv, res, scanSource{input: "app"}, 10, renderer.NoColorConfig())
	for _, want := range []string{
		"\n  Images         2 found, not scanned: alpine:3.20 (Dockerfile), ghcr.io/acme/private:1 (deploy/compose.yaml); " +
			"1 with a variable no file sets: ${REGISTRY}/tools:1 (Dockerfile)\n",
		"\n                 Add --images to scan them (pulled by SecurityContext; can take minutes each)\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
	if raw, err := folderJSON(inv, res); err != nil || !bytes.Contains(raw, []byte(`"ref": "ghcr.io/acme/private:1"`)) {
		t.Errorf("the JSON lists no image: %v", err)
	}

	scanImages = true
	scanFolderImages(t.Context(), &inv, &res)
	out = renderFolder(inv, res, scanSource{input: "app"}, 10, renderer.NoColorConfig())
	for _, want := range []string{
		"\n  image alpine:3.20     -            -            1 ▆▆▆▆▆▆     -                 -         1\n",
		"\n  Not checked    image ${REGISTRY}/tools:1: a variable no file sets\n",
		"\n  Not checked    image ghcr.io/acme/private:1: the scan failed: the registry refused the image: it is private or does not exist\n",
		"[AFFECTED] alpine:3.20/busybox@1.36.1-r29  medium, 1 advisories\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("--images: no %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "Images ") || strings.Contains(out, "git, local or unpinned") {
		t.Errorf("--images: the unscanned line or images counted as dependencies:\n%s", out)
	}
}
