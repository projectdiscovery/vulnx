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
	"github.com/spf13/pflag"
)

// TestCheckHostFlags refuses a host-only flag without --host, and --host with a file, a list or an image.
func TestCheckHostFlags(t *testing.T) {
	t.Cleanup(func() { scanHost, scanView, scanFailOn, scanImage = false, "grid", "", "" })
	flags := func(set ...string) *pflag.FlagSet {
		fs := pflag.NewFlagSet("scan", pflag.ContinueOnError)
		var s string
		var b bool
		for _, name := range hostOnlyFlags {
			if name == "graph" || name == "report" {
				fs.BoolVar(&b, name, false, "")
			} else {
				fs.StringVar(&s, name, "", "")
			}
		}
		if err := fs.Parse(set); err != nil {
			t.Fatal(err)
		}
		return fs
	}
	scanHost = false
	for _, set := range [][]string{{"--fail-on=high"}, {"--view=actions"}, {"--sbom=x.json"}, {"--graph"}, {"--report"}, {"--root=/mnt"}} {
		if err := checkHostFlags(flags(set...), nil); err == nil || !strings.Contains(err.Error(), "only with --host") {
			t.Errorf("%v without --host: %v", set, err)
		}
	}
	if err := checkHostFlags(flags(), []string{"package-lock.json"}); err != nil {
		t.Errorf("a file scan: %v", err)
	}
	scanHost, scanView = true, "grid"
	if err := checkHostFlags(flags("--fail-on=high"), nil); err != nil {
		t.Errorf("--host --fail-on: %v", err)
	}
	if err := checkHostFlags(flags(), []string{"package-lock.json"}); err == nil {
		t.Error("--host with a file")
	}
	scanImage = "debian:12"
	if err := checkHostFlags(flags(), nil); err == nil {
		t.Error("--host with --image")
	}
	scanImage, scanView = "", "pretty"
	if err := checkHostFlags(flags(), nil); err == nil {
		t.Error("an unknown view")
	}
	scanView, scanFailOn = "grid", "medium"
	if err := checkHostFlags(flags(), nil); err == nil {
		t.Error("an unknown --fail-on level")
	}
}

// TestRunHostScanJSON scans a mounted Linux root against a local API and writes --json to a file: --fail-on is
// decided on that path too, and no dated report is left in the working directory.
func TestRunHostScanJSON(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("etc/os-release", "ID=debian\nVERSION_ID=12\n")
	write("var/lib/dpkg/status", "Package: openssl\nStatus: install ok installed\nVersion: 3.0.11-1\n\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		if err := json.NewDecoder(body).Decode(&req); err != nil || len(req.Packages) != 1 {
			t.Errorf("%v %q", err, req.Packages)
			return
		}
		out := map[string]any{"total": 1, "summary": map[string]any{"packages": 1, "affected": 1}, "items": []map[string]any{{
			"input": req.Packages[0], "package": "deb/openssl", "version": "3.0.11-1", "status": "affected", "worst_severity": "high",
			"advisories": 1, "advisory_rows": []map[string]any{{"cve": "CVE-2024-1", "severity": "high"}}}}}
		if err := json.NewEncoder(w).Encode(out); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()
	client, err := vulnx.New(vulnx.WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	saved := vulnxClient
	t.Cleanup(func() {
		vulnxClient = saved
		scanHost, scanRoot, scanFailOn, jsonOutput, outputFile = false, "", "", false, ""
	})
	vulnxClient, scanHost, scanRoot, jsonOutput = client, true, root, true
	outputFile = filepath.Join(t.TempDir(), "host.json")
	for level, want := range map[string]bool{"high": true, "critical": false} {
		if err := os.RemoveAll(outputFile); err != nil {
			t.Fatal(err)
		}
		scanFailOn = level
		failed, err := runHostScan(t.Context())
		if err != nil || failed != want {
			t.Errorf("--fail-on %s: failed %v err %v", level, failed, err)
		}
	}
	raw, err := os.ReadFile(outputFile)
	if err != nil || !bytes.Contains(raw, []byte(`"CVE-2024-1"`)) || !bytes.Contains(raw, []byte(`"os": "debian 12"`)) {
		t.Errorf("%v\n%s", err, raw)
	}
	if left, err := filepath.Glob("vulnx-host-*"); err != nil || len(left) > 0 {
		t.Errorf("--json left %v (%v)", left, err)
	}
}

// TestStdoutTextFails reports a write to a stdout that is gone, and keeps the first error: a scan whose output did
// not arrive fails.
func TestStdoutTextFails(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	t.Cleanup(func() { os.Stdout = saved })
	os.Stdout = w
	out := &stdoutText{}
	out.print("report\n")
	first := out.err
	out.printf("%s\n", "more")
	os.Stdout = saved
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if first == nil || out.err != first {
		t.Errorf("%v %v", first, out.err)
	}
}
