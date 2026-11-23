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
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/gologger/levels"
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
		scanHost, scanRoot, scanFailOn, jsonOutput, outputFile, scanSBOM = false, "", "", false, "", ""
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
	scanSBOM = filepath.Join(t.TempDir(), "named.cdx.json") // named, the SBOM is written with --json too
	if err := os.RemoveAll(outputFile); err != nil {
		t.Fatal(err)
	}
	if _, err := runHostScan(t.Context()); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(scanSBOM); err != nil || !bytes.Contains(raw, []byte(`"CycloneDX"`)) {
		t.Errorf("named SBOM: %v", err)
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

// fakeLog writes a log line where the progress line is drawn.
type fakeLog struct{ out *bytes.Buffer }

func (f fakeLog) Write(data []byte, _ levels.Level) { f.out.Write(append(data, '\n')) }

// TestProgressAroundLogLines clears the progress line before a log line and draws it again after, and draws no
// progress where stderr is not a terminal.
func TestProgressAroundLogLines(t *testing.T) {
	var out bytes.Buffer
	saved := progress.out
	savedTerminal := progress.terminal
	t.Cleanup(func() { progress.out, progress.terminal, progress.line, progress.failed = saved, savedTerminal, "", false })
	progress.out, progress.terminal = &out, func() bool { return true }
	w := progressWriter{next: fakeLog{&out}}
	w.Write([]byte("[INF] before any progress"), levels.LevelInfo)
	hostProgress("Checking 7,412 components ...")
	w.Write([]byte("[INF] SecurityContext: 503 Service Unavailable; retrying in 5.5s"), levels.LevelInfo)
	hostProgress("")
	w.Write([]byte("[INF] after"), levels.LevelInfo)
	want := "[INF] before any progress\n" +
		"\r\033[KChecking 7,412 components ..." +
		"\r\033[K[INF] SecurityContext: 503 Service Unavailable; retrying in 5.5s\nChecking 7,412 components ..." +
		"\r\033[K" + "[INF] after\n"
	if got := out.String(); got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
	out.Reset()
	progress.terminal = func() bool { return false }
	hostProgress("Checking ...")
	if out.Len() != 0 {
		t.Errorf("progress on a non-terminal: %q", out.String())
	}
}

// TestPrintHostScanFiles writes the day's JSON report and SBOM, readable by their owner only, and lists both under
// the grid in the label column.
func TestPrintHostScanFiles(t *testing.T) {
	t.Chdir(t.TempDir())
	inv, res := hostFixture()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	done := make(chan []byte)
	go func() {
		raw, err := io.ReadAll(r)
		if err != nil {
			t.Error(err)
		}
		done <- raw
	}()
	err = printHostScan(t.Context(), inv, res, time.Second)
	os.Stdout = saved
	if closeErr := w.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	out := string(<-done)
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{".json", ".cdx.json"} {
		path, err := filepath.Abs("vulnx-host-" + time.Now().Format("2006-01-02") + suffix)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v", path, info.Mode().Perm())
		}
		label := "  JSON           "
		if suffix == ".cdx.json" {
			label = "  SBOM           "
		}
		if !strings.Contains(out, label+path+"\n") {
			t.Errorf("no %q line in\n%s", label+path, out)
		}
	}
	if !strings.Contains(out, "Add --report for a shareable link") {
		t.Errorf("no --report hint in\n%s", out)
	}
}
