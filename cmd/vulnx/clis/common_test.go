package clis

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/vulnx/v2"
)

func TestTimeoutFlagApplies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
	}))
	defer srv.Close()
	t.Setenv(vulnx.BaseURLEnvVar, srv.URL)
	origClient, origTimeout := vulnxClient, httpTimeout
	t.Cleanup(func() { vulnxClient, httpTimeout = origClient, origTimeout })
	vulnxClient, httpTimeout = nil, 50*time.Millisecond
	if err := ensureVulnxClientInitialized(nil); err != nil {
		t.Fatal(err)
	}
	// without the timeout the slow answer arrives and fails to decode instead
	_, err := vulnxClient.GetVulnerabilityByID(context.Background(), "CVE-2021-44228", nil)
	if err == nil || !strings.Contains(err.Error(), "Client.Timeout") {
		t.Errorf("--timeout 50ms not applied: %v", err)
	}
}

func TestCLIUserAgent(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	t.Setenv(vulnx.BaseURLEnvVar, srv.URL)
	origClient := vulnxClient
	t.Cleanup(func() { vulnxClient = origClient })
	vulnxClient = nil
	if err := ensureVulnxClientInitialized(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := vulnxClient.GetVulnerabilityByID(context.Background(), "CVE-2021-44228", nil); !errors.Is(err, vulnx.ErrNotFound) {
		t.Fatal(err)
	}
	if want := "vulnx/" + strings.TrimPrefix(Version, "v"); got != want {
		t.Errorf("User-Agent = %q, want %q", got, want)
	}
}

func TestDumpResponsePreview(t *testing.T) {
	body := strings.Repeat("x", maxDumpBody+10)
	resp := &http.Response{StatusCode: 200, ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}
	dump, err := dumpResponsePreview(resp)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(dump), "[body truncated at 64 KiB]") || len(dump) > maxDumpBody+200 {
		t.Errorf("dump is %d bytes, want a bounded preview", len(dump))
	}
	rest, err := io.ReadAll(resp.Body)
	if err != nil || string(rest) != body {
		t.Errorf("body after the dump: %d bytes, %v; want the whole body", len(rest), err)
	}
}

func TestFillProductCVEsFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	t.Setenv(vulnx.BaseURLEnvVar, srv.URL)
	origClient := vulnxClient
	t.Cleanup(func() { vulnxClient = origClient })
	vulnxClient = nil
	if err := ensureVulnxClientInitialized(nil); err != nil {
		t.Fatal(err)
	}
	res := vulnx.StackResult{Items: []vulnx.StackItem{{Package: "cpe/apache:tomcat", Version: "8.5.62", AdvisoryRowsTotal: 20,
		AdvisoryRows: []vulnx.StackAdvisory{{CVE: "CVE-2021-1"}}}}}
	if err := fillProductCVEs(context.Background(), &res); err == nil || !strings.Contains(err.Error(), "apache:tomcat 8.5.62") {
		t.Errorf("failed expansion: %v, want an error naming the product", err)
	}
}

func TestWriteStdoutFailureExits(t *testing.T) {
	if os.Getenv("VULNX_TEST_WRITE_STDOUT") == "1" {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		os.Stdout = w
		writeStdout([]byte(`{"results":[]}`))
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestWriteStdoutFailureExits$")
	cmd.Env = append(os.Environ(), "VULNX_TEST_WRITE_STDOUT=1")
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() == 0 {
		t.Errorf("a failed stdout write exited with %v, want a non-zero status\n%s", err, out)
	}
}
