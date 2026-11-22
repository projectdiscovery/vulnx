package clis

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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
