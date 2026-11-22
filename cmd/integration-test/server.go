package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/vulnx/v2/pkg/types"
)

var cveData *types.CVEBulkData

func SetupMockServer() {
	var err error
	// Load data from the JSON file
	cveData, err = loadData("test-data.json")
	if err != nil {
		fmt.Println("Error loading data:", err)
		return
	}

	// Setup HTTP server with mux for path-based routing
	mux := http.NewServeMux()

	// SecurityContext's /v1/cves list and /v1/cves/{id} record, in the shapes the live API answers
	mux.HandleFunc("/v1/cves", RequireAPIKey(handleSearchRequest))
	mux.HandleFunc("/v1/cves/", RequireAPIKey(handleGetByIDRequest))

	go func() {
		fmt.Printf("Vulnx test server listening on %s...\n", testPort())
		if err := http.ListenAndServe(":"+testPort(), mux); err != nil {
			fmt.Println("Error starting server:", err)
		}
	}()
}

// testPort is the mock server's port: VULNX_TEST_PORT, default 8080.
func testPort() string {
	if p := os.Getenv("VULNX_TEST_PORT"); p != "" {
		return p
	}
	return "8080"
}

// RequireAPIKey is a middleware that checks for the X-Api-Key header.
func RequireAPIKey(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-Api-Key")
		if apiKey != xPDCPHeaderTestKey {
			http.Error(w, "Unauthorized: X-Api-Key header is required", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// handleGetByIDRequest handles GET /v1/cves/{id}
func handleGetByIDRequest(w http.ResponseWriter, r *http.Request) {
	cveID := strings.TrimPrefix(r.URL.Path, "/v1/cves/")
	for i := range cveData.Cves {
		if strings.EqualFold(cveData.Cves[i].CveID, cveID) {
			rec := scRecord(&cveData.Cves[i])
			rec["found"] = true
			writeJSON(w, rec)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(`{"found":false,"error":"no such CVE"}`))
}

// handleSearchRequest handles GET /v1/cves: every test record, one page, and the facets asked for
func handleSearchRequest(w http.ResponseWriter, r *http.Request) {
	items := make([]map[string]any, 0, len(cveData.Cves))
	for i := range cveData.Cves {
		items = append(items, scRecord(&cveData.Cves[i]))
	}
	resp := map[string]any{"count": len(items), "total": len(items), "items": items, "truncated": false, "cursor": nil}
	if f := r.URL.Query().Get("facets"); f != "" {
		facets := map[string]any{}
		for _, name := range strings.Split(f, ",") {
			facets[name] = []map[string]any{
				{"value": "critical", "count": 10}, {"value": "high", "count": 20},
				{"value": "medium", "count": 30}, {"value": "low", "count": 40},
			}
		}
		resp["facets"] = facets
	}
	writeJSON(w, resp)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// scRecord renders a test CVE the way SecurityContext's /v1/cves does
func scRecord(data *types.CVEData) map[string]any {
	exploitTypes := []string{}
	if data.IsKev {
		exploitTypes = append(exploitTypes, "known_exploited")
	}
	if data.IsPoc {
		exploitTypes = append(exploitTypes, "public_exploit")
	}
	var template any
	if data.IsTemplate {
		template = map[string]any{"id": data.CveID, "url": "https://github.com/projectdiscovery/nuclei-templates"}
	}
	knownBy := []string{}
	if data.IsKev {
		knownBy = append(knownBy, "cisa")
	}
	return map[string]any{
		"cve":             data.CveID,
		"description":     data.CveDescription,
		"severity":        data.Severity,
		"cvss_score":      data.CvssScore,
		"epss_score":      data.Epss.Score,
		"epss_percentile": data.Epss.Percentile,
		"published_date":  strings.SplitN(data.PublishedAt, "T", 2)[0],
		"age_in_days":     data.AgeInDays,
		"exploit_types":   exploitTypes,
		"products":        0,
		"exploitation": map[string]any{
			"known_exploited":      data.IsKev,
			"known_exploited_by":   knownBy,
			"public_exploit":       data.IsPoc,
			"public_exploit_count": len(data.Poc),
			"nuclei_template":      template,
			"remote":               data.IsRemote,
		},
	}
}

// LoadData loads data from a JSON file into a slice of CVEData.
func loadData(filename string) (*types.CVEBulkData, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := file.Close(); err != nil {
			gologger.Error().Msgf("Failed to close file: %s", err)
		}
	}()

	var data types.CVEBulkData
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		return nil, err
	}

	return &data, nil
}
