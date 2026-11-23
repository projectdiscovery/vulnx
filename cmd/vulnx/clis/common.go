package clis

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/spf13/cobra"

	"time"

	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"

	_ "embed"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	retryablehttp "github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/vulnx/v2"

	fileutil "github.com/projectdiscovery/utils/file"
	updateutils "github.com/projectdiscovery/utils/update"
	"github.com/projectdiscovery/vulnx/v2/internal/termtext"
	"github.com/projectdiscovery/vulnx/v2/pkg/tools/analyze"
	"github.com/projectdiscovery/vulnx/v2/pkg/tools/renderer"
)

//go:embed banner.txt
var vulnxBanner string

var (
	verbose bool
	debug   bool

	// HTTP client config
	httpProxy   string
	httpTimeout time.Duration

	// Global vulnx client
	vulnxClient *vulnx.Client

	debugReq  bool
	debugResp bool

	// Add global json and output flags
	jsonOutput bool
	outputFile string

	// Add global silent flag
	silent bool

	// Add global no-color flag
	noColor bool

	// Global disable update check flag
	globalDisableUpdateCheck bool

	// updateSelf is the root --update flag
	updateSelf bool

	// Track if the banner has already been shown for this invocation
	bannerShown bool

	// Track if version has been shown for this invocation
	versionShown bool

	// cveIDRegex finds CVE ids inside free text
	cveIDRegex = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,}\b`)

	rootCmd = &cobra.Command{
		Use:   "vulnx",
		Short: "vulnx — the swiss army knife for vulnerability intel",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if updateSelf {
				GetUpdateCallback()()
				return nil
			}

			if !silent {
				showBanner()
				// Don't show version info for the version command itself
				if cmd.Name() != "version" {
					showVersionInfo()
				}
			}
			err := ensureVulnxClientInitialized(cmd)
			if err != nil {
				return err
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// If no subcommand is provided and stdin has data, try to auto-detect the command
			if len(args) == 0 && fileutil.HasStdin() {
				return handleStdinAutoDetection(cmd, args)
			}

			// If no subcommand is provided and no stdin, show dashboard
			if len(args) == 0 {
				return showDashboard()
			}

			// Otherwise, show help
			return cmd.Help()
		},
	}
)

func init() {
	// Global flags for gologger
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "enable debug output")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")

	// HTTP client config flags
	rootCmd.PersistentFlags().StringVar(&httpProxy, "proxy", "", "http proxy to use (e.g. http://127.0.0.1:8080)")
	rootCmd.PersistentFlags().DurationVar(&httpTimeout, "timeout", defaultTimeout, "http request timeout (e.g. 30s, 1m)")

	rootCmd.PersistentFlags().BoolVar(&debugReq, "debug-req", false, "dump http requests to stderr (api key redacted)")
	rootCmd.PersistentFlags().BoolVar(&debugResp, "debug-resp", false, "dump http responses to stderr")

	// Add persistent json and output flags
	rootCmd.PersistentFlags().BoolVarP(&jsonOutput, "json", "j", false, "output raw json (for piping)")
	rootCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "write output to file, json or csv by extension (error if file exists)")

	// Add persistent silent flag
	rootCmd.PersistentFlags().BoolVar(&silent, "silent", false, "silent mode (suppress banner and non-essential output)")

	// Add persistent no-color flag
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "disable colored output")

	// Add persistent disable update check flag
	rootCmd.PersistentFlags().BoolVar(&globalDisableUpdateCheck, "disable-update-check", false, "disable automatic vulnx update check")

	// main reports the error once
	rootCmd.SilenceErrors = true

	// Update flag
	rootCmd.Flags().BoolVar(&updateSelf, "update", false, "update vulnx to latest version")

	// Custom help and usage to always show banner
	defaultHelpFunc := rootCmd.HelpFunc()
	rootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		if !silent {
			showBanner()
			// Don't show version info for the version command itself
			if cmd.Name() != "version" {
				showVersionInfo()
			}
		}
		defaultHelpFunc(cmd, args)
	})
	defaultUsageFunc := rootCmd.UsageFunc()
	rootCmd.SetUsageFunc(func(cmd *cobra.Command) error {
		if !silent {
			showBanner()
			// Don't show version info for the version command itself
			if cmd.Name() != "version" {
				showVersionInfo()
			}
		}
		return defaultUsageFunc(cmd)
	})

}

// Execute executes the root command
func Execute() error {
	// Reset bannerShown for each top-level execution
	bannerShown = false
	versionShown = false
	return rootCmd.Execute()
}

// ensureVulnxClientInitialized initializes the global vulnxClient if it is nil.
func ensureVulnxClientInitialized(_ *cobra.Command) error {
	// Configure gologger levels based on flags
	if debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
		gologger.Debug().Msg("Debug logging enabled")
	} else if verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
		gologger.Verbose().Msg("Verbose logging enabled")
	} else if silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}

	if vulnxClient == nil {
		if debug {
			debugReq = true
			debugResp = true
		}

		transport := &http.Transport{}
		if httpProxy != "" {
			proxyURL, err := url.Parse(httpProxy)
			if err != nil {
				return fmt.Errorf("invalid proxy URL: %w", err)
			}
			transport.Proxy = http.ProxyURL(proxyURL)
		} else {
			transport.Proxy = http.ProxyFromEnvironment
		}
		// a zero or negative --timeout would disable the deadline: keep the default
		if httpTimeout <= 0 {
			httpTimeout = defaultTimeout
		}
		httpClient := &http.Client{
			Transport: transport,
			Timeout:   httpTimeout,
		}
		retryOpts := retryablehttp.DefaultOptionsSingle
		retryOpts.HttpClient = httpClient
		// retryablehttp sets the client's timeout from its own option
		retryOpts.Timeout = httpTimeout
		retryOpts.Verbose = debug

		opts := []vulnx.Option{
			vulnx.WithRetryableHTTPOptions(retryOpts),
			vulnx.WithUserAgent("vulnx/" + strings.TrimPrefix(Version, "v")),
		}
		if debugReq {
			opts = append(opts, vulnx.WithDebugRequest(func(req *http.Request) {
				dump, err := httputil.DumpRequestOut(req, true)
				printDump("HTTP REQUEST", dump, err)
			}))
		}
		if debugResp {
			opts = append(opts, vulnx.WithDebugResponse(func(resp *http.Response) {
				dump, err := dumpResponsePreview(resp)
				printDump("HTTP RESPONSE", dump, err)
			}))
		}
		client, err := vulnx.New(opts...)
		if err != nil {
			return fmt.Errorf("failed to initialize vulnx client: %w", err)
		}
		vulnxClient = client

	}
	return nil
}

// handleRateLimitError provides a common, user-friendly rate limit error message
func handleRateLimitError() {
	gologger.Fatal().Msg("Rate limit exceeded: SecurityContext allows anonymous callers a limited number of requests a minute per address; wait a minute and retry")
}

func showBanner() {
	if !bannerShown {
		fmt.Fprintf(os.Stderr, "%s\n", vulnxBanner)
		bannerShown = true
	}
}

// showDashboard displays key vulnerability statistics and data overview
func showDashboard() error {
	if silent {
		// If silent mode, just show basic stats in JSON format
		return showDashboardJSON()
	}

	fmt.Printf("\n")
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("📊 vulnerability trends & metrics\n")
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

	handler := analyze.NewHandler(vulnxClient)

	// one request for severity, vendors and exploit signals: anonymous callers are rate limited
	overallResp, err := handler.Analyze(analyze.Params{
		Fields:    []string{"severity=8", "affected_products.vendor=5", "exploit=10"},
		FacetSize: vulnx.Ptr(10),
	})
	if err != nil {
		if errors.Is(err, vulnx.ErrTooManyRequests) {
			fmt.Printf("⚠️  Dashboard unavailable: rate limited (anonymous callers get a few requests a minute); try again shortly.\n\n")
			renderQuickStartCommands()
			return nil
		}
		return fmt.Errorf("failed to fetch dashboard data: %v", err)
	}

	totalCount := overallResp.Total

	renderSeverityDistribution(overallResp.Facets, totalCount)
	renderVendorBreakdown(overallResp.Facets)
	renderWeaknesses(handler)
	renderExploitSignals(overallResp.Facets, totalCount)
	renderEPSSDistribution(totalCount)
	renderQuickStartCommands()

	return nil
}

func showDashboardJSON() error {
	// Simple JSON dashboard for silent mode

	handler := analyze.NewHandler(vulnxClient)

	params := analyze.Params{
		Fields:    []string{"severity", "exploit", "affected_products.vendor"},
		FacetSize: vulnx.Ptr(10),
	}

	resp, err := handler.Analyze(params)
	if err != nil {
		if errors.Is(err, vulnx.ErrTooManyRequests) {
			// Return minimal JSON for rate limited requests
			fmt.Println(`{"error": "Dashboard unavailable: rate limited; try again shortly."}`)
			return nil
		}
		return fmt.Errorf("failed to fetch dashboard data: %v", err)
	}

	dashboardData := map[string]interface{}{
		"total_vulnerabilities": resp.Total,
		"facets":                resp.Facets,
	}

	jsonBytes, err := json.MarshalIndent(dashboardData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal dashboard JSON: %v", err)
	}

	fmt.Printf("%s\n", jsonBytes)
	return nil
}

func handleStdinAutoDetection(cmd *cobra.Command, args []string) error {
	// Read stdin content
	stdinData, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read stdin: %w", err)
	}

	content := strings.TrimSpace(string(stdinData))
	if content == "" {
		return fmt.Errorf("no input provided via stdin")
	}

	// Check if the content looks like CVE IDs
	if isCVEContent(content) {
		// Auto-route to id command
		return executeIDCommand(content)
	}

	// If not CVE IDs, show help
	return cmd.Help()
}

func isCVEContent(content string) bool {
	// Check if content contains CVE IDs
	lines := strings.Split(content, "\n")
	cveCount := 0
	totalLines := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty lines and comments
		}
		totalLines++

		// Check if line contains CVE IDs (either directly or comma-separated)
		if cveIDRegex.MatchString(line) {
			cveCount++
		}
	}

	// Consider it CVE content if majority of non-empty lines contain CVE IDs
	return totalLines > 0 && cveCount > 0 && float64(cveCount)/float64(totalLines) >= 0.5
}

func executeIDCommand(content string) error {
	cveIDs := extractCVEIDs(content)
	if len(cveIDs) == 0 {
		return fmt.Errorf("no CVE ids found in stdin input")
	}
	runIDs(cveIDs)
	return nil
}

// isCSVOutput reports whether --output asks for CSV. Any other extension keeps the JSON default.
func isCSVOutput() bool {
	return strings.EqualFold(filepath.Ext(outputFile), ".csv")
}

// writeVulnsOutput writes vulns to --output as CSV or JSON, or prints JSON to stdout.
// A single requested ID is emitted as an object rather than an array.
func writeVulnsOutput(vulns []*vulnx.Vulnerability, single bool) {
	var data []byte
	var err error
	switch {
	case isCSVOutput():
		data, err = renderVulnsCSV(vulns)
	case single:
		data, err = json.MarshalIndent(vulns[0], "", "  ")
	default:
		data, err = json.MarshalIndent(vulns, "", "  ")
	}
	if err != nil {
		gologger.Fatal().Msgf("Failed to render output: %s", err)
	}

	if outputFile != "" {
		if err := writeNewFile(outputFile, data); err != nil {
			gologger.Fatal().Msgf("%s", err)
		}
		gologger.Info().Msgf("Wrote %d vulnerability(s) to file: %s", len(vulns), outputFile)
		return
	}

	writeStdout(data)
}

// renderVulnsCSV converts vulnerabilities to CSV rows.
func renderVulnsCSV(vulns []*vulnx.Vulnerability) ([]byte, error) {
	entries := make([]*renderer.Entry, 0, len(vulns))
	for _, vuln := range vulns {
		entries = append(entries, renderer.FromVulnerability(vuln))
	}
	return renderer.RenderCSV(entries)
}

// writeStdout prints data and a newline to stdout. A failed write (a closed pipe, a full disk) ends the run with
// a non-zero status, so a caller never takes truncated JSON or VEX output as a success.
func writeStdout(data []byte) {
	if _, err := os.Stdout.Write(append(data, '\n')); err != nil {
		gologger.Fatal().Msgf("Failed to write output: %s", err)
	}
}

// writeNewFile writes data to path, refusing to overwrite an existing file.
func writeNewFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("output file already exists: %s", path)
	}
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to write to output file: %w", err)
	}
	return f.Close()
}

type bucket struct {
	key   string
	count int
}

// extractBuckets reads a facet's buckets, largest first.
func extractBuckets(facets map[string]any, fieldName string) []bucket {
	facet, _ := facets[fieldName].(map[string]any)
	items, _ := facet["buckets"].([]any)
	var buckets []bucket
	for _, item := range items {
		m, _ := item.(map[string]any)
		key, _ := m["key"].(string)
		count, _ := m["count"].(float64)
		if count > 0 {
			buckets = append(buckets, bucket{key, int(count)})
		}
	}
	sort.SliceStable(buckets, func(i, j int) bool { return buckets[i].count > buckets[j].count })
	return buckets
}

// formatNumber formats large numbers with commas for better readability
func formatNumber(n int) string {
	str := fmt.Sprintf("%d", n)
	if len(str) <= 3 {
		return str
	}

	var result strings.Builder
	for i, digit := range str {
		if i > 0 && (len(str)-i)%3 == 0 {
			result.WriteString(",")
		}
		result.WriteRune(digit)
	}
	return result.String()
}

// renderSeverityDistribution displays vulnerability severity breakdown
func renderSeverityDistribution(facets map[string]any, totalCount int) {
	severityBuckets := extractBuckets(facets, "severity")

	// Create severity order for better presentation (excluding non-informative values)
	severityOrder := []string{"critical", "high", "medium", "low", "info"}
	orderedBuckets := make(map[string]int)

	for _, bucket := range severityBuckets {
		// Only include meaningful severity values
		lowerKey := strings.ToLower(strings.TrimSpace(bucket.key))
		if lowerKey != "" &&
			lowerKey != "undefined" &&
			lowerKey != "unassigned" &&
			lowerKey != "unknown" &&
			lowerKey != "n/a" &&
			lowerKey != "none" &&
			lowerKey != "null" {
			orderedBuckets[bucket.key] = bucket.count
		}
	}

	// Calculate total count for meaningful severities only
	meaningfulTotal := 0
	for _, count := range orderedBuckets {
		meaningfulTotal += count
	}

	// Skip section if no meaningful severities found
	if meaningfulTotal == 0 {
		return
	}

	fmt.Printf("🧮 severity distribution (total: %s)\n", formatNumber(meaningfulTotal))

	for _, severity := range severityOrder {
		if count, exists := orderedBuckets[severity]; exists && count > 0 {
			percentage := float64(count) / float64(meaningfulTotal) * 100
			barLength := int(percentage / 2.0) // Scale to 50 chars max
			if barLength > 50 {
				barLength = 50
			}
			if barLength < 1 && percentage > 0 {
				barLength = 1
			}

			bar := strings.Repeat("█", barLength)
			spaces := strings.Repeat(" ", 50-barLength)

			fmt.Printf("   %-8s │%s%s│ %8s (%5.1f%%)\n",
				severity, bar, spaces, formatNumber(count), percentage)
		}
	}
	fmt.Printf("\n")
}

// renderVendorBreakdown displays top affected vendors
func renderVendorBreakdown(facets map[string]any) {
	fmt.Printf("🏢 top affected vendors\n")

	vendorBuckets := extractBuckets(facets, "affected_products.vendor")

	if len(vendorBuckets) > 5 {
		vendorBuckets = vendorBuckets[:5]
	}

	maxCount := 0
	if len(vendorBuckets) > 0 {
		maxCount = vendorBuckets[0].count
	}

	for i, vendor := range vendorBuckets {
		percentage := float64(vendor.count) / float64(maxCount) * 100
		barLength := int(percentage / 2.5) // Scale to 40 chars max
		if barLength > 40 {
			barLength = 40
		}
		if barLength < 1 {
			barLength = 1
		}

		bar := strings.Repeat("█", barLength)
		spaces := strings.Repeat(" ", 40-barLength)

		fmt.Printf("%2d. %-12s │%s%s│ %s CVEs\n",
			i+1, termtext.Clean(vendor.key), bar, spaces, formatNumber(vendor.count))
	}
	fmt.Printf("\n")
}

// cweLabel is a CWE id as a weakness bucket key; other keys (NVD-CWE-noinfo, CWE-Other) are not weaknesses.
var cweLabel = regexp.MustCompile(`^CWE-[0-9]+$`)

// cweNames names the weaknesses that lead the CVE list (CWE Top 25 and other frequent ones).
var cweNames = map[string]string{
	"CWE-79": "cross-site scripting", "CWE-787": "out-of-bounds write", "CWE-89": "sql injection",
	"CWE-352": "cross-site request forgery", "CWE-22": "path traversal", "CWE-125": "out-of-bounds read",
	"CWE-78": "os command injection", "CWE-416": "use after free", "CWE-862": "missing authorization",
	"CWE-434": "unrestricted file upload", "CWE-94": "code injection", "CWE-20": "improper input validation",
	"CWE-77": "command injection", "CWE-287": "improper authentication", "CWE-269": "improper privilege management",
	"CWE-502": "unsafe deserialization", "CWE-200": "information exposure", "CWE-863": "incorrect authorization",
	"CWE-918": "server-side request forgery", "CWE-119": "memory buffer errors", "CWE-476": "null pointer dereference",
	"CWE-798": "hard-coded credentials", "CWE-190": "integer overflow", "CWE-400": "uncontrolled resource consumption",
	"CWE-306": "missing authentication", "CWE-120": "buffer overflow", "CWE-401": "memory leak",
	"CWE-284": "improper access control", "CWE-264": "permissions & privileges", "CWE-399": "resource management",
	"CWE-617": "reachable assertion", "CWE-639": "authorization bypass (idor)", "CWE-601": "open redirect",
	"CWE-362": "race condition", "CWE-732": "incorrect permissions", "CWE-611": "xml external entities",
}

// renderWeaknesses shows the most frequent weaknesses (CWE) across CVEs.
func renderWeaknesses(handler *analyze.Handler) {
	resp, err := handler.Analyze(analyze.Params{Fields: []string{"cwe=8"}, FacetSize: vulnx.Ptr(8)})
	if err != nil {
		if !errors.Is(err, vulnx.ErrTooManyRequests) {
			fmt.Printf("⚠️  Unable to fetch weakness data: %v\n\n", err)
		}
		return
	}
	var buckets []bucket
	for _, b := range extractBuckets(resp.Facets, "cwe") {
		if cweLabel.MatchString(b.key) {
			buckets = append(buckets, b)
		}
	}
	if len(buckets) > 5 {
		buckets = buckets[:5]
	}
	if len(buckets) == 0 {
		return
	}
	fmt.Printf("🔍 top weaknesses (cwe)\n")
	maxCount := buckets[0].count
	for _, b := range buckets {
		barLength := b.count * 20 / maxCount
		if barLength < 1 {
			barLength = 1
		}
		label := b.key
		if name := cweNames[b.key]; name != "" {
			label = fmt.Sprintf("%-8s %s", b.key, name)
		}
		fmt.Printf("   %-36s │%s%s│ %s\n", label, strings.Repeat("█", barLength), strings.Repeat("▁", 20-barLength), formatNumber(b.count))
	}
	fmt.Printf("\n")
}

// renderEPSSDistribution counts CVEs per EPSS band (three count queries: EPSS at least 0.7, 0.3 and 0.1).
func renderEPSSDistribution(totalCount int) {
	atLeast := func(score string) (int, error) {
		resp, err := vulnxClient.SearchVulnerabilities(context.Background(), vulnx.SearchParams{
			Query: vulnx.Ptr("epss_score:>=" + score), Limit: vulnx.Ptr(1)})
		return resp.Total, err
	}
	var n07, n03, n01 int
	var err error
	if n07, err = atLeast("0.7"); err == nil {
		if n03, err = atLeast("0.3"); err == nil {
			n01, err = atLeast("0.1")
		}
	}
	if err != nil {
		if !errors.Is(err, vulnx.ErrTooManyRequests) {
			fmt.Printf("⚠️  Unable to fetch EPSS data: %v\n\n", err)
		}
		return
	}
	// four separate counts: if the index changed between them, the bands would not add up
	if totalCount <= 0 || n07 > n03 || n03 > n01 || n01 > totalCount {
		return
	}
	fmt.Printf("📈 exploit prediction scoring system (epss) distribution\n")
	bands := []struct {
		label, range_ string
		count         int
	}{
		{"critical", "0.7-1.0", n07},
		{"high", "0.3-0.7", n03 - n07},
		{"medium", "0.1-0.3", n01 - n03},
		{"low", "<0.1 or none", totalCount - n01},
	}
	for _, b := range bands {
		percentage := float64(b.count) / float64(totalCount) * 100
		barLength := int(percentage / 2.0)
		if barLength > 50 {
			barLength = 50
		}
		if barLength < 1 && b.count > 0 {
			barLength = 1
		}
		fmt.Printf("   %-8s %-9s │%s%s│ %8s (%5.1f%%)\n", b.label, "("+b.range_+")", strings.Repeat("█", barLength),
			strings.Repeat(" ", 50-barLength), formatNumber(b.count), percentage)
	}
	fmt.Printf("\n")
}

// renderExploitSignals shows how many CVEs carry each exploitation signal (from the exploit facet).
func renderExploitSignals(facets map[string]any, totalCount int) {
	counts := map[string]int{}
	for _, b := range extractBuckets(facets, "exploit") {
		counts[b.key] = b.count
	}
	rows := []struct{ key, label string }{
		{"known_exploited", "CISA KEV"},
		{"vulncheck_known_exploited", "VulnCheck KEV"},
		{"ransomware", "ransomware use"},
		{"initial_access", "initial access"},
		{"nuclei_template", "nuclei template"},
		{"public_exploit", "public exploit"},
	}
	maxCount := 0
	for _, r := range rows {
		if counts[r.key] > maxCount {
			maxCount = counts[r.key]
		}
	}
	if maxCount == 0 {
		return
	}
	fmt.Printf("🚨 exploitation signals (CVEs; VulnCheck KEV includes every CISA KEV entry)\n")
	for _, r := range rows {
		n := counts[r.key]
		if n == 0 {
			continue
		}
		barLength := n * 40 / maxCount
		if barLength < 1 {
			barLength = 1
		}
		fmt.Printf("   %-16s │%s%s│ %8s (%5.2f%%)\n", r.label, strings.Repeat("█", barLength), strings.Repeat(" ", 40-barLength),
			formatNumber(n), float64(n)/float64(totalCount)*100)
	}
	fmt.Printf("\n")
}

// renderQuickStartCommands displays quick start commands
func renderQuickStartCommands() {
	fmt.Printf("🚀 quick start\n")

	commands := []struct {
		cmd  string
		desc string
	}{
		{"vulnx --help", "show help menu"},
		{"vulnx search \"is_template:true\"", "cves with nuclei templates"},
		{"vulnx search \"is_kev:true\"", "known exploited vulns"},
		{"vulnx id CVE-2021-44228", "fetch metadata for a CVE"},
		{"vulnx search --cpe <cpe>", "cves affecting a product version"},
		{"vulnx scan package-lock.json", "scan a lockfile or sbom (--vex)"},
		{"vulnx analyze -f severity", "analyze by severity"},
	}

	for _, cmd := range commands {
		fmt.Printf("   %-35s # %s\n", cmd.cmd, cmd.desc)
	}
	fmt.Printf("\n")
}

// showVersionInfo displays version information like other ProjectDiscovery tools
func showVersionInfo() {
	if versionShown || silent || globalDisableUpdateCheck {
		return
	}
	versionShown = true

	// Get version from the version.go file
	currentVersion := Version

	// Check for updates using PDTM API
	latestVersion, err := updateutils.GetToolVersionCallback("vulnx", currentVersion)()
	if err != nil {
		// If version check fails, show error only in verbose/debug mode
		if verbose || debug {
			gologger.Error().Msgf("vulnx version check failed: %v", err.Error())
		}
		return
	}

	// Format version status exactly like vulnx
	description := updateutils.GetVersionDescription(currentVersion, latestVersion)
	gologger.Info().Msgf("Current vulnx version %s %s", currentVersion, description)
}

// GetUpdateCallback returns a callback function that updates vulnx
func GetUpdateCallback() func() {
	return func() {
		showBanner()
		updateutils.GetUpdateToolCallback("vulnx", Version)()
	}
}

var sensitiveHeaderRe = regexp.MustCompile(`(?i)(X-Api-Key:\s*).*`)

func redactSensitiveHeaders(dump []byte) string {
	return sensitiveHeaderRe.ReplaceAllString(string(dump), "${1}[REDACTED]")
}

const defaultTimeout = 30 * time.Second

// maxDumpBody bounds the body shown by --debug-resp; the client reads the rest as usual.
const maxDumpBody = 64 << 10

// dumpResponsePreview dumps the headers and up to maxDumpBody of the body, then puts what it read back in front
// of the body, so the client still decodes (and size-checks) the whole response.
func dumpResponsePreview(resp *http.Response) ([]byte, error) {
	head, err := httputil.DumpResponse(resp, false)
	if err != nil {
		return nil, err
	}
	preview, err := io.ReadAll(io.LimitReader(resp.Body, maxDumpBody))
	resp.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(preview), resp.Body), resp.Body}
	if err != nil {
		return nil, err
	}
	dump := append(head, preview...)
	if len(preview) == maxDumpBody {
		dump = append(dump, fmt.Sprintf("\n[body truncated at %d KiB]", maxDumpBody>>10)...)
	}
	return dump, nil
}

// printDump writes a request or response dump to stderr, so it never mixes with --json output.
func printDump(title string, dump []byte, err error) {
	if err != nil {
		gologger.Error().Msgf("%s dump: %s", title, err)
		return
	}
	fmt.Fprintf(os.Stderr, "--- %s ---\n%s\n---\n", title, termtext.Clean(redactSensitiveHeaders(dump)))
}
