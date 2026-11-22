package clis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/vulnx/v2"
	"github.com/spf13/cobra"

	"github.com/projectdiscovery/vulnx/v2/pkg/tools/renderer"
)

var (
	// Flag placeholders – defined in init()
	searchLimit      int
	searchAll        bool
	filterCPE        string
	filterVersion    string
	searchOffset     int
	searchSortAsc    string
	searchSortDesc   string
	searchFields     []string
	searchTermFacets []string
	searchFacetSize  int
	searchDetailed   bool

	// Filter flags
	filterProduct       string
	filterVendor        string
	filterSeverity      []string
	filterVulnStatus    string
	filterVulnAge       string
	filterKevOnly       string
	filterTemplate      string
	filterPOC           string
	filterRemoteExploit string
	filterCvssScore     string
	filterEpssScore     string

	// Security-focused layout for CLI rendering
	defaultLayoutJSON = `[
		{
			"line": 1,
			"format": "[{doc_id}] {severity} - {title}",
			"omit_if": []
		},
		{
			"line": 2,
			"format": "  ↳ Priority: {research_priority} | {exploit_status} | Vuln Age: {age_urgency}",
			"omit_if": []
		},
		{
			"line": 3,
			"format": "  ↳ CVSS: {cvss_enhanced} | EPSS: {epss_enhanced} | KEV: {kev_enhanced}",
			"omit_if": ["cvss_score == 0", "epss_score == 0"]
		},
		{
			"line": 4,
			"format": "{exposure_vendors_products}",
			"omit_if": []
		},
		{
			"line": 5,
			"format": "  ↳ Patch: {patch} | POCs: {poc_count} | Nuclei Template: {template} | HackerOne: {hackerone}",
			"omit_if": []
		}
	]`

	searchCmd = &cobra.Command{
		Use:   "search <query>",
		Short: "search vulnerabilities using the vulnerability search api",
		Long: `Search vulnerabilities using the Vulnerability search API.

By default, results are sorted by latest CVE published date (newest first).
Use --sort-asc or --sort-desc to override this default behavior.

A search returns at most 1000 rows (--offset + --limit); --all fetches every
result, up to 10,000, and ignores --limit.

Global flags:
  --json      Output raw JSON (for piping, disables CLI output)
  --output    Write output to a .json or .csv file (error if file exists)
  --no-color  Disable colored output (colors are auto-disabled for non-terminal output)
  --detailed  Show detailed vulnerability information

To see all available search fields and filters, use: vulnx filters
`,
		Example: `
# Search help
vulnx help search

# Basic search for only KEV vulnerabilities
vulnx search "is_kev:true"

# Search with detailed information
vulnx search --detailed "xss"

# Output as JSON for piping
vulnx search --json "is_kev:true"

# Write output to a file (JSON)
vulnx search --output results.json "is_kev:true"

# Count matches by severity and vendor
vulnx search --term-facets severity,vendor=5 "is_remote:true"

# CVEs affecting one product version
vulnx search --product apache:tomcat --version 8.5.62
`,
		Args: cobra.ArbitraryArgs,
		Run: func(cmd *cobra.Command, args []string) {
			query := strings.Join(args, " ")
			query = strings.TrimSpace(query)

			// Input validation
			if err := validateSearchInputs(); err != nil {
				gologger.Fatal().Msgf("Invalid input: %s", err)
			}

			// Build filter query from flags
			filterQuery, err := buildFilterQuery()
			if err != nil {
				gologger.Fatal().Msgf("Failed to build filter query: %s", err)
			}

			params := vulnx.SearchParams{}

			params.Limit = vulnx.Ptr(searchLimit)
			if searchAll {
				params.All = true
				params.Progress = func(fetched, total int) {
					if !silent && (fetched%1000 == 0 || fetched == total) {
						gologger.Info().Msgf("fetched %d of %d", fetched, total)
					}
				}
			}
			if searchOffset > 0 {
				params.Offset = vulnx.Ptr(searchOffset)
			}

			// Set default sorting to latest CVE published date if no sort options provided
			if searchSortAsc == "" && searchSortDesc == "" {
				params.SortDesc = vulnx.Ptr("cve_created_at")
			} else {
				if searchSortAsc != "" {
					params.SortAsc = vulnx.Ptr(searchSortAsc)
				}
				if searchSortDesc != "" {
					params.SortDesc = vulnx.Ptr(searchSortDesc)
				}
			}
			if len(searchFields) > 0 {
				params.Fields = searchFields
			}
			// --fields narrows the response, which would leave CSV columns empty
			if len(params.Fields) > 0 && isCSVOutput() {
				params.Fields = mergeFields(params.Fields, csvRequiredFields)
			}
			if len(searchTermFacets) > 0 {
				params.TermFacets = searchTermFacets
				for i, facet := range params.TermFacets {
					if strings.Contains(facet, "=") {
						params.TermFacets[i] = strings.ReplaceAll(facet, "=", ":")
					}
				}
			}
			if searchFacetSize > 0 {
				params.FacetSize = vulnx.Ptr(searchFacetSize)
			}

			// Combine user query with filter query
			finalQuery := query
			if filterQuery != "" {
				if finalQuery != "" {
					finalQuery = fmt.Sprintf("(%s) && (%s)", finalQuery, filterQuery)
				} else {
					finalQuery = filterQuery
				}
			}

			// Set final query
			if finalQuery != "" {
				params.Query = vulnx.Ptr(finalQuery)
			}

			// Use the global vulnxClient
			resp, err := vulnxClient.SearchVulnerabilities(context.Background(), params)
			if err != nil {
				if errors.Is(err, vulnx.ErrNotFound) {
					gologger.Fatal().Msgf("No results: %s", err)
				}
				if errors.Is(err, vulnx.ErrTooManyRequests) {
					handleRateLimitError()
				}
				gologger.Fatal().Msgf("Failed to perform search: %s", err)
			}
			if resp.Count == 0 {
				if query != "" {
					gologger.Info().Msgf("No results found for query: %s", query)
				} else {
					gologger.Info().Msgf("No results found")
				}
				return
			}

			// Handle JSON and output file flags
			if jsonOutput || outputFile != "" {
				var data []byte
				if isCSVOutput() {
					vulns := make([]*vulnx.Vulnerability, len(resp.Results))
					for i := range resp.Results {
						vulns[i] = &resp.Results[i]
					}
					data, err = renderVulnsCSV(vulns)
				} else {
					data, err = json.Marshal(resp)
				}
				if err != nil {
					gologger.Fatal().Msgf("Failed to render output: %s", err)
				}
				if outputFile != "" {
					if err := writeNewFile(outputFile, data); err != nil {
						gologger.Fatal().Msgf("%s", err)
					}
					gologger.Info().Msgf("Wrote output to file: %s", outputFile)
					return
				}
				if _, err := os.Stdout.Write(append(data, '\n')); err != nil {
					gologger.Error().Msgf("Failed to write JSON output: %s", err)
				}
				return
			}

			// Default CLI renderer format
			layout, err := renderer.ParseLayout([]byte(defaultLayoutJSON))
			if err != nil {
				gologger.Fatal().Msgf("Failed to parse layout: %s", err)
			}

			// Convert vulnerabilities to entries
			entries := make([]*renderer.Entry, 0, len(resp.Results))
			for _, vuln := range resp.Results {
				entry := renderer.FromVulnerability(&vuln)
				if entry != nil {
					entries = append(entries, entry)
				}
			}

			// Configure colors based on flags and terminal detection
			var colors *renderer.ColorConfig
			if noColor || !renderer.IsTerminal() {
				colors = renderer.NoColorConfig()
			} else {
				colors = renderer.DefaultColorConfig()
			}

			// Render output with colors
			if searchDetailed {
				// Use detailed rendering for each entry (similar to 'id' command)
				for i, entry := range entries {
					// Add separator between multiple results
					if i > 0 {
						separator := strings.Repeat("─", 65)
						if colors != nil {
							fmt.Println(colors.ColorResultSeparator(separator))
						} else {
							fmt.Println(separator)
						}
						fmt.Println()
					}

					// Render detailed output for each entry
					result := renderer.RenderDetailed(entry, colors)
					fmt.Print(result)
				}

				// Show summary at the end
				fmt.Printf("\n")
				summaryLine := fmt.Sprintf("Showing %d out of %d total results", resp.Count, resp.Total)
				if colors != nil {
					fmt.Println(colors.ColorResultSeparator(summaryLine))
				} else {
					fmt.Println(summaryLine)
				}
			} else {
				// Use default layout rendering
				output := renderer.RenderWithColors(entries, layout, resp.Total, resp.Count, colors)
				fmt.Print(output)
			}
		},
	}
)

// buildFilterQuery turns the filter flags into query terms; the query translator validates their values.
func buildFilterQuery() (string, error) {
	var parts []string
	if filterVersion != "" {
		vendor, product, ok := strings.Cut(strings.ToLower(filterProduct), ":")
		if !ok || vendor == "" || product == "" {
			return "", fmt.Errorf("--version needs --product as vendor:product (e.g. --product apache:tomcat --version 8.5.62)")
		}
		parts = append(parts, fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", vendor, product, filterVersion))
	} else if filterProduct != "" {
		parts = append(parts, "product:"+filterProduct)
	}
	if filterCPE != "" {
		if !strings.HasPrefix(strings.ToLower(filterCPE), "cpe:") {
			return "", fmt.Errorf("--cpe takes a CPE string (cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*)")
		}
		parts = append(parts, filterCPE)
	}
	if filterVendor != "" {
		parts = append(parts, "vendor:"+filterVendor)
	}
	if len(filterSeverity) > 0 {
		terms := make([]string, len(filterSeverity))
		for i, s := range filterSeverity {
			terms[i] = "severity:" + strings.TrimSpace(s)
		}
		parts = append(parts, "("+strings.Join(terms, " || ")+")")
	}
	if filterVulnStatus != "" {
		parts = append(parts, "vuln_status:"+filterVulnStatus)
	}
	if filterVulnAge != "" {
		parts = append(parts, "age_in_days:"+strings.TrimSpace(filterVulnAge))
	}
	for _, f := range []struct{ flag, field, value string }{
		{"kev", "is_kev", filterKevOnly},
		{"template", "is_template", filterTemplate},
		{"poc", "is_poc", filterPOC},
		{"remote-exploit", "is_remote", filterRemoteExploit},
	} {
		if f.value == "" {
			continue
		}
		b, err := strconv.ParseBool(f.value)
		if err != nil {
			return "", fmt.Errorf("--%s takes true or false (got %q)", f.flag, f.value)
		}
		parts = append(parts, fmt.Sprintf("%s:%t", f.field, b))
	}
	if filterCvssScore != "" {
		parts = append(parts, "cvss_score:"+strings.TrimSpace(filterCvssScore))
	}
	if filterEpssScore != "" {
		parts = append(parts, "epss_score:"+strings.TrimSpace(filterEpssScore))
	}
	return strings.Join(parts, " && "), nil
}

// validateSearchInputs checks the flags before any request is made.
func validateSearchInputs() error {
	if searchLimit < 1 || searchLimit > vulnx.MaxResultWindow {
		return fmt.Errorf("--limit must be between 1 and %d", vulnx.MaxResultWindow)
	}
	if searchOffset < 0 {
		return fmt.Errorf("--offset must not be negative")
	}
	if !searchAll && searchOffset+searchLimit > vulnx.MaxResultWindow {
		return fmt.Errorf("--offset + --limit can be at most %d; use --all to fetch every result", vulnx.MaxResultWindow)
	}
	if searchSortAsc != "" && searchSortDesc != "" {
		return fmt.Errorf("cannot specify both --sort-asc and --sort-desc")
	}
	if searchFacetSize < 1 || searchFacetSize > maxFacetSize {
		return fmt.Errorf("--facet-size must be between 1 and %d", maxFacetSize)
	}
	if outputFile != "" {
		if ext := strings.ToLower(filepath.Ext(outputFile)); ext != ".json" && ext != ".csv" {
			return fmt.Errorf("output file must have .json or .csv extension")
		}
	}
	return nil
}

// csvRequiredFields are the API fields needed to populate every CSV column.
// Nested objects must be selected by leaf path; the API returns nothing for "h1" alone.
var csvRequiredFields = []string{
	"doc_id", "name", "severity", "cvss_score", "epss_score",
	"is_kev", "is_template", "poc_count", "h1.reports",
	"is_patch_available", "age_in_days", "affected_products.vendor", "affected_products.product", "tags",
}

// mergeFields returns base with any fields from extra that it does not already contain.
func mergeFields(base, extra []string) []string {
	result := slices.Clone(base)
	for _, f := range extra {
		if !slices.Contains(result, f) {
			result = append(result, f)
		}
	}
	return result
}

func init() { // Register flags and add command to rootCmd
	// Existing flags
	searchCmd.Flags().IntVarP(&searchLimit, "limit", "n", 10, "number of results to return (1-1000)")
	searchCmd.Flags().IntVar(&searchOffset, "offset", 0, "offset for pagination (start position)")
	searchCmd.Flags().StringVar(&filterCPE, "cpe", "", "CVEs affecting one product version, by CPE (cpe:2.3:a:apache:tomcat:8.5.62:*:*:*:*:*:*:*)")
	searchCmd.Flags().StringVar(&filterVersion, "version", "", "with --product vendor:product: CVEs affecting that version")
	searchCmd.Flags().BoolVar(&searchAll, "all", false, "fetch every matching result, page by page (at most 10,000; ignores --limit)")
	searchCmd.Flags().StringVar(&searchSortAsc, "sort-asc", "", "field to sort ascending")
	searchCmd.Flags().StringVar(&searchSortDesc, "sort-desc", "", "field to sort descending")
	searchCmd.Flags().StringSliceVar(&searchFields, "fields", nil, "fields to include in the response (comma-separated)")
	searchCmd.Flags().StringSliceVar(&searchTermFacets, "term-facets", nil, "count matches by up to 3 fields, field or field=size (comma-separated)")
	searchCmd.Flags().IntVar(&searchFacetSize, "facet-size", 10, "number of facet buckets to return (1-50)")
	searchCmd.Flags().BoolVar(&searchDetailed, "detailed", false, "show detailed vulnerability information (similar to 'id' command)")

	// Filter flags - String slice filters
	searchCmd.Flags().StringVarP(&filterProduct, "product", "p", "", "filter by one product, as vendor:product or a product name")
	searchCmd.Flags().StringVar(&filterVendor, "vendor", "", "filter by one vendor")
	searchCmd.Flags().StringSliceVarP(&filterSeverity, "severity", "s", nil, "filter by severity (comma-separated: critical,high,medium,low,none)")

	searchCmd.Flags().StringVar(&filterVulnStatus, "vuln-status", "", "filter by NVD status (analyzed, modified, deferred, received, awaiting_analysis, undergoing_analysis; new, confirmed, unconfirmed, unknown still accepted)")
	searchCmd.Flags().StringVarP(&filterVulnAge, "vuln-age", "a", "", "filter by days since publication (e.g. '5', '<10', '>=30')")

	// Boolean filters with default to true when flag is present without value
	searchCmd.Flags().StringVar(&filterKevOnly, "kev", "", "filter CISA KEV (known exploited vulnerabilities) only (true/false); VulnCheck KEV: is_vkev:true")
	searchCmd.Flags().Lookup("kev").NoOptDefVal = "true"

	searchCmd.Flags().StringVarP(&filterTemplate, "template", "t", "", "filter cves with nuclei templates (true/false)")
	searchCmd.Flags().Lookup("template").NoOptDefVal = "true"

	searchCmd.Flags().StringVar(&filterPOC, "poc", "", "filter cves with public pocs (true/false)")
	searchCmd.Flags().Lookup("poc").NoOptDefVal = "true"

	searchCmd.Flags().StringVar(&filterRemoteExploit, "remote-exploit", "", "filter remotely exploitable cves (true/false)")
	searchCmd.Flags().Lookup("remote-exploit").NoOptDefVal = "true"

	searchCmd.Flags().StringVar(&filterCvssScore, "cvss-score", "", "minimum cvss score, as >=N (e.g. '>=7.5')")
	searchCmd.Flags().StringVar(&filterEpssScore, "epss-score", "", "minimum epss score, as >=N (e.g. '>=0.5')")

	searchCmd.SetHelpFunc(searchHelpCmd.Run)
	rootCmd.AddCommand(searchCmd)
}
