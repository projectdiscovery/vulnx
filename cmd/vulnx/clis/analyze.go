package clis

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/vulnx/v2"
	"github.com/spf13/cobra"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/projectdiscovery/vulnx/v2/internal/termtext"
	analyzetool "github.com/projectdiscovery/vulnx/v2/pkg/tools/analyze"
)

var (
	// Flag placeholders – defined in init()
	analyzeFields    []string
	analyzeFacetSize int
	analyzeQuery     string

	analyzeCmd = &cobra.Command{
		Use:   "analyze",
		Short: "count vulnerabilities by field values (facets)",
		// main prints the error; the flag list would bury it
		SilenceUsage: true,
		Long: `Count CVEs per value of up to 3 fields (term facets), optionally over the CVEs a query matches.

Examples:
  # CVEs by severity
  vulnx analyze -f severity

  # Known-exploited CVEs by vendor and weakness
  vulnx analyze -f vendor=10,cwe -q 'is_kev:true'

Run 'vulnx analyze help' for the fields that can be counted.

Global flags:
  --json / -j   Output raw JSON
  --output / -o Write output to a .json file (error if file exists)
`,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 || len(args) == 1 && strings.EqualFold(args[0], "help") {
				return nil
			}
			return fmt.Errorf("analyze takes no query argument (got %q); filter with --query, e.g. vulnx analyze -f severity -q 'is_kev:true'", strings.Join(args, " "))
		},
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 1 {
				analyzeHelpCmd.Run(cmd, args)
				return
			}

			// Input validation
			if err := validateAnalyzeInputs(); err != nil {
				gologger.Fatal().Msgf("Invalid input: %s", err)
			}

			params := analyzetool.Params{
				Fields: analyzeFields,
			}
			params.FacetSize = vulnx.Ptr(analyzeFacetSize)
			if analyzeQuery != "" {
				params.Query = vulnx.Ptr(analyzeQuery)
			}

			// Use the global vulnxClient (initialised by rootCmd)
			handler := analyzetool.NewHandler(vulnxClient)
			resp, err := handler.Analyze(params)
			if err != nil {
				if errors.Is(err, vulnx.ErrTooManyRequests) {
					handleRateLimitError()
				}
				gologger.Fatal().Msgf("Failed to perform analysis: %s", err)
			}

			if jsonOutput || outputFile != "" {
				data, err := json.Marshal(resp)
				if err != nil {
					gologger.Fatal().Msgf("Failed to marshal JSON: %s", err)
				}
				if outputFile != "" {
					if err := writeNewFile(outputFile, data); err != nil {
						gologger.Fatal().Msgf("%s", err)
					}
					gologger.Info().Msgf("Wrote output to file: %s", outputFile)
					return
				}
				if _, err := os.Stdout.Write(append(data, '\n')); err != nil {
					gologger.Error().Msgf("Failed to write JSON to stdout: %s", err)
				}
				return
			}
			printFacetTables(resp.Facets, analyzeFields)
		},
	}
)

// printFacetTables prints one table per requested facet (field or field=size), in the order asked.
func printFacetTables(facets map[string]any, fields []string) {
	for _, f := range fields {
		name, _, _ := strings.Cut(strings.ReplaceAll(f, "=", ":"), ":")
		name = strings.TrimSpace(name)
		fmt.Printf("\nField: %s\n", name)
		buckets := extractBuckets(facets, name)
		if len(buckets) == 0 {
			fmt.Printf("No data found for field '%s'\n", name)
			continue
		}
		tbl := table.NewWriter()
		tbl.SetOutputMirror(os.Stdout)
		tbl.SetStyle(table.StyleRounded)
		tbl.AppendHeader(table.Row{"Value", "Count"})
		for _, b := range buckets {
			tbl.AppendRow(table.Row{termtext.Clean(b.key), b.count})
		}
		tbl.Render()
	}
}

// maxFacetSize bounds --facet-size for search and analyze.
const maxFacetSize = analyzetool.MaxFacetSize

// validateAnalyzeInputs checks the flags before any request is made.
func validateAnalyzeInputs() error {
	if len(analyzeFields) == 0 {
		return fmt.Errorf("at least one --fields value is required")
	}
	if analyzeFacetSize < 1 || analyzeFacetSize > maxFacetSize {
		return fmt.Errorf("--facet-size must be between 1 and %d", maxFacetSize)
	}
	if outputFile != "" && !strings.EqualFold(filepath.Ext(outputFile), ".json") {
		return fmt.Errorf("output file must have .json extension")
	}
	return nil
}

func init() {
	analyzeCmd.Flags().StringSliceVarP(&analyzeFields, "fields", "f", nil, "up to 3 fields to count CVEs by, field or field=size (comma-separated)")
	analyzeCmd.Flags().IntVar(&analyzeFacetSize, "facet-size", 10, "number of buckets per field (1-50)")
	analyzeCmd.Flags().StringVarP(&analyzeQuery, "query", "q", "", "count only the CVEs this field:value query matches")
	analyzeCmd.SetHelpFunc(analyzeHelpCmd.Run)

	rootCmd.AddCommand(analyzeCmd)
}
