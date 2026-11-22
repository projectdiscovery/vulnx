package clis

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"
	"github.com/projectdiscovery/vulnx/v2"
	"github.com/spf13/cobra"

	"github.com/projectdiscovery/vulnx/v2/internal/termtext"
	"github.com/projectdiscovery/vulnx/v2/pkg/tools/id"
	"github.com/projectdiscovery/vulnx/v2/pkg/tools/renderer"
)

// maxIDs bounds one id invocation: each id is one request.
const maxIDs = 100

var (
	idFile    string
	idHistory bool

	idCmd = &cobra.Command{
		Use:   "id [CVE-ID...]",
		Short: "get vulnerability details by CVE id",
		Long: `Get CVE details by id. Only CVE records are supported.

Supports multiple input methods:
• Command line arguments: vulnx id CVE-2021-44228 CVE-2023-4966
• Command line (comma-separated): vulnx id CVE-2021-44228,CVE-2023-4966
• File input: vulnx id --file ids.txt
• Stdin input: echo "CVE-2021-44228" | vulnx id

At most 100 ids are fetched per run.

Global flags:
  --json     Output raw JSON (for piping, disables CLI output)
  --output   Write output to a .json or .csv file (error if file exists)
  --no-color Disable colored output (colors are auto-disabled for non-terminal output)
`,
		Example: `
# Get details for a specific vulnerability
vulnx id CVE-2021-44228

# Get details for multiple vulnerabilities
vulnx id CVE-2021-44228 CVE-2023-4966

# Comma-separated IDs
vulnx id CVE-2021-44228,CVE-2023-4966,CVE-2024-3400

# Read IDs from file (one per line or comma-separated; # starts a comment)
vulnx id --file ids.txt

# Read from stdin
echo "CVE-2021-44228" | vulnx id

# Show what changed on the record
vulnx id --history CVE-2024-3400

# Output as JSON for piping
vulnx id --json CVE-2021-44228

# Write output to a file (JSON)
vulnx id --output vuln.json CVE-2021-44228
`,
		Args: cobra.ArbitraryArgs,
		Run: func(cmd *cobra.Command, args []string) {
			vulnIDs := parseIDs(strings.Join(args, "\n"))
			if idFile != "" {
				data, err := os.ReadFile(idFile)
				if err != nil {
					gologger.Fatal().Msgf("Failed to read IDs from file: %s", err)
				}
				vulnIDs = append(vulnIDs, parseIDs(string(data))...)
			}
			if len(vulnIDs) == 0 && fileutil.HasStdin() {
				data, err := io.ReadAll(os.Stdin)
				if err != nil {
					gologger.Fatal().Msgf("Failed to read IDs from stdin: %s", err)
				}
				vulnIDs = parseIDs(string(data))
			}
			if len(vulnIDs) == 0 {
				gologger.Fatal().Msg("No vulnerability IDs provided. Use command line arguments, --file, or pipe IDs via stdin")
			}
			runIDs(vulnIDs)
		},
	}
)

// parseIDs reads ids separated by newlines or commas, skipping blank lines and # comments.
func parseIDs(content string) []string {
	var ids []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, part := range strings.Split(line, ",") {
			if part = strings.TrimSpace(part); part != "" {
				ids = append(ids, part)
			}
		}
	}
	return ids
}

// runIDs fetches and prints each id once, in order; it exits non-zero when none could be fetched.
func runIDs(vulnIDs []string) {
	for i, v := range vulnIDs {
		if vulnx.IsCVEID(v) {
			vulnIDs[i] = strings.ToUpper(v)
		}
	}
	vulnIDs = removeDuplicates(vulnIDs)
	if len(vulnIDs) > maxIDs {
		gologger.Info().Msgf("Processing %d IDs. Limiting to the first %d.", len(vulnIDs), maxIDs)
		vulnIDs = vulnIDs[:maxIDs]
	}
	handler := id.NewHandler(vulnxClient)

	if jsonOutput || outputFile != "" {
		var vulns []*vulnx.Vulnerability
		for _, vulnID := range vulnIDs {
			if vuln := fetchVuln(handler, vulnID); vuln != nil {
				attachHistory(vuln)
				vulns = append(vulns, vuln)
			}
		}
		if len(vulns) == 0 {
			gologger.Fatal().Msg(noVulnsMessage(vulnIDs))
		}
		writeVulnsOutput(vulns, len(vulnIDs) == 1)
		return
	}

	colors := renderer.DefaultColorConfig()
	if noColor || !renderer.IsTerminal() {
		colors = renderer.NoColorConfig()
	}
	printed := 0
	for _, vulnID := range vulnIDs {
		vuln := fetchVuln(handler, vulnID)
		if vuln == nil {
			continue
		}
		if printed > 0 {
			fmt.Println(colors.ColorResultSeparator(strings.Repeat("─", 65)))
			fmt.Println()
		}
		fmt.Println(renderer.RenderDetailed(renderer.FromVulnerability(vuln), colors))
		if idHistory {
			attachHistory(vuln)
			fmt.Println(renderHistory(vuln.History))
		}
		printed++
	}
	switch {
	case printed == 0:
		gologger.Fatal().Msg(noVulnsMessage(vulnIDs))
	case printed < len(vulnIDs):
		gologger.Info().Msgf("Retrieved %d of %d vulnerabilities", printed, len(vulnIDs))
	}
}

// fetchVuln fetches one id, logging why it could not be; a rate limit ends the run.
func fetchVuln(h *id.Handler, vulnID string) *vulnx.Vulnerability {
	vuln, err := h.Get(vulnID)
	switch {
	case err == nil:
		return vuln
	case !vulnx.IsCVEID(vulnID):
		gologger.Error().Msg(notCVEMessage(vulnID))
	case errors.Is(err, vulnx.ErrNotFound):
		gologger.Error().Msgf("Vulnerability not found: %s", vulnID)
	case errors.Is(err, vulnx.ErrTooManyRequests):
		handleRateLimitError()
	default:
		gologger.Error().Msgf("Failed to fetch vulnerability %s: %s", vulnID, err)
	}
	return nil
}

func notCVEMessage(id string) string {
	return fmt.Sprintf("%s is not a CVE id; only CVE records are supported", id)
}

// noVulnsMessage says nothing was retrieved, repeating why for ids that are not CVE ids (the per-id error is
// hidden by --silent).
func noVulnsMessage(ids []string) string {
	msg := "No vulnerabilities were retrieved"
	for _, id := range ids {
		if !vulnx.IsCVEID(id) {
			msg += "; " + notCVEMessage(id)
		}
	}
	return msg
}

// attachHistory adds the CVE's recorded changes when --history is set.
func attachHistory(v *vulnx.Vulnerability) {
	if !idHistory {
		return
	}
	h, err := vulnxClient.GetCVEHistory(context.Background(), v.CVEID)
	if err != nil {
		gologger.Error().Msgf("history for %s: %s", v.CVEID, err)
		return
	}
	v.History = h
}

// renderHistory prints a CVE's recorded changes, newest first.
func renderHistory(h []vulnx.ChangeEntry) string {
	var b strings.Builder
	b.WriteString("Changes 🕒\n")
	if len(h) == 0 {
		b.WriteString("  ↳ none recorded\n")
		return b.String()
	}
	val := func(v any) string {
		if v == nil {
			return "∅"
		}
		s := []rune(termtext.Clean(fmt.Sprint(v)))
		if len(s) > 60 {
			return string(s[:57]) + "..."
		}
		return string(s)
	}
	for i := len(h) - 1; i >= 0; i-- {
		c := h[i]
		src := ""
		if c.Source != "" {
			src = " (" + termtext.Clean(c.Source) + ")"
		}
		fmt.Fprintf(&b, "  ↳ %s  %s: %s → %s%s\n", termtext.Clean(c.ChangedDate), termtext.Clean(c.Field), val(c.OldValue), val(c.NewValue), src)
	}
	return b.String()
}

// removeDuplicates removes duplicate strings, keeping the first of each in order.
func removeDuplicates(ids []string) []string {
	seen := make(map[string]bool, len(ids))
	var result []string
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			result = append(result, id)
		}
	}
	return result
}

func init() {
	idCmd.Flags().StringVar(&idFile, "file", "", "read vulnerability ids from file (one per line or comma-separated)")
	idCmd.Flags().BoolVar(&idHistory, "history", false, "show what changed on each CVE record")
	rootCmd.AddCommand(idCmd)
}
