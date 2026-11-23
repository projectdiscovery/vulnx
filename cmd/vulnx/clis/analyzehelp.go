package clis

import (
	"fmt"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/spf13/cobra"

	"github.com/projectdiscovery/vulnx/v2"
)

// facetOnlyFields describes the facet fields that are not query fields.
var facetOnlyFields = map[string]string{
	"exploit":    "Exploitation signals, one bucket each: known_exploited, vulncheck_known_exploited, public_exploit, nuclei_template, ransomware, initial_access",
	"nvd_status": "NVD's status (same as vuln_status)",
}

var analyzeHelpCmd = &cobra.Command{
	Use:     "help",
	Aliases: []string{"analyze:help", "analyzehelp"},
	Short:   "detailed help for the 'analyze' command with the fields it can count",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(cmd.UsageString())
		desc := map[string]string{}
		for _, f := range vulnx.SupportedFilters() {
			desc[f.Field] = f.Description
		}
		tbl := table.NewWriter()
		tbl.SetStyle(table.StyleRounded)
		tbl.AppendHeader(table.Row{"Field", "Description"})
		tbl.SetColumnConfigs([]table.ColumnConfig{{Name: "Description", WidthMax: 70, WidthMaxEnforcer: text.WrapSoft}})
		for _, f := range vulnx.FacetFields() {
			d := desc[f]
			if d == "" {
				d = facetOnlyFields[f]
			}
			tbl.AppendRow(table.Row{f, d})
		}
		fmt.Println(tbl.Render())
		fmt.Println("At most 3 fields per call; field=size sets a field's bucket count (1-50).")
	},
}
