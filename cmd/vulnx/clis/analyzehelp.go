package clis

import (
	"fmt"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"

	"github.com/projectdiscovery/vulnx/v2"
)

var (
	analyzeHelpCmd = &cobra.Command{
		Use:     "help",
		Aliases: []string{"analyze:help", "analyzehelp"},
		Short:   "detailed help for the 'analyze' command with facet-capable fields",
		Run: func(cmd *cobra.Command, args []string) {

			// Print command usage & flags (default Cobra output) before examples
			fmt.Println(cmd.UsageString())

			fltrs := vulnx.SupportedFilters()

			// Render table with only facet-capable fields
			tbl := table.NewWriter()
			tbl.SetStyle(table.StyleRounded)
			tbl.AppendHeader(table.Row{"Field", "Data Type", "Description", "Facet"})
			tbl.SetColumnConfigs([]table.ColumnConfig{
				{Name: "Description", WidthMax: 60},
			})
			for _, f := range fltrs {
				if !f.FacetPossible {
					continue
				}
				tbl.AppendRow(table.Row{
					f.Field,
					f.DataType,
					f.Description,
					boolToYN(f.FacetPossible),
				})
			}
			tbl.Render()
		},
	}
)
