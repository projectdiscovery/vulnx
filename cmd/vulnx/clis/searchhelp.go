package clis

import (
	"fmt"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"

	"github.com/projectdiscovery/vulnx/v2"
)

var (
	searchHelpCmd = &cobra.Command{
		Use:     "help",
		Aliases: []string{"search:help", "searchhelp"},
		Short:   "detailed help for the 'search' command with available filters",
		Run: func(cmd *cobra.Command, args []string) {
			// Print command usage & flags (default Cobra output) before field table
			fmt.Println(cmd.UsageString())

			fltrs := vulnx.SupportedFilters()

			tbl := table.NewWriter()
			tbl.SetStyle(table.StyleRounded)
			tbl.AppendHeader(table.Row{"Field", "Data Type", "Description", "Sortable", "Facet"})
			tbl.SetColumnConfigs([]table.ColumnConfig{
				{Name: "Description", WidthMax: 60},
			})
			for _, f := range fltrs {
				tbl.AppendRow(table.Row{
					f.Field,
					f.DataType,
					f.Description,
					boolToYN(f.CanSort),
					boolToYN(f.FacetPossible),
				})
			}
			fmt.Println(tbl.Render())
		},
	}
)

func boolToYN(b bool) string {
	if b {
		return "Y"
	}
	return "-"
}
