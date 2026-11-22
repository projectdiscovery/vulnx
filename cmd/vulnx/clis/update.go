package clis

import (
	"github.com/projectdiscovery/gologger"
	updateutils "github.com/projectdiscovery/utils/update"
	"github.com/spf13/cobra"
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "update vulnx to latest version",
	Run: func(cmd *cobra.Command, args []string) {
		gologger.Info().Msg("Checking for vulnx updates...")
		updateutils.GetUpdateToolCallback("vulnx", Version)()
	},
}

func init() {
	rootCmd.AddCommand(updateCmd)
}
