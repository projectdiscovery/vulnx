package clis

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/vulnx/v2"
	"github.com/spf13/cobra"
)

var healthCmd = &cobra.Command{
	Use:     "healthcheck",
	Aliases: []string{"health", "hc"},
	Short:   "check that the SecurityContext API answers",
	// a failed check is not a usage error
	SilenceUsage: true,
	Long: `Check that vulnx can reach the SecurityContext API.

Reports the API URL and whether an API key is set (SECURITYCONTEXT_API_KEY), then
runs a one-row search and reports the response time. Exits non-zero on failure.
`,
	Example: `
vulnx healthcheck
vulnx hc --proxy http://127.0.0.1:8080
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		gologger.Info().Msgf("API: %s", cmp.Or(os.Getenv(vulnx.BaseURLEnvVar), vulnx.DefaultBaseURL))
		if vulnxClient.IsAuthenticated() {
			gologger.Info().Msgf("API key: set (%s)", vulnx.APIKeyEnvVar)
		} else {
			gologger.Info().Msgf("API key: not set; requests are anonymous and rate limited per address (set %s)", vulnx.APIKeyEnvVar)
		}
		start := time.Now()
		resp, err := vulnxClient.SearchVulnerabilities(context.Background(), vulnx.SearchParams{Limit: vulnx.Ptr(1)})
		elapsed := time.Since(start).Round(time.Millisecond)
		switch {
		case errors.Is(err, vulnx.ErrUnauthorized) && vulnxClient.IsAuthenticated():
			return fmt.Errorf("the API answered 401 Unauthorized: check %s, and that the API URL is https (a key is not sent over plain http)", vulnx.APIKeyEnvVar)
		case errors.Is(err, vulnx.ErrUnauthorized):
			return fmt.Errorf("the API answered 401 Unauthorized to an anonymous request: set %s", vulnx.APIKeyEnvVar)
		case err != nil:
			return err
		}
		gologger.Info().Msgf("The API answered in %s (%d CVEs searchable)", elapsed, resp.Total)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(healthCmd)
}
