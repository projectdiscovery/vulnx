package main

import (
	"os"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/vulnx/v2"
	"github.com/projectdiscovery/vulnx/v2/cmd/vulnx/clis"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == vulnx.HostRuntimeWorkerArg {
		if err := vulnx.RunHostRuntimeWorker(os.Stdin, os.Stdout); err != nil {
			gologger.Fatal().Msgf("Runtime worker failed: %s", err)
		}
		return
	}
	if err := clis.Execute(); err != nil {
		gologger.Fatal().Msgf("Could not execute CLI: %s", err)
	}
}
