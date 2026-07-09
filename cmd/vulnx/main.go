package main

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/vulnx/v2/cmd/vulnx/clis"
)

func main() {
	if err := clis.Execute(); err != nil {
		gologger.Fatal().Msgf("Could not execute CLI: %s", err)
	}
}
