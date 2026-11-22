package main

import (
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
)

var (
	testAPIKey  = "test-67291d9a-0aa6-49b1-b249-2b9d4b45bcea"
	debug       = os.Getenv("DEBUG") == "true"
	success     = aurora.Green("[✓]").String()
	failed      = aurora.Red("[✘]").String()
	vulnxBinary = flag.String("vulnx", "", "Vulnx Binary")
)

func main() {
	flag.Parse()
	SetupMockServer()
	if err := os.Setenv("VULNX_API_URL", "http://localhost:"+testPort()); err != nil {
		gologger.Fatal().Msgf("Failed to set VULNX_API_URL: %s", err)
	}
	if err := os.Setenv("SECURITYCONTEXT_API_KEY", testAPIKey); err != nil {
		gologger.Fatal().Msgf("Failed to set SECURITYCONTEXT_API_KEY: %s", err)
	}
	if !runIntegrationTests() {
		os.Exit(1)
	}
}

// runIntegrationTests runs every case in name order and reports whether all passed.
func runIntegrationTests() bool {
	fmt.Println("Running Vulnx integration tests...")
	names := make([]string, 0, len(vulnxTestCases))
	for name := range vulnxTestCases {
		names = append(names, name)
	}
	sort.Strings(names)
	ok := true
	for _, name := range names {
		if err := vulnxTestCases[name].Execute(); err != nil {
			fmt.Fprintf(os.Stderr, "%s Vulnx Test %q failed: %s\n", failed, name, err)
			ok = false
			continue
		}
		fmt.Printf("%s Vulnx Test %q passed!\n", success, name)
	}
	return ok
}
