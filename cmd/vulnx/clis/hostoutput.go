package clis

// vulnx scan --host's outputs besides the terminal: the JSON result, the SBOM, and --fail-on's exit status.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/projectdiscovery/vulnx/v2"
)

// writeHostJSON writes a host scan as the stack result with the inventory beside it, or as VEX.
func writeHostJSON(inv vulnx.HostInventory, res vulnx.StackResult, vex string) error {
	if vex != "" {
		return writeStackOutput(res, vex, 0)
	}
	data, err := hostJSON(inv, res)
	if err != nil {
		return fmt.Errorf("failed to render output: %w", err)
	}
	return writeData(data)
}

// failOnLevels are --fail-on's values.
var failOnLevels = []string{"kev", "critical", "high"}

// failsOn is whether a host scan has a finding a program can reach at --fail-on's level or worse.
func failsOn(level string, inv vulnx.HostInventory, res vulnx.StackResult) bool {
	for _, f := range findings(inv, res) {
		switch {
		case level == "kev" && f.tier == tierKEV,
			level == "critical" && (f.tier == tierKEV || f.worst == "critical"),
			level == "high" && (f.tier == tierKEV || f.worst == "critical" || f.worst == "high"):
			return true
		}
	}
	return false
}

// hostJSON is a host scan's full result: the stack result with the inventory beside it (sources, where each
// component was found, how each place is updated, what was not assessed or read).
func hostJSON(inv vulnx.HostInventory, res vulnx.StackResult) ([]byte, error) {
	return json.MarshalIndent(struct {
		Host vulnx.HostInventory `json:"host"`
		vulnx.StackResult
	}{inv, res}, "", "  ")
}

// writeHostReportJSON writes the full result as vulnx-host-<date>.json in the working directory, replacing the
// same day's, and returns its absolute path. Every host scan writes it: the terminal shows one screen of it.
func writeHostReportJSON(inv vulnx.HostInventory, res vulnx.StackResult) (string, error) {
	abs, err := filepath.Abs("vulnx-host-" + time.Now().Format("2006-01-02") + ".json")
	if err != nil {
		return "", err
	}
	data, err := hostJSON(inv, res)
	if err != nil {
		return "", err
	}
	return abs, os.WriteFile(abs, data, 0o644)
}

// writeHostSBOM writes the inventory as a CycloneDX SBOM and returns its absolute path. path "auto" (or empty)
// names it vulnx-host-<date>.cdx.json in the working directory, replacing the same day's.
func writeHostSBOM(path string, inv vulnx.HostInventory) (string, error) {
	now := time.Now()
	if path == "" || path == "auto" {
		path = "vulnx-host-" + now.Format("2006-01-02") + ".cdx.json"
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	raw, err := inv.CycloneDX(now)
	if err != nil {
		return "", err
	}
	return abs, os.WriteFile(abs, raw, 0o644)
}

// shareExpiry is how long a shared host report's link works.
const shareExpiry = 24 * time.Hour
