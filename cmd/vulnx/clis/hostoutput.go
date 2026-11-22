package clis

// vulnx scan --host's outputs besides the terminal: the JSON result, the SBOM, and --fail-on's exit status.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/projectdiscovery/vulnx/v2"
)

// writeHostJSON writes a host scan as the stack result with the inventory beside it, or as VEX, or as CSV for -o
// file.csv (the result's rows: the inventory is no table).
func writeHostJSON(inv vulnx.HostInventory, res vulnx.StackResult, vex string) error {
	if vex != "" || outputFile != "" && isCSVOutput() {
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
// same day's, and returns its absolute path. A scan printed to the terminal writes it beside what it shows.
func writeHostReportJSON(inv vulnx.HostInventory, res vulnx.StackResult) (string, error) {
	data, err := hostJSON(inv, res)
	if err != nil {
		return "", err
	}
	return writeDated(".json", data)
}

// writeHostSBOM writes the inventory as a CycloneDX SBOM and returns its absolute path. path "auto" names it
// vulnx-host-<date>.cdx.json in the working directory, replacing the same day's; a path given is never
// overwritten, as with -o.
func writeHostSBOM(path string, inv vulnx.HostInventory) (string, error) {
	raw, err := inv.CycloneDX(time.Now())
	if err != nil {
		return "", err
	}
	if path == "" || path == "auto" {
		return writeDated(".cdx.json", raw)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return abs, writeNewFile(abs, raw)
}

// writeDated writes vulnx-host-<date><suffix> in the working directory, replacing the same day's, and returns its
// absolute path. The data goes to a new file beside it, readable by its owner only (a report holds paths and
// the runtime snapshot), renamed over the old one: a symlink planted at the name is replaced, not followed.
func writeDated(suffix string, data []byte) (string, error) {
	abs, err := filepath.Abs("vulnx-host-" + time.Now().Format("2006-01-02") + suffix)
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp(filepath.Dir(abs), "."+filepath.Base(abs)+".*")
	if err != nil {
		return "", err
	}
	_, err = f.Write(data)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(f.Name(), abs)
	}
	if err != nil {
		return "", errors.Join(err, os.Remove(f.Name()))
	}
	return abs, nil
}

// shareExpiry is how long a shared host report's link works.
const shareExpiry = 24 * time.Hour
