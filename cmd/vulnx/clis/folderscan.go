package clis

// vulnx scan <folder>: read a directory's lockfiles, SBOMs, installed packages and programs here, check their
// names and versions as --host does, and write what the flags ask for.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/vulnx/v2"
	"github.com/projectdiscovery/vulnx/v2/internal/termtext"
	"github.com/projectdiscovery/vulnx/v2/pkg/tools/renderer"
)

// folderArg is the scan's folder: its one argument, when that names a directory.
func folderArg(args []string) (string, bool) {
	if len(args) != 1 || scanList != "" || scanImage != "" || scanHost {
		return "", false
	}
	st, err := os.Stat(args[0])
	return args[0], err == nil && st.IsDir()
}

// runFolderScan scans a folder and writes what the flags ask for. failed is whether a finding a program can
// reach is at or above --fail-on's level.
func runFolderScan(ctx context.Context, dir string, show int) (failed bool, err error) {
	if scanReport {
		if err := vulnxClient.StackExpirySupported(ctx); errors.Is(err, vulnx.ErrExpiryUnsupported) {
			return false, errors.New("--report: this SecurityContext API cannot expire a report's link yet, so nothing was scanned or uploaded")
		} else if err != nil {
			return false, fmt.Errorf("--report: %w", err)
		}
	}
	start := time.Now()
	hostProgress("Reading " + dir + " ...")
	inv, err := vulnx.FolderEntries(ctx, dir)
	if err != nil {
		hostProgress("")
		return false, fmt.Errorf("failed to read %s: %w", dir, err)
	}
	res, err := checkInventory(ctx, inv)
	hostProgress("")
	if err != nil {
		return false, err
	}
	failed = failsOn(scanFailOn, inv, res)
	if scanVEX != "" || jsonOutput || outputFile != "" {
		if scanSBOM != "" && scanSBOM != "auto" {
			if _, err := writeHostSBOM(scanSBOM, inv); err != nil {
				return failed, fmt.Errorf("failed to write the SBOM: %w", err)
			}
		}
		if scanVEX != "" || outputFile != "" && isCSVOutput() {
			return failed, writeStackOutput(res, scanVEX, 0)
		}
		data, err := folderJSON(inv, res)
		if err != nil {
			return failed, fmt.Errorf("failed to render output: %w", err)
		}
		return failed, writeData(data)
	}
	c := colorConfig()
	out := &stdoutText{}
	out.print(renderFolder(inv, res, scanSource{input: dir, start: start}, show, c))
	if scanSBOM != "" || scanReport {
		path, cleanup, err := folderSBOM(inv)
		if err != nil {
			return failed, fmt.Errorf("failed to write the SBOM: %w", err)
		}
		defer cleanup()
		if scanSBOM != "" {
			out.print(hostLabel("SBOM") + path + "\n")
		}
		if scanReport {
			if err := shareHostReport(ctx, path, out); err != nil {
				return failed, err
			}
		}
	}
	return failed, out.err
}

// checkInventory checks what a folder holds as --host checks a machine: a part at a time, with each Go advisory's
// affected functions, then the full CVE lists --full and --vex ask for and which programs reach affected code.
func checkInventory(ctx context.Context, inv vulnx.HostInventory) (vulnx.StackResult, error) {
	hostProgress(fmt.Sprintf("Checking %s packages ...", formatNumber(len(inv.Entries))))
	res, err := vulnxClient.CheckManyWith(ctx, inv.Entries, vulnx.CheckOptions{Functions: true, Compact: true, Progress: func(done, total int) {
		if done < total {
			hostProgress(fmt.Sprintf("Checking %s packages: %s done ...", formatNumber(total), formatNumber(done)))
		}
	}})
	if err != nil {
		return res, fmt.Errorf("failed to scan: %w", err)
	}
	inv.DropUnknownProducts(&res)
	if scanFull || scanVEX != "" {
		if err := fillProductCVEs(ctx, &res); err != nil {
			return res, err
		}
	}
	vulnx.DropOtherSchemes(&res)
	hostProgress("Checking which Go programs reach affected code ...")
	inv.MarkReachability(&res)
	return res, nil
}

// folderSBOM writes the folder's SBOM where --sbom names it (vulnx-folder-<date>.cdx.json for a bare --sbom), or,
// for --report alone, to a temporary file that cleanup removes.
func folderSBOM(inv vulnx.HostInventory) (path string, cleanup func(), err error) {
	cleanup = func() {}
	switch scanSBOM {
	case "":
		raw, err := inv.CycloneDX(time.Now())
		if err != nil {
			return "", cleanup, err
		}
		f, err := os.CreateTemp("", "vulnx-folder-*.cdx.json")
		if err != nil {
			return "", cleanup, err
		}
		_, err = f.Write(raw)
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
		cleanup = func() {
			if err := os.Remove(f.Name()); err != nil {
				gologger.Info().Msgf("could not remove the temporary SBOM %s: %v", f.Name(), err)
			}
		}
		if err != nil {
			cleanup()
			return "", func() {}, err
		}
		return f.Name(), cleanup, nil
	case "auto":
		raw, err := inv.CycloneDX(time.Now())
		if err != nil {
			return "", cleanup, err
		}
		path, err := writeDatedAs("vulnx-folder-", ".cdx.json", raw)
		return path, cleanup, err
	}
	path, err = writeHostSBOM(scanSBOM, inv)
	return path, cleanup, err
}

// folderJSON is a folder scan as the stack result with what the folder holds beside it.
func folderJSON(inv vulnx.HostInventory, res vulnx.StackResult) ([]byte, error) {
	return json.MarshalIndent(struct {
		Folder vulnx.HostInventory `json:"folder"`
		vulnx.StackResult
	}{inv, res}, "", "  ")
}

// renderFolder is a folder scan's text output: the host grid with a row per source (a lockfile by its path,
// installed packages by kind, Go and Rust programs), what was not checked or not counted and what was scanned,
// then each package with its CVEs.
func renderFolder(inv vulnx.HostInventory, res vulnx.StackResult, from scanSource, show int, c *renderer.ColorConfig) string {
	var b strings.Builder
	dim := func(t string) string { return c.Colorize(t, renderer.Gray) }
	rows, total, n := hostGrid(inv, res)
	fmt.Fprintf(&b, "\n  %s affected   %s reachable   %s known exploited   %s public exploit\n\n",
		c.Colorize(formatNumber(n.Affected), renderer.Bold), c.Colorize(formatNumber(n.Reachable), renderer.Bold),
		c.Colorize(formatNumber(n.Exploited), renderer.Bold+renderer.BrightRed), c.Colorize(formatNumber(n.PublicExploit), renderer.Bold))
	if len(rows) > 0 {
		renderGrid(&b, "SOURCE", rows, total, c)
		b.WriteString("\n")
	}
	if len(inv.NotAssessed) > 0 {
		b.WriteString(dim(hostLabel("Not checked")+fmt.Sprintf("%s git, local or unpinned dependencies: %s",
			formatNumber(len(inv.NotAssessed)), notCheckedSources(inv))) + "\n")
	}
	if n.NotLinked > 0 {
		b.WriteString(dim(hostLabel("Not counted")+notLinkedText(n.NotLinked)) + "\n")
	}
	if res.FunctionsUnavailable {
		b.WriteString(dim(hostLabel("Not checked")+"Go reachability: the API does not serve affected functions yet") + "\n")
	}
	for _, why := range inv.NotRead {
		if why != vulnx.FolderNotRead {
			b.WriteString(dim(hostLabel("Not read")+termtext.Clean(why)) + "\n")
		}
	}
	scanned := []string{termtext.Clean(from.input), plural(len(inv.Entries), "package", "packages")}
	if !from.start.IsZero() {
		scanned = append(scanned, time.Since(from.start).Round(time.Second).String())
	}
	b.WriteString(dim(hostLabel("Scanned")+strings.Join(scanned, " · ")) + "\n")
	// a folder holds hundreds of packages: the list names what needs looking at, the rest with --show-all
	listed, quiet := res, 0
	listed.Items = nil
	for _, it := range res.Items {
		if v := verdict(it); !scanShowAll && v != "affected" && v != "undetermined" {
			quiet++
			continue
		}
		it.Input = purlDisplay(it.Input)
		listed.Items = append(listed.Items, it)
	}
	if list := renderStackList(listed, show); list != "" {
		b.WriteString("\n" + list)
	}
	if quiet > 0 {
		b.WriteString(dim(fmt.Sprintf("\n  %s clean or not in the index, not listed (--show-all lists them)", plural(quiet, "package", "packages"))) + "\n")
	}
	b.WriteString(undeterminedLines(res))
	return b.String()
}

// purlDisplay shows a package purl as ecosystem/name@version (pkg:npm/%40babel/core@7.22.0 -> npm/@babel/core@7.22.0);
// an OS package's purl is left for the list's own short form, and anything else is shown as it is.
func purlDisplay(in string) string {
	body, ok := strings.CutPrefix(in, "pkg:")
	if !ok || strings.HasPrefix(body, "deb/") || strings.HasPrefix(body, "rpm/") || strings.HasPrefix(body, "apk/") {
		return in
	}
	body, _, _ = strings.Cut(body, "?")
	if unesc, err := url.PathUnescape(body); err == nil {
		body = unesc
	}
	return body
}
