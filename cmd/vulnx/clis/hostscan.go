package clis

// vulnx scan --host: read what is installed, check it, and write what the flags ask for.

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/projectdiscovery/vulnx/v2"
	"github.com/projectdiscovery/vulnx/v2/pkg/tools/renderer"
	"github.com/spf13/pflag"
)

// hostOnlyFlags mean something only with --host: given without it they are an error, not ignored.
var hostOnlyFlags = []string{"view", "sbom", "graph", "report", "fail-on", "root"}

// checkHostFlags rejects a host-only flag without --host, and --host's flags with values it does not take.
func checkHostFlags(flags *pflag.FlagSet, args []string) error {
	if !scanHost {
		for _, name := range hostOnlyFlags {
			if flags.Changed(name) {
				return fmt.Errorf("--%s works only with --host", name)
			}
		}
		return nil
	}
	switch {
	case len(args) > 0 || scanList != "" || scanImage != "":
		return errors.New("--host scans this machine: it takes no file, package versions, --list or --image")
	case !slices.Contains(hostViews, scanView):
		return fmt.Errorf("--view takes %s (got %s)", strings.Join(hostViews, ", "), scanView)
	case scanFailOn != "" && !slices.Contains(failOnLevels, scanFailOn):
		return fmt.Errorf("--fail-on takes %s (got %s)", strings.Join(failOnLevels, ", "), scanFailOn)
	}
	return nil
}

// runHostScan scans this machine, or the Linux filesystem mounted at --root, and writes what the flags ask for.
// failed is whether a reachable finding is at or above --fail-on's level, whatever the output.
func runHostScan(ctx context.Context) (failed bool, err error) {
	root := ""
	if scanRoot != "" {
		if root, err = filepath.Abs(scanRoot); err != nil {
			return false, fmt.Errorf("--root: %w", err)
		}
	}
	if scanReport { // before the scan: a report whose link could not expire is never uploaded
		if err := vulnxClient.StackExpirySupported(ctx); errors.Is(err, vulnx.ErrExpiryUnsupported) {
			return false, errors.New("--report: this SecurityContext API cannot expire a report's link yet, so nothing was scanned or uploaded")
		} else if err != nil {
			return false, fmt.Errorf("--report: %w", err)
		}
	}
	start := time.Now()
	inv, res, err := checkHost(ctx, root)
	hostProgress("")
	if err != nil {
		return false, err
	}
	failed = failsOn(scanFailOn, inv, res)
	if scanVEX != "" || jsonOutput || outputFile != "" {
		return failed, writeHostJSON(inv, res, scanVEX)
	}
	return failed, printHostScan(ctx, inv, res, time.Since(start))
}

// checkHost reads the host and checks what it read: every component's verdict, editor extensions against the
// marketplaces' removals, and which Go programs reach affected code.
func checkHost(ctx context.Context, root string) (vulnx.HostInventory, vulnx.StackResult, error) {
	var res vulnx.StackResult
	hostProgress("Reading what is installed ...")
	inv, err := vulnx.HostEntries(ctx, root)
	if err != nil {
		return inv, res, fmt.Errorf("failed to read the host: %w", err)
	}
	inv.CollectRuntimeIsolated(ctx, root)
	if repos := inv.PendingRepositories(); len(repos) > 0 {
		hostProgress("Looking up products by source repository ...")
		products, _, err := vulnxClient.ProductsByRepository(ctx, repos)
		if err != nil {
			return inv, res, fmt.Errorf("failed to scan: %w", err)
		}
		inv.ResolvePending(products) // an API without the lookup resolves none: they stay not checked
	}
	hostProgress(fmt.Sprintf("Checking %s components ...", formatNumber(len(inv.Entries))))
	res, err = vulnxClient.CheckManyWith(ctx, inv.Entries, vulnx.CheckOptions{Functions: true, Compact: true, Progress: func(done, total int) {
		if done < total {
			hostProgress(fmt.Sprintf("Checking %s components: %s done ...", formatNumber(total), formatNumber(done)))
		}
	}})
	if err != nil {
		return inv, res, fmt.Errorf("failed to scan: %w", err)
	}
	inv.DropUnknownProducts(&res)
	// the full lists first: DropOtherSchemes judges every row a product has, not its 10 most urgent
	if scanFull || scanVEX != "" {
		if err := fillProductCVEs(ctx, &res); err != nil {
			return inv, res, err
		}
	}
	vulnx.DropOtherSchemes(&res)
	if len(inv.Extensions) > 0 {
		hostProgress("Checking editor extensions against marketplace removals ...")
		ext, checked, err := vulnxClient.CheckExtensions(ctx, inv.Extensions)
		if err != nil {
			return inv, res, fmt.Errorf("failed to scan: %w", err)
		}
		inv.AddExtensions(&res, ext, checked)
	}
	hostProgress("Checking which Go programs reach affected code ...")
	inv.MarkReachability(&res)
	inv.RefreshRuntimeMatches(ctx)
	return inv, res, nil
}

// printHostScan prints the chosen view and writes the day's JSON report, then the files --graph, --sbom and
// --report ask for.
func printHostScan(ctx context.Context, inv vulnx.HostInventory, res vulnx.StackResult, elapsed time.Duration) error {
	c := colorConfig()
	fmt.Print(renderHost(scanView, inv, res, elapsed, scanShowAll, c))
	path, err := writeHostReportJSON(inv, res)
	if err != nil {
		return fmt.Errorf("failed to write the report: %w", err)
	}
	fmt.Printf("  JSON: %s\n", path)
	if scanView == "grid" && !scanReport {
		fmt.Println("  " + c.Colorize("Add --report for a shareable link (expires in 24 hours)", renderer.Gray))
	}
	if scanGraph {
		path, err := writeHostGraph(inv, res)
		if err != nil {
			return fmt.Errorf("failed to write the graph: %w", err)
		}
		fmt.Printf("  Graph: %s\n", path)
	}
	if scanSBOM != "" || scanReport {
		path, err := writeHostSBOM(scanSBOM, inv)
		if err != nil {
			return fmt.Errorf("failed to write the SBOM: %w", err)
		}
		fmt.Printf("  SBOM: %s\n", path)
		if scanReport {
			if err := shareHostReport(ctx, path); err != nil {
				return err
			}
		}
	}
	if scanView == "grid" {
		fmt.Print(hostFooter(inv, elapsed, c))
	}
	return nil
}

// shareHostReport uploads the SBOM at path as a stored stack whose link expires, and prints the link.
func shareHostReport(ctx context.Context, path string) error {
	hostProgress("Uploading the SBOM to SecurityContext ...")
	id, expiresAt, err := vulnxClient.ShareFile(ctx, path, shareExpiry)
	if err == nil {
		hostProgress("Waiting for SecurityContext to read it ...")
		_, err = vulnxClient.WaitStackReady(ctx, id)
	}
	hostProgress("")
	if errors.Is(err, vulnx.ErrExpiryUnsupported) {
		return errors.New("--report: this SecurityContext API cannot expire a report's link yet, so nothing was uploaded")
	}
	if err != nil {
		return fmt.Errorf("--report: %w", err)
	}
	if expiresAt == "" {
		fmt.Printf("  Report: %s (the API did not say when it expires: the link may not)\n", vulnxClient.StackPage(id))
		return nil
	}
	fmt.Printf("  Report: %s (expires in 24 hours)\n", vulnxClient.StackPage(id))
	return nil
}
