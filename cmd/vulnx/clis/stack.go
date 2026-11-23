package clis

// vulnx scan: scan a lockfile, SBOM, Compose file or Dockerfile, a list of package versions, an image or this
// machine (hostscan.go), on SecurityContext's /v1/stack.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"
	"github.com/projectdiscovery/vulnx/v2"
	"github.com/projectdiscovery/vulnx/v2/internal/termtext"
	"github.com/projectdiscovery/vulnx/v2/pkg/tools/renderer"
	"github.com/spf13/cobra"
)

var (
	scanList     string
	scanFull     bool
	scanShow     int
	scanVEX      string
	scanAuthor   string
	scanWait     time.Duration
	scanShowAll  bool
	scanView     string
	scanSBOM     string
	scanReport   bool
	scanGraph    bool
	scanFailOn   string
	scanImage    string
	scanPlat     string
	scanHost     bool
	scanImages   bool
	scanNoIgnore bool
	scanRoot     string

	scanCmd = &cobra.Command{
		Use:   "scan <file> | scan <folder> | scan <package@version>... | scan --image <ref> | scan --host",
		Short: "scan a dependency file, a folder or a list of package versions",
		Long: `Scan with SecurityContext and list each package as affected, clean, undetermined or unseen.

A file is recognised by name: package-lock.json, yarn.lock, pnpm-lock.yaml, bun.lock, uv.lock, poetry.lock,
Cargo.lock, go.mod, Gemfile.lock, composer.lock, packages.lock.json, gradle.lockfile, compose.yaml /
docker-compose.yml (each service's image is pulled and scanned), or a Dockerfile (its base image and the packages
its RUN lines install). The file is uploaded to SecurityContext and scanned there. A CycloneDX or SPDX JSON SBOM is
read here instead and its components checked as a list.

Or a folder: its lockfiles and manifests (package-lock.json, npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml,
requirements*.txt, Pipfile.lock, poetry.lock, uv.lock, go.mod, Cargo.lock, Gemfile.lock, composer.lock) and JSON
SBOMs are read here, with the packages installed in it (node_modules, site-packages, gem specifications), its Go
and Rust programs and the MCP servers its own configuration starts. Only names and versions are sent; no file is
uploaded and paths stay on this machine. What git ignores there, and repositories nested in it, are skipped
(--no-ignore reads them). A git, local or unpinned dependency is listed as not checked. The
images its Dockerfiles and Compose files name are listed; --images has SecurityContext pull and scan them.

Or give package versions directly (arguments, --list file, or stdin), checked in one request:
  ecosystem/name@version          npm/lodash@4.17.20, pypi/django@3.2.0, maven/org.apache.logging.log4j:log4j-core@2.14.1
  pkg:…                           a package URL, e.g. pkg:deb/debian/openssl@3.0.11-1~deb12u2?distro=debian-12
  vendor:product@version or cpe:  an NVD product version, e.g. apache:tomcat@8.5.62

Or an operating system:
  --image ghcr.io/owner/name:tag  a public container image, pulled and read by SecurityContext
  --host                          this machine, or with --root a mounted Linux filesystem: OS packages, Python,
                                  npm and Ruby packages, Go and Rust binaries, on macOS Homebrew formulae and
                                  applications, and AI tools (assistant apps, agent CLIs, editor extensions, MCP
                                  servers). The names and versions of what it finds, editor extensions and MCP
                                  server packages included, are sent to SecurityContext; paths, configuration and
                                  the runtime snapshot of listening sockets stay on this machine. The terminal
                                  shows one screen; the full result is written as vulnx-host-<date>.json and
                                  what was checked as the CycloneDX SBOM vulnx-host-<date>.cdx.json (no runtime
                                  data). --json, -o and --vex write the result instead of both.

--vex writes a VEX document instead of the result: one statement per (package, CVE); affected rows are
"affected" / "exploitable" with the fixed version when known, undetermined rows "under_investigation" / "in_triage".`,
		Example: `
vulnx scan package-lock.json
vulnx scan .
vulnx scan ~/src/app --fail-on high --sbom
vulnx scan ~/src/app --images
vulnx scan sbom.cdx.json --vex openvex -o sbom.vex.json
vulnx scan compose.yaml --json
vulnx scan npm/lodash@4.17.20 pypi/django@3.2.0
vulnx scan apache:tomcat@8.5.62 --full
vulnx scan --image debian:12-slim
vulnx scan --image ghcr.io/projectdiscovery/nuclei:latest --platform linux/arm64
vulnx scan --host
vulnx scan --host --root /mnt/image-rootfs
vulnx scan --list versions.txt --vex cyclonedx -o versions.vex.json
cat versions.txt | vulnx scan`,
		Args: cobra.ArbitraryArgs,
		Run: func(cmd *cobra.Command, args []string) {
			if err := checkHostFlags(cmd.Flags(), args); err != nil {
				gologger.Fatal().Msgf("%s", err)
			}
			if scanVEX != "" && scanVEX != "openvex" && scanVEX != "cyclonedx" {
				gologger.Fatal().Msgf("--vex takes openvex or cyclonedx (got %s)", scanVEX)
			}
			if err := checkScanOutput(); err != nil {
				gologger.Fatal().Msgf("%s", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), scanWait)
			if dir, ok := folderArg(args); ok {
				failed, err := runFolderScan(ctx, dir, textShow(cmd.Flags().Changed("show")))
				cancel()
				if err != nil {
					fatalScan(err)
				}
				if failed {
					os.Exit(2)
				}
				return
			}
			if scanHost {
				failed, err := runHostScan(ctx)
				cancel()
				if err != nil {
					fatalScan(err)
				}
				if failed {
					os.Exit(2)
				}
				return
			}
			err := runStackScan(ctx, args, textShow(cmd.Flags().Changed("show")))
			cancel()
			if err != nil {
				fatalScan(err)
			}
		},
	}
)

// checkScanOutput refuses an -o file whose extension names no format a scan writes: .json, or .csv for the result
// as a table (a VEX document is JSON).
func checkScanOutput() error {
	if outputFile == "" {
		return nil
	}
	switch ext := strings.ToLower(filepath.Ext(outputFile)); {
	case ext == ".csv" && scanVEX != "":
		return errors.New("--vex writes JSON: give -o a .json file")
	case ext != ".json" && ext != ".csv":
		return errors.New("-o takes a .json or .csv file")
	}
	return nil
}

// runStackScan scans an image, a file or package versions and writes the result.
// textShow is how many CVEs per package the text output lists (0: all): --show, all with --show-all, and all
// with --full unless --show was given, since --full fetched them to be read.
func textShow(showSet bool) int {
	if scanShowAll || scanFull && !showSet {
		return 0
	}
	return scanShow
}

// scanSource is what a scan read and when it started, for the grid's Scanned line.
type scanSource struct {
	input string
	start time.Time
}

// scanFrom is the running scan's source.
var scanFrom scanSource

func runStackScan(ctx context.Context, args []string, show int) error {
	scanFrom = scanSource{input: "the package list", start: time.Now()}
	switch {
	case scanImage != "":
		scanFrom.input = scanImage
	case scanList != "":
		scanFrom.input = scanList
	case len(args) == 1 && fileutil.FileExists(args[0]):
		scanFrom.input = args[0]
	}
	// an image by registry reference: pulled and scanned by SecurityContext
	if scanImage != "" {
		id, err := vulnxClient.ScanImage(ctx, scanImage, scanPlat)
		if err != nil {
			return fmt.Errorf("failed to scan: %w", err)
		}
		gologger.Info().Msgf("Scanning image %s (stack %s); pulling can take minutes", scanImage, id)
		return waitAndWrite(ctx, id, show)
	}
	// package versions rather than a file: arguments that are not a file, --list, or stdin
	if len(args) != 1 || !fileutil.FileExists(args[0]) || scanList != "" {
		if len(args) == 1 && scanList == "" && !looksLikeEntry(args[0]) {
			return fmt.Errorf("no such file: %s (a package version is ecosystem/name@version, a pkg: purl or a cpe:)", args[0])
		}
		entries, err := scanEntries(args, os.Stdin)
		if err != nil {
			return err
		}
		res, err := vulnxClient.CheckMany(ctx, entries)
		if err != nil {
			return fmt.Errorf("failed to scan: %w", err)
		}
		return writeChecked(ctx, res, show)
	}
	// a JSON SBOM is read here and checked as a list (one request, answered at once)
	if raw, err := vulnx.ReadUpload(args[0]); err == nil {
		if entries, format, ok := vulnx.SBOMEntries(raw); ok {
			if len(entries) == 0 {
				return fmt.Errorf("%s is a %s SBOM with no component that has a purl or CPE", args[0], format)
			}
			gologger.Info().Msgf("Checking %d components of %s (%s SBOM)", len(entries), args[0], format)
			res, err := vulnxClient.CheckMany(ctx, entries)
			if err != nil {
				return fmt.Errorf("failed to scan: %w", err)
			}
			return writeChecked(ctx, res, show)
		}
	}
	id, err := vulnxClient.ScanFile(ctx, args[0])
	if err != nil {
		return fmt.Errorf("failed to scan: %w", err)
	}
	gologger.Info().Msgf("Uploaded %s (stack %s); waiting for the scan", args[0], id)
	return waitAndWrite(ctx, id, show)
}

// looksLikeEntry is whether a lone argument that is not a file can be a package version: a name with a
// version, a purl, a CPE or a comma list, or - for stdin. Anything else is taken as a mistyped file name, not sent.
func looksLikeEntry(arg string) bool {
	return arg == "-" || strings.Contains(arg, "@") || strings.Contains(arg, ",") || strings.HasPrefix(arg, "pkg:") || strings.HasPrefix(arg, "cpe:")
}

// waitAndWrite follows a queued stack until it is read and writes its result.
func waitAndWrite(ctx context.Context, id string, show int) error {
	last := ""
	res, err := vulnxClient.WaitStack(ctx, id, func(status string) {
		if status != last && status != "ready" {
			gologger.Info().Msgf("scan %s", termtext.Clean(status))
			last = status
		}
	})
	if err != nil {
		return fmt.Errorf("failed to scan: %w", err)
	}
	return writeChecked(ctx, res, show)
}

// writeChecked writes a result, with every CVE of each product version first when --full or --vex asks.
func writeChecked(ctx context.Context, res vulnx.StackResult, show int) error {
	if scanFull || scanVEX != "" {
		if err := fillProductCVEs(ctx, &res); err != nil {
			return err
		}
	}
	return writeStackOutput(res, scanVEX, show)
}

// fatalScan ends a scan that failed; a rate limit says when to retry.
func fatalScan(err error) {
	if errors.Is(err, vulnx.ErrTooManyRequests) {
		handleRateLimitError()
	}
	gologger.Fatal().Msgf("%s", err)
}

// scanEntries collects package versions from arguments (comma lists too), --list and stdin; "-" as an argument
// or as --list's file is stdin.
func scanEntries(args []string, stdin io.Reader) ([]string, error) {
	var entries []string
	fromStdin := scanList == "-"
	for _, a := range args {
		if a == "-" {
			fromStdin = true
			continue
		}
		for _, e := range strings.Split(a, ",") {
			if e = strings.TrimSpace(e); e != "" {
				entries = append(entries, e)
			}
		}
	}
	if scanList != "" && scanList != "-" {
		f, err := os.Open(scanList)
		if err != nil {
			return nil, err
		}
		fromFile, err := readEntries(f)
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", scanList, err)
		}
		entries = append(entries, fromFile...)
	}
	if fromStdin || len(entries) == 0 && fileutil.HasStdin() {
		fromStdin, err := readEntries(stdin)
		if err != nil {
			return nil, fmt.Errorf("failed to read stdin: %w", err)
		}
		entries = append(entries, fromStdin...)
	}
	if len(entries) == 0 {
		return nil, errors.New("nothing to scan: give a file, package versions as arguments, --list, or stdin")
	}
	return removeDuplicates(entries), nil
}

// readEntries reads package versions one per line or comma-separated; a line starting with # is a comment.
func readEntries(r io.Reader) ([]string, error) {
	var out []string
	for e, err := range fileutil.LinesReader(r, fileutil.WithComment("#"), fileutil.WithSplit(','), fileutil.WithTrimSpace(), fileutil.WithSkipEmpty()) {
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// fillProductCVEs replaces a product item's top rows with its full CVE list (a stack item carries the 10 most
// urgent; /v1/products/.../versions/... pages through all of them). A failure is returned rather than leaving the
// item's top rows, since --full and VEX output promise every CVE.
func fillProductCVEs(ctx context.Context, res *vulnx.StackResult) error {
	for i := range res.Items {
		it := &res.Items[i]
		key, isProduct := strings.CutPrefix(it.Package, "cpe/")
		if !isProduct || it.Version == "" || it.AdvisoryRowsTotal <= len(it.AdvisoryRows) {
			continue
		}
		vendor, product, ok := strings.Cut(key, ":")
		if !ok {
			continue
		}
		rows, err := vulnxClient.ProductVersionCVEs(ctx, vendor, product, it.Version)
		if err != nil {
			return fmt.Errorf("failed to fetch the full CVE list of %s %s: %w", key, it.Version, err)
		}
		it.AdvisoryRows = rows
	}
	return nil
}

// writeStackOutput prints or writes a stack result: JSON (--json / -o file.json), a VEX document (--vex), or text.
// show caps the CVEs listed per package in text output (0: all).
func writeStackOutput(res vulnx.StackResult, vex string, show int) error {
	var data []byte
	var err error
	switch {
	case vex == "openvex":
		data, err = vulnx.OpenVEX(res, scanAuthor, time.Now())
	case vex == "cyclonedx":
		data, err = vulnx.CycloneDXVEX(res, time.Now())
	case outputFile != "" && isCSVOutput():
		data, err = renderer.RenderStackCSV(res)
	case jsonOutput || outputFile != "":
		data, err = json.MarshalIndent(res, "", "  ")
	default:
		out := &stdoutText{}
		out.print(renderStackText(res, show, scanFrom))
		return out.err
	}
	if err != nil {
		return fmt.Errorf("failed to render output: %w", err)
	}
	return writeData(data)
}

// writeData writes a rendered document to -o's file, which must not exist yet, or to stdout.
func writeData(data []byte) error {
	if outputFile == "" {
		out := &stdoutText{}
		out.print(string(data) + "\n")
		return out.err
	}
	if err := writeNewFile(outputFile, data); err != nil {
		return err
	}
	gologger.Info().Msgf("Wrote %s", outputFile)
	return nil
}

// shortOSPackageName shows an OS package purl as name@version
// (pkg:deb/debian/openssl@3.0.11-1~deb12u2?distro=debian-12 -> openssl@3.0.11-1~deb12u2).
func shortOSPackageName(in string) string {
	if !strings.HasPrefix(in, "pkg:deb/") && !strings.HasPrefix(in, "pkg:rpm/") && !strings.HasPrefix(in, "pkg:apk/") {
		return in
	}
	body, _, _ := strings.Cut(in, "?")
	path, version, ok := strings.Cut(body, "@")
	if !ok {
		return in
	}
	if unesc, err := url.PathUnescape(version); err == nil {
		version = unesc
	}
	return path[strings.LastIndex(path, "/")+1:] + "@" + version
}

// verdict is an item's status as shown: unseen for a package the index has no record of, which the API answers
// clean.
func verdict(it vulnx.StackItem) string {
	if it.Unseen() {
		return "unseen"
	}
	return it.Status
}

// stackGridMin is the fewest packages a scan's text output opens with a severity grid for; fewer get the one-line
// summary only.
const stackGridMin = 6

// stackEcosystem names the grid row of a scan's item: an OS package by its distribution and release ("alpine
// 3.18"), a product version as a product, anything else by its ecosystem ("npm").
func stackEcosystem(it vulnx.StackItem) string {
	if it.Distro != "" {
		return strings.TrimSpace(it.Distro + " " + it.Release)
	}
	name := it.Package
	if name == "" {
		name = strings.TrimPrefix(it.Input, "pkg:")
	}
	if strings.HasPrefix(name, "cpe/") || strings.HasPrefix(name, "cpe:") {
		return "products"
	}
	if eco, _, ok := strings.Cut(name, "/"); ok && eco != "" {
		return eco
	}
	return "other"
}

// itemExploits is whether any of an item's rows is known exploited, and whether any has a public exploit.
func itemExploits(it vulnx.StackItem) (kev, poc bool) {
	for _, a := range it.AdvisoryRows {
		if a.Exploit != nil {
			kev = kev || a.Exploit.KnownExploited
			poc = poc || a.Exploit.PublicExploit
		}
	}
	return kev, poc
}

// renderStackGrid is a scan's opening screen, the host grid's: the headline counts, one row per ecosystem with its
// affected packages by worst severity, the total, then what the index has no record of and what was scanned.
func renderStackGrid(res vulnx.StackResult, from scanSource, c *renderer.ColorConfig) string {
	var rows []gridRow
	byName := map[string]int{}
	kev, poc := 0, 0
	for _, it := range res.Items {
		name := stackEcosystem(it)
		i, ok := byName[name]
		if !ok {
			i = len(rows)
			byName[name] = i
			rows = append(rows, gridRow{Name: name})
		}
		rows[i].Checked++
		k, p := itemExploits(it)
		if k {
			kev++
		}
		if p {
			poc++
		}
		if verdict(it) != "affected" {
			continue
		}
		if sev := slices.Index(gridSeverities, strings.ToLower(it.WorstSeverity)); sev >= 0 {
			rows[i].Severity[sev]++
		}
		if k {
			rows[i].Exploited++
		}
	}
	slices.SortStableFunc(rows, func(a, b gridRow) int { return b.Checked - a.Checked })
	total := gridRow{Name: "total"}
	for _, r := range rows {
		total.Checked += r.Checked
		total.Exploited += r.Exploited
		for i, n := range r.Severity {
			total.Severity[i] += n
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\n  %s affected   %s known exploited   %s public exploit\n\n",
		c.Colorize(formatNumber(res.Summary.Affected), renderer.Bold), c.Colorize(formatNumber(kev), renderer.Bold+renderer.BrightRed),
		c.Colorize(formatNumber(poc), renderer.Bold))
	renderGrid(&b, "ECOSYSTEM", rows, total, c)
	b.WriteString("\n")
	dim := func(t string) string { return c.Colorize(t, renderer.Gray) }
	if n := res.Summary.Unseen; n > 0 {
		b.WriteString(dim(hostLabel("Unseen")+formatNumber(n)+" not in the index") + "\n")
	}
	scanned := []string{plural(len(res.Items), "package", "packages")}
	if from.input != "" {
		scanned = append([]string{termtext.Clean(from.input)}, scanned...)
	}
	if !from.start.IsZero() {
		scanned = append(scanned, time.Since(from.start).Round(time.Second).String())
	}
	b.WriteString(dim(hostLabel("Scanned")+strings.Join(scanned, " · ")) + "\n\n")
	return b.String()
}

// renderStackText is a scan's text output: a severity grid when it has stackGridMin packages or more, then each
// package with its CVEs (show caps them, 0: all), affected first, and the one-line summary for a short scan.
func renderStackText(res vulnx.StackResult, show int, from scanSource) string {
	var b strings.Builder
	grid := len(res.Items) >= stackGridMin
	if grid {
		b.WriteString(renderStackGrid(res, from, colorConfig()))
	}
	b.WriteString(renderStackList(res, show))
	s := res.Summary
	if !grid {
		// counted from the rows: the API's summary counts these for packages, not for products (CPE entries)
		kev, poc := 0, 0
		for _, it := range res.Items {
			k, p := itemExploits(it)
			if k {
				kev++
			}
			if p {
				poc++
			}
		}
		fmt.Fprintf(&b, "\n%s: %d affected, %d clean, %d undetermined, %d unseen", plural(s.Packages, "package", "packages"),
			s.Affected, s.Clean, s.Undetermined, s.Unseen)
		if kev > 0 || poc > 0 {
			fmt.Fprintf(&b, " (%d with a known exploited CVE, %d with a public exploit)", kev, poc)
		}
		b.WriteString("\n")
	}
	b.WriteString(undeterminedLines(res))
	return b.String()
}

// undeterminedLines says why items were left undetermined, a line per reason.
func undeterminedLines(res vulnx.StackResult) string {
	var b strings.Builder
	for _, r := range res.Summary.UndeterminedReasons {
		fmt.Fprintf(&b, "  undetermined %s (%d): %s\n", termtext.Clean(r.Reason), r.Count, termtext.Clean(r.Why))
	}
	return b.String()
}

// renderStackList lists each package with its CVEs (show caps them, 0: all), affected first.
func renderStackList(res vulnx.StackResult, show int) string {
	var b strings.Builder
	items := append([]vulnx.StackItem(nil), res.Items...)
	statusRank := map[string]int{"affected": 0, "undetermined": 1, "unseen": 2, "clean": 3}
	sort.SliceStable(items, func(i, j int) bool {
		if a, z := statusRank[verdict(items[i])], statusRank[verdict(items[j])]; a != z {
			return a < z
		}
		return vulnx.WorseSeverity(items[i].WorstSeverity, items[j].WorstSeverity)
	})
	for _, it := range items {
		name := it.Input
		name = shortOSPackageName(name)
		if name == "" {
			name = strings.TrimPrefix(it.Package, "cpe/") + "@" + it.Version
		}
		line := fmt.Sprintf("[%s] %s", strings.ToUpper(termtext.Clean(verdict(it))), termtext.Clean(name))
		if it.Status == "affected" {
			n := it.AdvisoryRowsTotal
			if n == 0 {
				n = it.Advisories
			}
			line += fmt.Sprintf("  %s, %d advisories", termtext.Clean(it.WorstSeverity), n)
			if it.FixedVersion != "" {
				line += "  fix: " + termtext.Clean(it.FixedVersion)
			}
		}
		b.WriteString(line + "\n")
		rows := it.AdvisoryRows
		if show > 0 && len(rows) > show {
			rows = rows[:show]
		}
		for _, a := range rows {
			id := a.CVE
			if id == "" {
				id = a.AdvisoryID
			}
			marks := ""
			if a.Exploit != nil {
				if a.Exploit.KnownExploited {
					marks += " KEV"
				}
				if a.Exploit.PublicExploit {
					marks += " POC"
				}
				if a.Exploit.NucleiTemplate != nil {
					marks += " TEMPLATE"
				}
			}
			score := ""
			if a.CvssScore > 0 {
				score = fmt.Sprintf(" %.1f", a.CvssScore)
			}
			fmt.Fprintf(&b, "  ↳ %-16s %-8s%s%s  %s\n", termtext.Clean(id), termtext.Clean(a.Severity), score, marks, termtext.Clean(a.Name))
		}
		total := len(it.AdvisoryRows)
		if it.AdvisoryRowsTotal > total {
			total = it.AdvisoryRowsTotal
		}
		if hidden := total - len(rows); hidden > 0 {
			hint := " (--show-all lists them)"
			if len(it.AdvisoryRows) < total && strings.HasPrefix(it.Package, "cpe/") {
				hint = " (--full lists them)" // the answer holds a product's 10 most urgent
			} else if len(it.AdvisoryRows) < total {
				hint = ""
			}
			fmt.Fprintf(&b, "  ↳ +%d more%s\n", hidden, hint)
		}
		if it.Status == "undetermined" {
			reason := it.Reason
			if reason == "" && len(it.Undetermined) > 0 {
				reason = it.Undetermined[0].Reason
			}
			if reason != "" {
				fmt.Fprintf(&b, "  ↳ undetermined: %s\n", termtext.Clean(reason))
			}
		}
	}
	return b.String()
}

func init() {
	scanCmd.Flags().StringVar(&scanList, "list", "", "read package versions from a file (one per line or comma-separated)")
	scanCmd.Flags().BoolVar(&scanFull, "full", false, "list every CVE of a product version (a scan lists its 10 most urgent); text output shows all unless --show is set")
	scanCmd.Flags().IntVar(&scanShow, "show", 10, "CVEs to list per package in text output (0: all)")
	scanCmd.Flags().StringVar(&scanVEX, "vex", "", "write a VEX document instead: openvex or cyclonedx")
	scanCmd.Flags().StringVar(&scanAuthor, "vex-author", "vulnx", "author of the OpenVEX document")
	scanCmd.Flags().DurationVar(&scanWait, "wait", 20*time.Minute, "how long to wait for the scan (image pulls can take minutes)")
	scanCmd.Flags().BoolVar(&scanShowAll, "show-all", false, "list every CVE per package in text output (with --host: every affected component and every one not checked; with a folder: its clean packages too)")
	scanCmd.Flags().StringVar(&scanImage, "image", "", "scan a public container image by reference (e.g. debian:12-slim, ghcr.io/owner/name:tag)")
	scanCmd.Flags().StringVar(&scanPlat, "platform", "", "image platform, e.g. linux/arm64 (default linux/amd64)")
	scanCmd.Flags().BoolVar(&scanHost, "host", false, "scan what is installed on this machine; sends the names and versions it finds to SecurityContext")
	scanCmd.Flags().StringVar(&scanView, "view", "grid", "with --host, what the terminal shows: grid (findings per source and severity), actions, brief, programs, details or markdown")
	scanCmd.Flags().StringVar(&scanSBOM, "sbom", "", "with --host: name the CycloneDX SBOM of what was checked, written beside the JSON report as vulnx-host-<date>.cdx.json unless named (an existing file is not overwritten; with --json, -o or --vex it is written only when named); with a folder: write its SBOM (vulnx-folder-<date>.cdx.json unless named)")
	scanCmd.Flags().Lookup("sbom").NoOptDefVal = "auto"
	scanCmd.Flags().BoolVar(&scanGraph, "graph", false, "with --host: also write a local graph page of the findings (opens in a browser, nothing uploaded)")
	scanCmd.Flags().BoolVar(&scanNoIgnore, "no-ignore", false, "with a folder: also read what its git ignore rules exclude and the repositories and worktrees nested in it")
	scanCmd.Flags().BoolVar(&scanImages, "images", false, "with a folder: also scan the images its Dockerfiles and Compose files name (pulled by SecurityContext; only the image names are sent)")
	scanCmd.Flags().BoolVar(&scanReport, "report", false, "with --host or a folder: upload the SBOM and print a report link that expires in 24 hours (the runtime snapshot stays local)")
	scanCmd.Flags().StringVar(&scanFailOn, "fail-on", "", "with --host or a folder: exit 2 if a reachable finding is at or above this level: kev (known exploited), critical or high")
	scanCmd.Flags().StringVar(&scanRoot, "root", "", "with --host: read a mounted Linux root filesystem instead of this machine (no runtime snapshot)")
	rootCmd.AddCommand(scanCmd)
}
