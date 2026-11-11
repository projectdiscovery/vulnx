package clis

// vulnx scan: scan a lockfile, SBOM, Compose file or Dockerfile, or a list of package versions (issue #385, with
// VEX output), on SecurityContext's /v1/stack.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/utils/errkit"
	fileutil "github.com/projectdiscovery/utils/file"
	"github.com/projectdiscovery/vulnx/v2"
	"github.com/spf13/cobra"
)

var (
	scanList    string
	scanFull    bool
	scanShow    int
	scanVEX     string
	scanAuthor  string
	scanWait    time.Duration
	scanShowAll bool
	scanHTML    string
	scanView    string
	scanOpen    bool
	scanSBOM    string
	scanReport  bool
	scanFailOn  string
	scanImage   string
	scanPlat    string
	scanHost    bool
	scanRoot    string

	scanCmd = &cobra.Command{
		Use:   "scan <file> | scan <package@version>... | scan --image <ref> | scan --host",
		Short: "scan a dependency file or a list of package versions",
		Long: `Scan with SecurityContext and list each package as affected, clean, undetermined or unseen.

A file is recognised by name: package-lock.json, yarn.lock, pnpm-lock.yaml, bun.lock, uv.lock, poetry.lock,
Cargo.lock, go.mod, Gemfile.lock, composer.lock, packages.lock.json, gradle.lockfile, a CycloneDX or SPDX JSON
SBOM, compose.yaml / docker-compose.yml (each service's image is pulled and scanned), or a Dockerfile (its base
image and the packages its RUN lines install).

Or give package versions directly (arguments, --list file, or stdin), checked in one request:
  ecosystem/name@version          npm/lodash@4.17.20, pypi/django@3.2.0, maven/org.apache.logging.log4j:log4j-core@2.14.1
  pkg:…                           a package URL, e.g. pkg:deb/debian/openssl@3.0.11-1~deb12u2?distro=debian-12
  vendor:product@version or cpe:  an NVD product version, e.g. apache:tomcat@8.5.62

Or an operating system:
  --image ghcr.io/owner/name:tag  a public container image: SecurityContext pulls it and reads its OS packages,
                                  language manifests and bundled libraries (--platform linux/arm64)
  --host                          this machine: Linux packages from dpkg, apk or rpm with the release from
                                  /etc/os-release, judged by the distribution's own advisories (macOS: its
                                  version); Python, npm and Ruby packages installed outside the distribution;
                                  the modules of Go and Rust binaries on PATH; on macOS, Homebrew formulae and
                                  applications with a known product. Anything read but not judged is listed.
                                  --root reads a mounted Linux filesystem instead. The terminal shows one
                                  screen: findings per source and severity (--view for other views). --report
                                  prints a report URL that auto-expires in 24 hours; --html writes the report
                                  as a local file (--open opens it);
                                  --fail-on kev|critical|high exits 2 on a reachable finding.

--vex writes a VEX document instead of the result: one statement per (package, CVE); affected rows are
"affected" / "exploitable" with the fixed version when known, undetermined rows "under_investigation" / "in_triage".`,
		Example: `
vulnx scan package-lock.json
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
			if scanVEX != "" && scanVEX != "openvex" && scanVEX != "cyclonedx" {
				gologger.Fatal().Msgf("--vex takes openvex or cyclonedx (got %s)", scanVEX)
			}
			ctx, cancel := context.WithTimeout(context.Background(), scanWait)
			defer cancel()
			show := scanShow
			if scanShowAll {
				show = 0
			}
			// an image by registry reference: pulled and scanned by SecurityContext
			if scanImage != "" {
				id, err := vulnxClient.ScanImage(ctx, scanImage, scanPlat)
				if err != nil {
					fatalAPI("scan", err)
				}
				gologger.Info().Msgf("Scanning image %s (stack %s); pulling can take minutes", scanImage, id)
				last := ""
				res, err := vulnxClient.WaitStack(ctx, id, func(status string) {
					if status != last && status != "ready" {
						gologger.Info().Msgf("scan %s", status)
						last = status
					}
				})
				if err != nil {
					fatalAPI("scan", err)
				}
				writeStackOutput(res, scanVEX, show)
				return
			}
			// this machine (or a mounted root filesystem): what is installed on it, checked as a list
			if scanHost || scanRoot != "" {
				if !slices.Contains(hostViews, scanView) {
					gologger.Fatal().Msgf("--view takes %s (got %s)", strings.Join(hostViews, ", "), scanView)
				}
				if scanFailOn != "" && !slices.Contains(failOnLevels, scanFailOn) {
					gologger.Fatal().Msgf("--fail-on takes %s (got %s)", strings.Join(failOnLevels, ", "), scanFailOn)
				}
				if scanReport { // before the scan: a report that could not expire is never uploaded
					if err := vulnxClient.StackExpirySupported(ctx); errkit.Is(err, vulnx.ErrExpiryUnsupported) {
						gologger.Fatal().Msg("--report: this SecurityContext API cannot expire a report's link yet, so nothing was scanned or uploaded")
					} else if err != nil {
						fatalAPI("report", err)
					}
				}
				start := time.Now()
				hostProgress("Reading what is installed ...")
				inv, err := vulnx.HostEntries(scanRoot)
				if err != nil {
					hostProgress("")
					gologger.Fatal().Msgf("Failed to read the host: %s", err)
				}
				hostProgress(fmt.Sprintf("Checking %s components ...", thousands(len(inv.Entries))))
				res, err := vulnxClient.CheckManyWith(ctx, inv.Entries, vulnx.CheckOptions{Functions: true, Compact: true, Progress: func(done, total int) {
					if done < total {
						hostProgress(fmt.Sprintf("Checking %s components: %s done ...", thousands(total), thousands(done)))
					}
				}})
				if err != nil {
					hostProgress("")
					fatalAPI("scan", err)
				}
				hostProgress("Checking which Go programs reach affected code ...")
				inv.MarkReachability(&res)
				hostProgress("")
				elapsed := time.Since(start)
				if scanFull || scanVEX != "" {
					fillProductCVEs(&res)
				}
				if scanVEX != "" || jsonOutput || outputFile != "" {
					writeHostJSON(inv, res, scanVEX)
					return
				}
				fmt.Print(renderHost(scanView, inv, res, elapsed, scanShowAll, colorConfig()))
				switch {
				case scanHTML != "" || scanOpen:
					path, err := writeHostReport(scanHTML, inv, res, elapsed)
					if err != nil {
						gologger.Fatal().Msgf("Failed to write the report: %s", err)
					}
					fmt.Printf("  Local report: file://%s\n", path)
					if scanOpen {
						openFile(path)
					}
				case scanView == "grid" && !scanReport:
					fmt.Println("  Full report: --report (URL, expires in 24 hours) or --html (local file)")
				}
				if scanSBOM != "" || scanReport {
					path, err := writeHostSBOM(scanSBOM, inv)
					if err != nil {
						gologger.Fatal().Msgf("Failed to write the SBOM: %s", err)
					}
					fmt.Printf("  SBOM: %s\n", path)
					if scanReport {
						hostProgress("Uploading the SBOM to SecurityContext ...")
						id, _, err := vulnxClient.ShareFile(ctx, path, shareExpiry)
						if err == nil {
							hostProgress("Waiting for SecurityContext to read it ...")
							_, err = vulnxClient.WaitStackReady(ctx, id)
						}
						hostProgress("")
						if errkit.Is(err, vulnx.ErrExpiryUnsupported) {
							gologger.Fatal().Msg("--report: this SecurityContext API cannot expire a report's link yet, so nothing was uploaded")
						}
						if err != nil {
							fatalAPI("report", err)
						}
						fmt.Printf("  Report: %s (expires in 24 hours)\n", vulnxClient.StackPage(id))
					}
				}
				if failsOn(scanFailOn, inv, res) {
					os.Exit(2)
				}
				return
			}
			// package versions rather than a file: arguments that are not a file, --list, or stdin
			if len(args) != 1 || !fileutil.FileExists(args[0]) || scanList != "" {
				entries := scanEntries(args)
				res, err := vulnxClient.CheckMany(ctx, entries)
				if err != nil {
					fatalAPI("scan", err)
				}
				if scanFull || scanVEX != "" {
					fillProductCVEs(&res)
				}
				writeStackOutput(res, scanVEX, show)
				return
			}
			// a JSON SBOM is read here and checked as a list (one request, answered at once)
			if raw, err := os.ReadFile(args[0]); err == nil {
				if entries, format, ok := vulnx.SBOMEntries(raw); ok {
					if len(entries) == 0 {
						gologger.Fatal().Msgf("%s is a %s SBOM with no component that has a purl or CPE", args[0], format)
					}
					gologger.Info().Msgf("Checking %d components of %s (%s SBOM)", len(entries), args[0], format)
					res, err := vulnxClient.CheckMany(ctx, entries)
					if err != nil {
						fatalAPI("scan", err)
					}
					if scanFull || scanVEX != "" {
						fillProductCVEs(&res) // a VEX states every CVE, not a product's 10 most urgent
					}
					writeStackOutput(res, scanVEX, show)
					return
				}
			}
			id, err := vulnxClient.ScanFile(ctx, args[0])
			if err != nil {
				fatalAPI("scan", err)
			}
			gologger.Info().Msgf("Uploaded %s (stack %s); waiting for the scan", args[0], id)
			last := ""
			res, err := vulnxClient.WaitStack(ctx, id, func(status string) {
				if status != last && status != "ready" {
					gologger.Info().Msgf("scan %s", status)
					last = status
				}
			})
			if err != nil {
				fatalAPI("scan", err)
			}
			writeStackOutput(res, scanVEX, show)
		},
	}
)

// scanEntries collects package versions from arguments (comma lists too), --list and stdin.
func scanEntries(args []string) []string {
	var entries []string
	for _, a := range args {
		for _, e := range strings.Split(a, ",") {
			if e = strings.TrimSpace(e); e != "" {
				entries = append(entries, e)
			}
		}
	}
	if scanList != "" {
		fromFile, err := readEntries(scanList)
		if err != nil {
			gologger.Fatal().Msgf("Failed to read %s: %s", scanList, err)
		}
		entries = append(entries, fromFile...)
	}
	if len(entries) == 0 && fileutil.HasStdin() {
		fromStdin, err := readEntriesFrom(os.Stdin)
		if err != nil {
			gologger.Fatal().Msgf("Failed to read stdin: %s", err)
		}
		entries = append(entries, fromStdin...)
	}
	if len(entries) == 0 {
		gologger.Fatal().Msg("Nothing to scan: give a file, package versions as arguments, --list, or stdin")
	}
	return removeDuplicates(entries)
}

func fatalAPI(what string, err error) {
	if strings.Contains(err.Error(), "too many requests") {
		handleRateLimitError()
	}
	gologger.Fatal().Msgf("Failed to %s: %s", what, err)
}

func readEntries(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return readEntriesFrom(f)
}

func readEntriesFrom(f *os.File) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, e := range strings.Split(line, ",") {
			if e = strings.TrimSpace(e); e != "" {
				out = append(out, e)
			}
		}
	}
	return out, sc.Err()
}

// fillProductCVEs replaces a product item's top rows with its full CVE list (a stack item carries the 10 most
// urgent; /v1/products/.../versions/... pages through all of them).
func fillProductCVEs(res *vulnx.StackResult) {
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
		rows, err := vulnxClient.ProductVersionCVEs(context.Background(), vendor, product, it.Version)
		if err != nil {
			gologger.Warning().Msgf("full CVE list for %s %s: %s", key, it.Version, err)
			continue
		}
		it.AdvisoryRows = rows
	}
}

var severityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4, "": 5}

// writeStackOutput prints or writes a stack result: JSON (--json / -o file.json), a VEX document (--vex), or text.
// show caps the CVEs listed per package in text output (0: all).
func writeStackOutput(res vulnx.StackResult, vex string, show int) {
	var data []byte
	var err error
	switch {
	case vex == "openvex":
		data, err = vulnx.OpenVEX(res, scanAuthor, time.Now())
	case vex == "cyclonedx":
		data, err = vulnx.CycloneDXVEX(res, time.Now())
	case jsonOutput || outputFile != "":
		data, err = json.MarshalIndent(res, "", "  ")
	}
	if err != nil {
		gologger.Fatal().Msgf("Failed to render output: %s", err)
	}
	if data != nil {
		if outputFile != "" {
			if err := writeNewFile(outputFile, data); err != nil {
				gologger.Fatal().Msgf("%s", err)
			}
			gologger.Info().Msgf("Wrote %s", outputFile)
			return
		}
		_, _ = os.Stdout.Write(append(data, '\n'))
		return
	}
	fmt.Print(renderStackText(res, show))
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

func renderStackText(res vulnx.StackResult, show int) string {
	var b strings.Builder
	items := append([]vulnx.StackItem(nil), res.Items...)
	statusRank := map[string]int{"affected": 0, "undetermined": 1, "unseen": 2, "clean": 3}
	sort.SliceStable(items, func(i, j int) bool {
		if statusRank[items[i].Status] != statusRank[items[j].Status] {
			return statusRank[items[i].Status] < statusRank[items[j].Status]
		}
		return severityRank[items[i].WorstSeverity] < severityRank[items[j].WorstSeverity]
	})
	for _, it := range items {
		name := it.Input
		name = shortOSPackageName(name)
		if name == "" {
			name = strings.TrimPrefix(it.Package, "cpe/") + "@" + it.Version
		}
		line := fmt.Sprintf("[%s] %s", strings.ToUpper(it.Status), name)
		if it.Status == "affected" {
			n := it.AdvisoryRowsTotal
			if n == 0 {
				n = it.Advisories
			}
			line += fmt.Sprintf("  %s, %d advisories", it.WorstSeverity, n)
			if it.FixedVersion != "" {
				line += "  fix: " + it.FixedVersion
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
			fmt.Fprintf(&b, "  ↳ %-16s %-8s%s%s  %s\n", id, a.Severity, score, marks, a.Name)
		}
		total := len(it.AdvisoryRows)
		if it.AdvisoryRowsTotal > total {
			total = it.AdvisoryRowsTotal
		}
		if hidden := total - len(rows); hidden > 0 {
			hint := ""
			if strings.HasPrefix(it.Package, "cpe/") {
				hint = " (--full lists them)"
			}
			fmt.Fprintf(&b, "  ↳ +%d more%s\n", hidden, hint)
		}
		if it.Status == "undetermined" {
			reason := it.Reason
			if reason == "" && len(it.Undetermined) > 0 {
				reason = it.Undetermined[0].Reason
			}
			if reason != "" {
				fmt.Fprintf(&b, "  ↳ undetermined: %s\n", reason)
			}
		}
	}
	s := res.Summary
	// counted from the rows: the API's summary counts these for packages, not for products (CPE entries)
	kev, poc := 0, 0
	for _, it := range res.Items {
		k, p := false, false
		for _, a := range it.AdvisoryRows {
			if a.Exploit != nil {
				k = k || a.Exploit.KnownExploited
				p = p || a.Exploit.PublicExploit
			}
		}
		if k {
			kev++
		}
		if p {
			poc++
		}
	}
	fmt.Fprintf(&b, "\n%d packages: %d affected, %d clean, %d undetermined, %d unseen", s.Packages, s.Affected, s.Clean, s.Undetermined, s.Unseen)
	if kev > 0 || poc > 0 {
		fmt.Fprintf(&b, " (%d with a known exploited CVE, %d with a public exploit)", kev, poc)
	}
	b.WriteString("\n")
	for _, r := range s.UndeterminedReasons {
		fmt.Fprintf(&b, "  undetermined %s (%d): %s\n", r.Reason, r.Count, r.Why)
	}
	return b.String()
}

func init() {
	scanCmd.Flags().StringVar(&scanList, "list", "", "read package versions from a file (one per line or comma-separated)")
	scanCmd.Flags().BoolVar(&scanFull, "full", false, "list every CVE of a product version (a scan lists its 10 most urgent)")
	scanCmd.Flags().IntVar(&scanShow, "show", 10, "CVEs to list per package in text output (0: all)")
	scanCmd.Flags().StringVar(&scanVEX, "vex", "", "write a VEX document instead: openvex or cyclonedx")
	scanCmd.Flags().StringVar(&scanAuthor, "vex-author", "vulnx", "author of the OpenVEX document")
	scanCmd.Flags().DurationVar(&scanWait, "wait", 20*time.Minute, "how long to wait for the scan (image pulls can take minutes)")
	scanCmd.Flags().BoolVar(&scanShowAll, "show-all", false, "list every CVE per package in text output (with --host: every affected component and every one not assessed)")
	scanCmd.Flags().StringVar(&scanImage, "image", "", "scan a public container image by reference (e.g. debian:12-slim, ghcr.io/owner/name:tag)")
	scanCmd.Flags().StringVar(&scanPlat, "platform", "", "image platform, e.g. linux/arm64 (default linux/amd64)")
	scanCmd.Flags().BoolVar(&scanHost, "host", false, "scan what is installed on this machine: OS packages, language packages, Go and Rust binaries, and on macOS Homebrew and applications")
	scanCmd.Flags().StringVar(&scanView, "view", "grid", "with --host, what the terminal shows: grid (findings per source and severity), actions, brief, programs, details or markdown")
	scanCmd.Flags().StringVar(&scanHTML, "html", "", "with --host: also write the full report as one local HTML file and print its link (--html=path.html to name it)")
	scanCmd.Flags().Lookup("html").NoOptDefVal = "auto"
	scanCmd.Flags().StringVar(&scanSBOM, "sbom", "", "with --host: also write what was checked as a CycloneDX SBOM file (--sbom=path.cdx.json to name it)")
	scanCmd.Flags().Lookup("sbom").NoOptDefVal = "auto"
	scanCmd.Flags().BoolVar(&scanReport, "report", false, "with --host: print a report URL that auto-expires in 24 hours")
	scanCmd.Flags().BoolVar(&scanOpen, "open", false, "with --host: write the local HTML report and open it in the browser")
	scanCmd.Flags().StringVar(&scanFailOn, "fail-on", "", "with --host: exit 2 when a reachable finding is kev (known exploited), critical or high (or worse)")
	scanCmd.Flags().StringVar(&scanRoot, "root", "", "with --host: read a mounted Linux root filesystem instead of /")
	rootCmd.AddCommand(scanCmd)
}
