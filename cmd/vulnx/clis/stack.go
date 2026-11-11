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
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"
	"github.com/projectdiscovery/vulnx/v2"
	"github.com/projectdiscovery/vulnx/v2/pkg/tools/renderer"
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
                                  --root reads a mounted Linux filesystem instead.

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
				inv, err := vulnx.HostEntries(scanRoot)
				if err != nil {
					gologger.Fatal().Msgf("Failed to read the host: %s", err)
				}
				gologger.Info().Msgf("Checking %s components of %s", thousands(len(inv.Entries)), inv.OS)
				res, err := vulnxClient.CheckManyWith(ctx, inv.Entries, vulnx.CheckOptions{Functions: true, Compact: true, Progress: func(done, total int) {
					if done < total {
						gologger.Info().Msgf("checked %s of %s", thousands(done), thousands(total))
					}
				}})
				if err != nil {
					fatalAPI("scan", err)
				}
				inv.MarkReachability(&res)
				if scanFull || scanVEX != "" {
					fillProductCVEs(&res)
				}
				if scanVEX != "" || jsonOutput || outputFile != "" {
					writeHostJSON(inv, res, scanVEX)
					return
				}
				fmt.Print(renderHostText(inv, res, scanShowAll, colorConfig()))
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
	scanCmd.Flags().StringVar(&scanRoot, "root", "", "with --host: read a mounted Linux root filesystem instead of /")
	rootCmd.AddCommand(scanCmd)
}

// writeHostJSON writes a host scan as the stack result with the inventory beside it, or as VEX.
func writeHostJSON(inv vulnx.HostInventory, res vulnx.StackResult, vex string) {
	if vex != "" {
		writeStackOutput(res, vex, 0)
		return
	}
	data, err := json.MarshalIndent(struct {
		Host vulnx.HostInventory `json:"host"`
		vulnx.StackResult
	}{inv, res}, "", "  ")
	if err != nil {
		gologger.Fatal().Msgf("Failed to render output: %s", err)
	}
	if outputFile != "" {
		if err := writeNewFile(outputFile, data); err != nil {
			gologger.Fatal().Msgf("%s", err)
		}
		gologger.Info().Msgf("Wrote %s", outputFile)
		return
	}
	_, _ = os.Stdout.Write(append(data, '\n'))
}

func colorConfig() *renderer.ColorConfig {
	if noColor || !renderer.IsTerminal() {
		return renderer.NoColorConfig()
	}
	return renderer.DefaultColorConfig()
}

// thousands formats n with comma separators.
func thousands(n int) string {
	s := fmt.Sprint(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// hostFixFirst is how many affected components a host report lists before --show-all.
const hostFixFirst = 25

// hostNotAssessedNames is how many not-assessed names per source a host report lists before --show-all.
const hostNotAssessedNames = 12

// componentParts splits a check entry into a kind, a name and a version for display.
func componentParts(entry string) (kind, name, version string) {
	if strings.HasPrefix(entry, "cpe:2.3:") {
		f := strings.Split(entry, ":")
		if len(f) > 5 {
			return "product", f[3] + ":" + f[4], strings.ReplaceAll(f[5], "\\", "")
		}
		return "product", entry, ""
	}
	body, _, _ := strings.Cut(strings.TrimPrefix(entry, "pkg:"), "?")
	typ, rest, _ := strings.Cut(body, "/")
	at := strings.LastIndex(rest, "@")
	if at < 0 {
		return typ, rest, ""
	}
	name, version = rest[:at], rest[at+1:]
	if u, err := url.PathUnescape(name); err == nil {
		name = u
	}
	if u, err := url.PathUnescape(version); err == nil {
		version = u
	}
	switch typ {
	case "golang":
		typ = "go"
	case "cargo":
		typ = "crate"
	case "deb", "rpm", "apk":
		name = name[strings.LastIndex(name, "/")+1:]
	}
	return typ, name, version
}

func fit(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

// renderHostText is a host scan for a person: what was read, the components to fix first, and what was not
// checked. --json has every row.
func renderHostText(inv vulnx.HostInventory, res vulnx.StackResult, all bool, c *renderer.ColorConfig) string {
	var b strings.Builder
	title := func(t string) { b.WriteString("\n" + c.Colorize(t, renderer.Bold+renderer.BrightWhite) + "\n") }
	dim := func(t string) string { return c.Colorize(t, renderer.Gray) }

	notAssessed := len(inv.NotAssessed)
	title(fmt.Sprintf("%s · %s components checked · %s not assessed", inv.OS, thousands(len(inv.Entries)), thousands(notAssessed)))
	fmt.Fprintf(&b, "  %-14s %8s %13s  %s\n", dim("SOURCE"), dim("CHECKED"), dim("NOT ASSESSED"), dim("READ FROM"))
	for _, s := range inv.Sources {
		na := "-"
		if s.NotAssessed > 0 {
			na = thousands(s.NotAssessed)
		}
		detail := s.Detail
		if detail == "" {
			detail = s.Name
		}
		fmt.Fprintf(&b, "  %-14s %8s %13s  %s\n", s.Name, thousands(s.Sent), na, detail)
	}
	if len(inv.NotRead) > 0 {
		b.WriteString(dim("  Not read: "+strings.Join(inv.NotRead, "; ")) + "\n")
	}

	// counted from the rows: the API's summary counts these for packages, not for products (CPE entries)
	kev, poc := 0, 0
	exploit := map[string]string{}
	for _, it := range res.Items {
		if unreachable(it) {
			continue
		}
		for _, a := range it.AdvisoryRows {
			if a.Exploit == nil || a.Reachability == "not_reachable" {
				continue
			}
			if a.Exploit.KnownExploited {
				exploit[it.Input] = "KEV"
			} else if a.Exploit.PublicExploit && exploit[it.Input] == "" {
				exploit[it.Input] = "POC"
			}
		}
		switch exploit[it.Input] {
		case "KEV":
			kev++
		case "POC":
			poc++
		}
	}
	s := res.Summary
	title("Result")
	fmt.Fprintf(&b, "  %s affected · %s undetermined · %s clean\n",
		c.Colorize(thousands(s.Affected), renderer.Bold+renderer.Red), thousands(s.Undetermined), thousands(s.Clean))
	if kev > 0 || poc > 0 {
		fmt.Fprintf(&b, "  %s with a known exploited CVE · %s more with a public exploit\n",
			c.Colorize(thousands(kev), renderer.Bold+renderer.BrightRed), thousands(poc))
	}
	var sev []string
	for _, k := range []string{"critical", "high", "medium", "low"} {
		if n := s.BySeverity[k]; n > 0 {
			sev = append(sev, c.ColorSeverity(k)+" "+thousands(n))
		}
	}
	if len(sev) > 0 {
		b.WriteString("  worst severity: " + strings.Join(sev, " · ") + "\n")
	}
	if line := reachabilityLine(res); line != "" {
		b.WriteString("  " + line + "\n")
	}

	// one row per component (a module vendored at many versions by many binaries is one thing to fix)
	type group struct {
		kind, name, worst, mark, fix string
		versions, in                 []string
		cves, linked, carriers, open int
	}
	exploitRank := map[string]int{"KEV": 0, "POC": 1, "": 2}
	groups := map[string]*group{}
	var order []*group
	byKind := map[string]int{}
	// per place found: what to update
	type place struct {
		name, worst, mark string
		components        map[string]bool
	}
	places := map[string]*place{}
	var placeOrder []*place
	notLinked := 0
	for _, it := range res.Items {
		if it.Status != "affected" {
			continue
		}
		if unreachable(it) {
			notLinked++
			continue
		}
		worst, cves := liveSeverity(it)
		kind, name, version := componentParts(it.Input)
		key := kind + " " + name
		g := groups[key]
		if g == nil {
			g = &group{kind: kind, name: name, worst: worst}
			groups[key] = g
			order = append(order, g)
			byKind[kind]++
		}
		g.versions = append(g.versions, version)
		if r := it.Reachability; r != nil {
			g.linked += len(r.Reachable)
			g.open += len(r.Unknown)
			g.carriers += len(r.Reachable) + len(r.NotReachable) + len(r.Unknown)
		}
		if severityRank[worst] < severityRank[g.worst] {
			g.worst = worst
		}
		if m := exploit[it.Input]; exploitRank[m] < exploitRank[g.mark] {
			g.mark = m
		}
		g.cves = max(g.cves, cves)
		if g.fix == "" || versionLess(g.fix, it.FixedVersion) {
			g.fix = it.FixedVersion
		}
		for _, in := range inv.FoundIn[it.Input] {
			if it.Reachability != nil && slices.Contains(it.Reachability.NotReachable, in) {
				continue // this binary links none of the affected functions
			}
			if !slices.Contains(g.in, in) {
				g.in = append(g.in, in)
			}
			p := places[in]
			if p == nil {
				p = &place{name: in, worst: worst, components: map[string]bool{}}
				places[in] = p
				placeOrder = append(placeOrder, p)
			}
			p.components[name] = true
			if severityRank[worst] < severityRank[p.worst] {
				p.worst = worst
			}
			if m := exploit[it.Input]; exploitRank[m] < exploitRank[p.mark] {
				p.mark = m
			}
		}
	}
	urgent := func(m1, w1 string, n1 int, m2, w2 string, n2 int) bool {
		if exploitRank[m1] != exploitRank[m2] {
			return exploitRank[m1] < exploitRank[m2]
		}
		if severityRank[w1] != severityRank[w2] {
			return severityRank[w1] < severityRank[w2]
		}
		return n1 > n2
	}
	// at equal exploit and severity, a component a binary is known to link comes before one no binary is shown to
	sort.SliceStable(order, func(i, j int) bool {
		a, z := order[i], order[j]
		if a.mark == z.mark && a.worst == z.worst && (a.linked > 0) != (z.linked > 0) && a.carriers > 0 && z.carriers > 0 {
			return a.linked > 0
		}
		return urgent(a.mark, a.worst, a.cves, z.mark, z.worst, z.cves)
	})
	sort.SliceStable(placeOrder, func(i, j int) bool {
		a, z := placeOrder[i], placeOrder[j]
		return urgent(a.mark, a.worst, len(a.components), z.mark, z.worst, len(z.components))
	})
	markCol := func(m string) string {
		switch m {
		case "KEV":
			return c.Colorize("KEV", renderer.Bold+renderer.BrightRed)
		case "POC":
			return "POC"
		}
		return "   "
	}
	list := func(items []string, n int) string {
		if len(items) > n {
			return strings.Join(items[:n], ", ") + fmt.Sprintf(" +%d", len(items)-n)
		}
		return strings.Join(items, ", ")
	}
	if len(order) > 0 {
		shown := order
		if !all && len(shown) > hostFixFirst {
			shown = shown[:hostFixFirst]
		}
		head := "Fix first · " + plural(len(order), "affected component", "affected components")
		if len(shown) < len(order) {
			head += fmt.Sprintf(", top %d (--show-all lists every one)", len(shown))
		}
		title(head)
		fmt.Fprintf(&b, "  %s %s %s %s %s %s %s %s %s\n", dim(fmt.Sprintf("%-8s", "SEVERITY")), dim("   "),
			dim(fmt.Sprintf("%-7s", "TYPE")), dim(fmt.Sprintf("%-32s", "COMPONENT")), dim(fmt.Sprintf("%-18s", "VERSION")),
			dim(fmt.Sprintf("%4s", "CVES")), dim(fmt.Sprintf("%-12s", "FIXED IN")), dim(fmt.Sprintf("%-7s", "LINKED")), dim("FOUND IN"))
		for _, g := range shown {
			version := g.versions[0]
			if len(g.versions) > 1 {
				version = fmt.Sprintf("%d versions", len(g.versions))
			}
			linked := "-"
			if g.carriers > 0 {
				linked = fmt.Sprintf("%d/%d", g.linked, g.carriers)
				if g.open > 0 {
					linked += "?"
				}
			}
			fmt.Fprintf(&b, "  %s %s %-7s %-32s %-18s %4d %-12s %-7s %s\n",
				c.ColorSeverity(fmt.Sprintf("%-8s", g.worst)), markCol(g.mark), g.kind, fit(g.name, 32), fit(version, 18),
				g.cves, fit(g.fix, 12), linked, dim(fit(list(g.in, 3), 48)))
		}
		var kinds []string
		for k := range byKind {
			kinds = append(kinds, k)
		}
		sort.Slice(kinds, func(i, j int) bool { return byKind[kinds[i]] > byKind[kinds[j]] })
		for i, k := range kinds {
			kinds[i] = fmt.Sprintf("%s %d", k, byKind[k])
		}
		b.WriteString(dim("  by type: "+strings.Join(kinds, " · ")) + "\n")
		b.WriteString(dim("  LINKED: binaries that link a function the advisories name as affected, of those carrying it; ? some are "+
			"unknown (no function list, or the package is linked but no listed function by name: it may be inlined)") + "\n")
		if notLinked > 0 {
			b.WriteString(dim(fmt.Sprintf("  left out: %s Go module versions whose binaries link none of the affected functions", thousands(notLinked))) + "\n")
		}
	}
	if len(placeOrder) > 0 {
		shown := placeOrder
		if !all && len(shown) > hostFixFirst/2 {
			shown = shown[:hostFixFirst/2]
		}
		head := "Update · " + plural(len(placeOrder), "program or directory carries", "programs and directories carry") + " affected components"
		if len(shown) < len(placeOrder) {
			head += fmt.Sprintf(", top %d", len(shown))
		}
		title(head)
		fmt.Fprintf(&b, "  %s %s %s %s %s\n", dim(fmt.Sprintf("%-8s", "SEVERITY")), dim("   "),
			dim(fmt.Sprintf("%-36s", "WHERE")), dim(fmt.Sprintf("%8s", "AFFECTED")), dim("COMPONENTS"))
		for _, p := range shown {
			names := make([]string, 0, len(p.components))
			for n := range p.components {
				names = append(names, n)
			}
			sort.Strings(names)
			fmt.Fprintf(&b, "  %s %s %-36s %8d %s\n", c.ColorSeverity(fmt.Sprintf("%-8s", p.worst)), markCol(p.mark),
				fit(p.name, 36), len(names), dim(fit(list(names, 3), 60)))
		}
	}
	if s.Undetermined > 0 {
		title(fmt.Sprintf("Undetermined · %s", thousands(s.Undetermined)))
		// answers merged from several requests repeat a reason once per request
		counts, why := map[string]int{}, map[string]string{}
		var reasons []string
		for _, r := range s.UndeterminedReasons {
			if _, ok := counts[r.Reason]; !ok {
				reasons = append(reasons, r.Reason)
			}
			counts[r.Reason] += r.Count
			why[r.Reason] = r.Why
		}
		for _, r := range reasons {
			fmt.Fprintf(&b, "  %d %s: %s\n", counts[r], r, dim(why[r]))
		}
	}
	if notAssessed > 0 {
		title(fmt.Sprintf("Not assessed · %s with no exact identifier, so not checked", thousands(notAssessed)))
		var order []string
		bySource := map[string][]string{}
		for _, na := range inv.NotAssessed {
			if _, ok := bySource[na.Source]; !ok {
				order = append(order, na.Source)
			}
			bySource[na.Source] = append(bySource[na.Source], na.Name)
		}
		for _, src := range order {
			names := bySource[src]
			more := ""
			if !all && len(names) > hostNotAssessedNames {
				more = fmt.Sprintf(" +%d more", len(names)-hostNotAssessedNames)
				names = names[:hostNotAssessedNames]
			}
			fmt.Fprintf(&b, "  %s (%d): %s%s\n", src, len(bySource[src]), strings.Join(names, ", "), dim(more))
		}
	}
	b.WriteString(dim("\n  --json writes every component with its CVEs; --show-all lists everything here") + "\n")
	return b.String()
}

func advisoryCount(it vulnx.StackItem) int {
	if it.AdvisoryRowsTotal > it.Advisories {
		return it.AdvisoryRowsTotal
	}
	return it.Advisories
}

var versionNumbers = regexp.MustCompile(`\d+`)

// versionLess orders versions by their first three numbers (v1.10.0 after v1.9.2), and on a tie puts the longer
// one first, so a release wins over a pseudo-version of it: close enough to show a component's highest fix.
func versionLess(a, b string) bool {
	x, y := versionNumbers.FindAllString(a, 3), versionNumbers.FindAllString(b, 3)
	for i := 0; i < len(x) && i < len(y); i++ {
		xi, _ := strconv.Atoi(x[i])
		yi, _ := strconv.Atoi(y[i])
		if xi != yi {
			return xi < yi
		}
	}
	if len(x) != len(y) {
		return len(x) < len(y)
	}
	return len(a) > len(b)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return thousands(n) + " " + many
}

// unreachable is a host scan's Go item that no binary carrying it can run: each one was checked and links none of
// the functions its advisories name.
func unreachable(it vulnx.StackItem) bool {
	r := it.Reachability
	return r != nil && len(r.NotReachable) > 0 && len(r.Reachable) == 0 && len(r.Unknown) == 0
}

// liveSeverity is an item's worst severity and advisory count over the rows a binary can run (rows not marked
// not_reachable); without reachability marks, the API's own.
func liveSeverity(it vulnx.StackItem) (string, int) {
	worst, n, marked := "", 0, false
	for _, a := range it.AdvisoryRows {
		if a.Reachability == "not_reachable" {
			marked = true
			continue
		}
		n++
		if worst == "" || severityRank[a.Severity] < severityRank[worst] {
			worst = a.Severity
		}
	}
	if !marked {
		return it.WorstSeverity, advisoryCount(it)
	}
	return worst, n
}

// reachabilityLine counts Go module versions by binary: how many copies link an affected function.
func reachabilityLine(res vulnx.StackResult) string {
	if res.FunctionsUnavailable {
		return "Go reachability: not checked (the API does not serve affected functions yet)"
	}
	reach, not, unknown := 0, 0, 0
	for _, it := range res.Items {
		if r := it.Reachability; r != nil {
			reach, not, unknown = reach+len(r.Reachable), not+len(r.NotReachable), unknown+len(r.Unknown)
		}
	}
	if reach+not+unknown == 0 {
		return ""
	}
	return fmt.Sprintf("Go reachability: of %s affected module copies in binaries, %s link an affected function, %s link none, %s unknown",
		thousands(reach+not+unknown), thousands(reach), thousands(not), thousands(unknown))
}
