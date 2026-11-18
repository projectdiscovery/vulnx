<h1 align="center"> vulnx </h1>

<p align="center">
<a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-_red.svg" alt="MIT License"></a>
<a href="https://goreportcard.com/badge/github.com/projectdiscovery/vulnx"><img src="https://goreportcard.com/badge/github.com/projectdiscovery/vulnx" alt="Go Report Card"></a>
<a href="https://pkg.go.dev/github.com/projectdiscovery/vulnx/v2"><img src="https://img.shields.io/badge/go-reference-blue" alt="Go Reference"></a>
<a href="https://github.com/projectdiscovery/vulnx/releases"><img src="https://img.shields.io/github/release/projectdiscovery/vulnx" alt="GitHub Release"></a>
<a href="https://twitter.com/pdiscoveryio"><img src="https://img.shields.io/twitter/follow/pdiscoveryio.svg?logo=twitter" alt="Twitter Follow"></a>
<a href="https://discord.gg/projectdiscovery"><img src="https://img.shields.io/discord/695645237418131507.svg?logo=discord" alt="Discord"></a>
<a href="https://starlog.is/articles/cybersecurity/projectdiscovery-vulnx">
  <img src="https://img.shields.io/badge/Starlog-Deep_Dive-00e5ff?style=flat&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiPjxwYXRoIGQ9Ik0xMiAyTDkgOUgyTDcgMTRMNSAyMkwxMiAxN0wxOSAyMkwxNyAxNEwyMiA5SDE1TDEyIDJaIi8+PC9zdmc+" alt="Starlog Deep Dive">
</a>
</p>

<h4 align="center"> Modern CLI for exploring vulnerability data with powerful search, filtering, and analysis capabilities </h4>

![image](https://github.com/user-attachments/assets/d60a1d43-27d8-4874-9459-046b7d8c633a)

## Quick Start

```bash
# 1. Get vulnx
go install github.com/projectdiscovery/vulnx/v2/cmd/vulnx@latest

# 2. Explore commands
vulnx --help
vulnx search --help

# 3. Start exploring vulnerabilities (no API key required)
vulnx filters                          # See all available search fields
vulnx search apache                    # Keyword search
vulnx id CVE-2021-44228                # One CVE in detail
```

### Data source

vulnx reads [SecurityContext](https://securitycontext.com) (`https://api.securitycontext.com/v1/cves`). It serves
CVE records only: nuclei template records without a CVE (`vulnx id <template-id>`) are not supported. No API key is
needed; see [API key and rate limits](#api-key-and-rate-limits). `VULNX_API_URL` points vulnx at another
SecurityContext deployment.

Queries are `field:value` terms joined with `&&`; `||` works between values of one field
(`severity:critical || severity:high`), a keyword search takes up to 5 words, and a search filters on one vendor or
product. Wildcards, `NOT` on groups, upper bounds on scores and sorting or faceting on fields SecurityContext does not
index are rejected with a message saying so. `vulnx filters` lists every field.

## What vulnx Does

**Search vulnerabilities with precision:**
```bash
vulnx search "severity:critical && is_remote:true"
vulnx search "apache" --limit 20
vulnx search "cvss_score:>=8 && cve_created_at:2024"
```

**Get detailed vulnerability info:**
```bash
vulnx id CVE-2021-44228
vulnx id CVE-2024-3400 --json
```

**Analyze vulnerability patterns:**
```bash
vulnx analyze --fields severity
vulnx analyze --fields vendor -q "is_kev:true"
```

## Core Commands

| Command | Purpose | Example |
|---------|---------|---------|
| `search` | Find vulnerabilities with advanced filters | `vulnx search "apache && severity:high"` |
| `id` | Get details for specific CVE | `vulnx id CVE-2021-44228` |
| `filters` | List all available search fields and filters | `vulnx filters` |
| `analyze` | Aggregate data by fields | `vulnx analyze -f severity` |
| `scan` | Check package versions, lockfiles, SBOMs or images | `vulnx scan npm/lodash@4.17.20` |
| `version` | Show version info and check for updates | `vulnx version` |
| `update` | Update vulnx to latest version | `vulnx update` |
| `healthcheck` | Check that the API answers | `vulnx healthcheck` |

## Essential Options

**Output formats:**
```bash
vulnx search "apache" --json              # Machine-readable JSON
vulnx search "apache" --output results.json  # Save to file
vulnx search "apache" --output results.csv   # Save as CSV (format picked by extension)
vulnx search "apache" --silent            # Quiet output
vulnx search "apache" --no-color          # No colors (also off when output is not a terminal)
```

**Logging and debugging** (all on stderr, so `--json` output stays clean):
```bash
vulnx --verbose search "apache"           # Verbose (-v): also show notices hidden by default
vulnx --debug search "apache"             # Debug logs plus request and response dumps
vulnx --debug-req search "apache"         # Dump requests only (API key redacted)
vulnx --debug-resp search "apache"        # Dump responses only
```

**Search control:**
```bash
vulnx search "apache" --limit 50          # Get 50 results
vulnx search "apache" --sort-desc cvss_score  # Sort by CVSS score
vulnx search "apache" --fields cve_id,severity  # Specific fields only
```

**Advanced search:**
```bash
vulnx search --term-facets severity=5,vendor=10 "apache"
vulnx search --kev --term-facets vendor "remote code"
vulnx search --detailed "xss"                # Detailed output like 'id' command
```

## Discovering Available Fields

**Explore what you can search on:**
```bash
vulnx filters                           # Show all available search fields
vulnx filters --json                    # Machine-readable field list
vulnx filters --output fields.json      # Save field info to file
vulnx filters --output fields.csv       # Save field info as CSV
```

The `filters` command shows every searchable field: its data type, description, examples, enum values, and whether
it can be sorted on or counted with `--term-facets` / `analyze`.

**Example output:**
```
Field: severity
Data Type: enum
Description: Severity; several values with ||
Can Sort: No
Facet Possible: Yes
Examples: severity:critical, (severity:critical || severity:high)
Enum Values: critical, high, medium, low, none
```

Use this command to discover new search possibilities and understand field syntax before building complex queries.

## Common Search Patterns

**Find high-risk vulnerabilities:**
```bash
vulnx search "severity:critical && is_remote:true && is_kev:true"
vulnx search "cvss_score:>=8 && cve_created_at:>=2024"   # High CVSS from 2024
vulnx search "is_kev:true && age_in_days:<90"            # Recent KEV exploits
```

**Search by technology:**
```bash
vulnx search "apache"                     # Apache vulnerabilities
vulnx search --vendor apache           # One vendor (one per search)
vulnx search "affected_products.vendor:microsoft"  # By vendor
```

**Filter by severity and scores:**
```bash
vulnx search "severity:high"              # High severity
vulnx search "cvss_score:>=7"             # CVSS score 7 or more
vulnx search "epss_score:>=0.8"           # High EPSS score
```

**Time-based searches:**
```bash
vulnx search "cve_created_at:>=2024"      # Published in 2024 or later
vulnx search "cve_created_at:>=2024-01-01 && cve_created_at:<2024-07-01"  # First half of 2024
vulnx search "age_in_days:<30"            # Recent vulnerabilities (last 30 days)
```

**Find exploitable vulnerabilities:**
```bash
vulnx search "is_poc:true"                # Has proof of concept
vulnx search "is_kev:true"                # Known exploited vulns
vulnx search "is_template:true"           # Has Nuclei templates
vulnx search --detailed "log4j"          # Detailed analysis of specific vuln
```

## Filter Flags

### Filter Flags Reference

| Flag | Short | Description | Example |
|------|-------|-------------|---------|
| `--product` | `-p` | Filter by one product (vendor:product, or a product name) | `--product apache:log4j` |
| `--vendor` | | Filter by one vendor | `--vendor microsoft` |
| `--severity` | `-s` | Filter by severity | `--severity critical,high` |
| `--cvss-score` | | Minimum CVSS score | `--cvss-score ">=8"` |
| `--epss-score` | | Minimum EPSS score | `--epss-score ">=0.8"` |
| `--vuln-age` | `-a` | Filter by age in days | `--vuln-age "<30"` |
| `--kev` | | In CISA's KEV list (VulnCheck's: query `is_vkev:true`) | `--kev` |
| `--template` | `-t` | Has Nuclei templates | `--template` |
| `--poc` | | Has proof of concept | `--poc` |
| `--remote-exploit` | | Remotely exploitable | `--remote-exploit` |
| `--vuln-status` | | Filter by NVD status | `--vuln-status analyzed` |
| `--cpe` | | CVEs affecting one product version | `--cpe 'cpe:2.3:a:apache:tomcat:8.5.62:*:*:*:*:*:*:*'` |
| `--version` | | With `--product vendor:product`: CVEs affecting that version | `--version 8.5.62` |


### Search Control Flags

| Flag | Short | Description | Example |
|------|-------|-------------|---------|
| `--detailed` | | Detailed output like 'id' | `--detailed` |
| `--limit` | `-n` | Number of results (1-1000) | `--limit 50` |
| `--offset` | | Pagination offset (offset + limit up to 1000) | `--offset 100` |
| `--all` | | Every matching result, up to 10,000 (ignores `--limit`) | `--all` |
| `--sort-asc` | | Sort ascending (cve_created_at, cve_updated_at, cvss_score, epss_score, trending) | `--sort-asc cvss_score` |
| `--sort-desc` | | Sort descending | `--sort-desc cve_created_at` |
| `--fields` | | Select specific fields | `--fields cve_id,severity` |
| `--term-facets` | | Count matches by up to 3 fields (see `vulnx analyze help`) | `--term-facets severity=5` |
| `--facet-size` | | Buckets per facet (1-50) | `--facet-size 20` |

**Product and vendor filtering:**
```bash
vulnx search --product apache:log4j    # One product, as vendor:product
vulnx search --product log4j            # A product name NVD gives one vendor
vulnx search --vendor microsoft         # One vendor
```

**Severity and scoring:**
```bash
vulnx search --severity critical,high   # Filter by severity
vulnx search --cvss-score ">=8"         # Minimum CVSS score
vulnx search --epss-score ">=0.8"       # Minimum EPSS score
vulnx search --vuln-status analyzed     # NVD status
vulnx search --vuln-age "<30"           # Recent vulnerabilities
```

**Exploit characteristics:**
```bash
vulnx search --kev                      # In CISA's KEV list
vulnx search "is_vkev:true"             # In VulnCheck's KEV list (includes every CISA entry)
vulnx search --template                 # Has Nuclei templates
vulnx search --poc                      # Has proof of concept
vulnx search --remote-exploit           # Remotely exploitable
vulnx search "is_ransomware:true"       # KEV entry records ransomware use
vulnx search "is_initial_access:true"   # VulnCheck initial-access exploit
```

## Version Search, Scans and VEX

**CVEs affecting one product version** (by CPE):
```bash
vulnx search --cpe 'cpe:2.3:a:apache:tomcat:8.5.62:*:*:*:*:*:*:*'
vulnx search --product apache:tomcat --version 8.5.62          # the same, without writing the CPE
vulnx search --cpe 'cpe:2.3:a:apache:http_server:1.3.13:*:*:*:*:*:*:*' --kev --sort-desc cvss_score
```
Results come most urgent first (severity, then CVSS). Severity, exploit, score, age, CWE and remote/auth filters
and sorting work with `--cpe`; keywords, vendor and facets do not.

**Scan a dependency file or a list of package versions:** lockfiles (package-lock.json, yarn.lock,
pnpm-lock.yaml, poetry.lock, uv.lock, Cargo.lock, go.mod, Gemfile.lock, composer.lock, ...), CycloneDX / SPDX JSON
SBOMs, compose.yaml or a Dockerfile; or versions given directly:
```bash
vulnx scan package-lock.json
vulnx scan npm/lodash@4.17.20 pypi/django@3.2.0 apache:tomcat@8.5.62
vulnx scan --list versions.txt --json
vulnx scan sbom.cdx.json --vex openvex -o sbom.openvex.json     # OpenVEX
vulnx scan sbom.cdx.json --vex cyclonedx -o sbom.vex.cdx.json   # CycloneDX VEX
```
**Scan an operating system:** a container image, or the machine vulnx runs on:
```bash
vulnx scan --image debian:12-slim                       # a public image: SecurityContext pulls and scans it
vulnx scan --image ghcr.io/owner/name:tag --platform linux/arm64
vulnx scan --host                                       # this machine
vulnx scan --host --root /mnt/rootfs                    # a mounted Linux filesystem
```
`--host` reads Linux packages from dpkg, apk or rpm with the release from `/etc/os-release` (Debian, Ubuntu,
Alpine, RHEL, Rocky Linux, AlmaLinux), judged by the distribution's own advisories, so backported fixes count;
on macOS it checks the macOS version against Apple's per-release fixes. It also reads what is installed beside the
OS packages: Python, npm and Ruby packages outside the distribution's own directories, the modules linked into Go
binaries on PATH and the crates Rust binaries embed, and on macOS Homebrew formulae and applications. Homebrew
formulae and applications have no package ecosystem, so only those with a known product are judged; the rest are
listed as not assessed, with a count per source. Only names and versions are sent.

Live host scans also save a passive `host.runtime` snapshot in the local JSON report: TCP listeners, bound UDP
endpoints, visible owner processes, numeric account IDs and executable paths. Exact executable-path matches link
back to inventory entries; they do not prove that dependencies are loaded or exploitable. Collection is time-bounded
and permission-limited, with timestamps, scope and explicit gaps; mounted-root scans skip it. The CLI runs runtime
collection and metadata parsing in a separate worker with a deadline, retaining a completed socket snapshot if later
enrichment cannot finish. Wildcard and specific
bind addresses do not establish internet access. No services are contacted, privileges elevated, or process arguments,
environments or secret contents collected. Runtime observations are not sent to the API or included in shared SBOMs.

Verified listening executables outside the usual installation paths are also read for embedded Go module or Rust
crate versions. Their package identifiers join the normal vulnerability checks under `runtime binaries`; unsupported
or changed executables remain unassessed. Files are never started to discover a version. The JSON distinguishes exact
component matches from `contained_in` installation relationships: an app helper or language runtime can reside in a
known installation without proving which packages it loaded. Runtime-discovered executable locations remain local
when exporting a shared SBOM. Inventory totals and findings can grow; the terminal format and original graph layout
stay the same. The local JSON contains paths and addresses: review it before sharing.

AI tools are read as a source of their own: assistant and editor applications, an agent command-line tool that
updates itself, AI editor extensions, and the packages MCP servers are started from (`npx server@1.2.0`,
`uvx server==1.2.0`) in each agent's configuration. A server with no version pinned, or one that is a local program,
is listed as not assessed. Only the package name and version are read from a configuration, never its environment.
Python tools installed in their own environment (`uv tool`, `pipx`) are read with the other Python packages.

`--graph` also writes `vulnx-host-<date>.graph.html`: one local page, with no network and nothing uploaded, that
draws the findings as a graph of where things are installed, the affected components there and the advisories that
affect them. It lists the advisories that reach the most places and the places with the most findings, and a click
shows what a node connects to and how to update it.

The harnesses read: Claude Code and Claude Desktop, Codex, Cursor, VS Code, Windsurf, Gemini CLI, Qwen Code,
OpenCode (its `plugin` packages and local plugin files too), Copilot CLI, Goose, Amp, Droid, Kiro, Amazon Q, Zed,
Crush, Junie, LM Studio, Continue, and the Cline, Roo Code and Kilo Code extensions. One that is not installed
reads nothing.

Local models are read too: the models in the Hugging Face cache, LM Studio's and Ollama's stores and the PyTorch
hub cache. A model file that is a pickle can run code when it is loaded (safetensors and GGUF cannot): one whose
pickle imports something that runs commands is flagged, the others are counted. Also said: a model that ships its
own code, and Ollama or LM Studio set to listen beyond this machine, since neither asks for a login. The runtimes
themselves (Ollama, llama.cpp, vLLM, MLX) are checked with the binaries, formulae and Python packages.

Under the grid, `Agent setup` counts what coding agents and editors load and run for you: editor extensions, skills,
plugins, hooks and MCP servers. It then lists the ones whose setup lets someone else decide what runs on the
machine: an MCP server with no version pinned, fetched from a git URL or another registry, or reached over plain
http; an extension installed from a file or named like a well-known one from another publisher; a skill or hook
that downloads code and runs it, or whose instructions carry invisible characters; an agent set to run commands
without asking. Every installed editor extension is also checked against the marketplaces' own removal lists (the Visual Studio
Marketplace's and Open VSX's): one removed as malware, as an impersonation or as untrustworthy is named there.
An extension on no list is counted as checked, which says only that no marketplace removed it.
These are read from the files and are risks, not verdicts: they are listed in the JSON report
under `host.agent_surface` and `host.risks`, apart from the vulnerabilities.

A formula is judged by product when its own source repository is the one the product lists: vulnx reads the
repository from the formula's own file and asks SecurityContext which products list it, keeping only a product that
lists that repository alone. An application built
on the Electron framework is judged by the framework's version and the npm packages in its bundle. A product the
index turns out not to know is listed as not checked instead of clean, and a formula with nothing that runs
(certificates, headers) is left out as data.

For Go binaries it also checks reachability: SecurityContext returns the functions each Go advisory names as affected,
and vulnx looks them up in each binary's own function table (present in stripped binaries too). A finding is
reachable when the binary links a listed function, and not reachable when it links no function of any affected
package; it stays unknown when the package is linked but no listed function is, since the compiler may have inlined
it. "Fix first" leaves out module versions no binary can reach and shows, per component, how many of the binaries
carrying it link an affected function (LINKED).

The terminal shows one screen: the reachable findings per source and severity. Every scan also writes the full
result as `vulnx-host-<date>.json` in the current directory: every component with its advisories, where it was
found, how to update it, Go reachability, the runtime snapshot and what was not checked.
```bash
vulnx scan --host                       # one screen, and the full result as vulnx-host-<date>.json
vulnx scan --host --report              # also a report URL that auto-expires in 24 hours
vulnx scan --host --sbom                # also write what was checked as a CycloneDX SBOM (vulnx-host-<date>.cdx.json)
vulnx scan --host --view actions        # in the terminal: what to update, most urgent first
vulnx scan --host --view details        # per component (also: brief, programs, markdown)
vulnx scan --host --json                # the full result on stdout (-o names a file)
vulnx scan --host --fail-on kev         # exit 2 when a reachable finding is known exploited, critical or high
```

The SBOM names, for each component, how it was installed and the places that hold it, and for each such place where
it is on disk and how it is updated (`brew upgrade caddy`, `go install ...@latest`, an application to update); home
directories read `~`. Places seen only through the runtime snapshot stay out of it.

`--report` is the one option that uploads more than a check does: it stores the machine's component names and
versions on SecurityContext under an unlisted link, which anyone who has the link can read. The link works for a
day. After that it stops answering; SecurityContext keeps the names and versions for analysis, no longer tied to who
sent them. Against an API that cannot expire a link, `--report` uploads nothing. The hosted page shows the verdicts;
where each component was found, Go reachability and the runtime snapshot are in the local JSON. OS packages in CycloneDX and SPDX SBOMs are judged the same way.

A VEX document has one statement per package and CVE: affected (with the fixed version when known) or under
investigation (with the reason). Clean packages get no statement.

| Flag | Description |
|------|-------------|
| `--list <file>` | Read package versions from a file (one per line or comma-separated) |
| `--show <n>` | CVEs listed per package in text output (default 10; `0` lists all) |
| `--show-all` | List every CVE per package in text output (same as `--show 0`) |
| `--full` | Fetch every CVE of a product version (`vendor:product@version`); without it a scan returns the 10 most urgent. `--vex` implies it; combine with `--show 0` to print them all |
| `--vex openvex\|cyclonedx` | Write a VEX document instead of the report |
| `--vex-author <name>` | Author of the OpenVEX document (default `vulnx`) |
| `--wait <duration>` | How long to wait for the scan (default `20m`; image pulls can take minutes) |
| `--image <ref>`, `--platform <os/arch>` | Scan a public container image (default platform `linux/amd64`) |
| `--host`, `--root <dir>` | Scan this machine, or a mounted Linux root filesystem |

```bash
vulnx scan --full --show 0 apache:tomcat@8.5.62          # every CVE of that version
vulnx scan --vex openvex --vex-author "Acme PSIRT" -o vex.json --list versions.txt
vulnx scan --image debian:12-slim --wait 45m
```

**Fetch everything a search matches** (page by page, up to 10,000 CVEs):
```bash
vulnx search --kev --all -o kev.json
```

**What changed on a CVE** (KEV listings, NVD status, EPSS, exposure, patches, labels):
```bash
vulnx id CVE-2024-3400 --history
```

## Vulnerability ID Lookup

**Multiple input methods:**
```bash
# Single ID lookup
vulnx id CVE-2021-44228

# Multiple IDs (comma-separated)
vulnx id CVE-2021-44228,CVE-2023-4966,CVE-2024-3400

# Auto-detection from stdin (no 'id' command needed)
echo "CVE-2021-44228" | vulnx
echo -e "CVE-2021-44228\nCVE-2023-4966" | vulnx

# File input
vulnx id --file ids.txt
```

**Batch processing:**
```bash
# JSON output for automation
vulnx id --json CVE-2021-44228 CVE-2023-4966

# Save to file
vulnx id --output vulns.json --file ids.txt
vulnx id --output vulns.csv --file ids.txt

# Pipeline integration
cat report.txt | grep -o 'CVE-[0-9]\{4\}-[0-9]\+' | vulnx id --json
```

## Useful Field Names

| Field | Description | Example Values |
|-------|-------------|----------------|
| `severity` | Vulnerability severity | `low`, `medium`, `high`, `critical` |
| `cvss_score` | Minimum CVSS score (0-10) | `>=7.5` |
| `cve_id` | CVE identifier | `CVE-2021-44228` |
| `is_remote` | Remotely exploitable | `true`, `false` |
| `is_kev` | Known exploited vuln | `true`, `false` |
| `is_poc` | Has proof of concept | `true`, `false` |
| `vendor` | Vendor name | `apache`, `microsoft` |
| `product` | Product, as vendor:product or a name | `apache:tomcat`, `log4j` |
| `cve_created_at` | Publication date | `>=2024`, `>2024-01-01`, `<2023` |
| `age_in_days` | Days since publication | `<30`, `>365`, `<=90` |

## Query Syntax

**Basic searches:**
```bash
vulnx search "apache"                     # Keyword
vulnx search "remote code execution"      # Keywords, all required (up to 5)
vulnx search "severity:critical"          # Field search
```

**Boolean logic:**
```bash
vulnx search "apache && nginx"            # Both keywords
vulnx search "severity:critical || severity:high"  # Either value of one field
vulnx search "is_kev:true && NOT is_poc:true"      # NOT on a true/false field
vulnx search "apache && severity:high"    # Keyword and filter
```

**Comparisons** (scores take a minimum only; wildcards are not supported):
```bash
vulnx search "cvss_score:>=9"             # At least
vulnx search "cve_created_at:>=2024-01-01" # Date comparison
vulnx search "age_in_days:<30"            # Recent vulnerabilities
vulnx search "cve_created_at:2024"        # Published in 2024
```

## Date Queries

A date without an operator matches that whole year, month or day; `>=`, `>`, `<` and `<=` compare.

**Single date comparisons:**
```bash
vulnx search "cve_created_at:>=2024"      # CVEs from 2024 onward
vulnx search "cve_created_at:<2024"       # CVEs before 2024
vulnx search "cve_created_at:>2024-06-01" # CVEs after June 1, 2024
```

**Date ranges:**
```bash
# CVEs from January 2024 only
vulnx search "cve_created_at:>=2024-01-01 && cve_created_at:<2024-02-01"

# High CVSS CVEs from 2024
vulnx search "cvss_score:>=8 && cve_created_at:2024"

# Recent vulnerabilities (age-based)
vulnx search "age_in_days:<30"            # Last 30 days
vulnx search "age_in_days:>365"           # Older than 1 year
```

**Supported formats:**
- `2024` (year)
- `2024-01` (year-month)
- `2024-01-15` (full date)

## Configuration

### API key and rate limits

vulnx works without an API key: calls are anonymous and SecurityContext allows a limited number of requests a minute
per address. Set `SECURITYCONTEXT_API_KEY` to send a SecurityContext API key with every request. The key goes only
over https (or to a loopback host) and is not sent on a redirect to another host. A short rate limit is waited out
automatically; a longer one stops with a message.

```bash
export SECURITYCONTEXT_API_KEY=<your key>
vulnx healthcheck                        # shows whether a key is set and that the API answers
```

**Version management:**
```bash
vulnx version                            # Show version and check for updates
vulnx version --disable-update-check     # Show version without update check
vulnx update                             # Update to latest version
vulnx --update                           # Alternative update command
```

**Global options:**
```bash
vulnx --json search "apache"              # JSON output
vulnx --silent search "apache"            # No banner
vulnx --timeout 60s search "apache"       # Custom timeout
vulnx --disable-update-check search "apache"  # Disable automatic update checks
```

## Troubleshooting

**Rate limit issues:** wait a minute and retry, or set an API key (see [API key and rate limits](#api-key-and-rate-limits)).

**"unsupported query":** the query uses a field, operator or sort SecurityContext does not offer; the message says
which. Run `vulnx filters` for the fields that work.

**No results:**
```bash
vulnx search "is_kev:true" --limit 1      # Test with known results
vulnx healthcheck                       # Check connectivity
```

**Large result sets:**
```bash
vulnx search "apache" --limit 100         # Increase limit
vulnx search "apache" --offset 100        # Pagination (offset + limit up to 1000)
vulnx search --fields cve_id,severity "apache"  # Fewer fields
```

**Connection issues:**
```bash
vulnx --timeout 60s search "apache"       # Increase timeout
vulnx --proxy http://localhost:8080 search "apache"  # Use proxy
vulnx --debug search "apache"             # Debug mode
vulnx --debug-req search "apache"         # Dump requests to stderr (API key redacted)
```

## Getting Help

**Help commands:**
```bash
vulnx --help                           # All commands overview
vulnx search --help                    # Search command help
vulnx id --help                        # ID command help
vulnx filters --help                   # Filters command help
vulnx analyze --help                   # Analyze command help
vulnx version                          # Version info with update check
vulnx version --disable-update-check   # Version info without update check
```

**Data exploration:**
```bash
vulnx filters                          # Show all searchable fields
vulnx search help                      # Detailed search fields
vulnx analyze help                     # Available analyze fields
```


## Tips

- **Start immediately**: vulnx works without an API key; just run `vulnx search apache`
- **Stay updated**: vulnx automatically checks for updates; use `--disable-update-check` to disable
- Use `vulnx filters` to discover all available search fields and their syntax
- Start with broad searches, then narrow down with filters
- Use `--json` for scripting and automation
- Combine multiple filters for precise results
- Use `analyze` to understand data patterns
- Save frequently used queries as shell aliases

For advanced usage patterns and examples, see [USAGE.md](USAGE.md).

## AI Assistants (MCP)

vulnx no longer ships an MCP server. Point an MCP client at the hosted SecurityContext server,
`https://mcp.securitycontext.com` (Streamable HTTP, stateless). It offers three tools: `get_security_context` (one
repository, package, product, CVE, ...), `search_security_context` (find and filter them) and
`create_security_context` (scan a public repository it does not have yet). Anonymous use works with rate limits; send
a SecurityContext API key in the `X-Api-Key` header for higher limits.

```json
{
  "mcpServers": {
    "securitycontext": {
      "url": "https://mcp.securitycontext.com",
      "headers": { "X-Api-Key": "<your key>" }
    }
  }
}
```

Leave out `headers` to use it anonymously.

## Breaking Changes in v2 (SecurityContext backend)

- The API is `https://api.securitycontext.com` (override with `VULNX_API_URL`); the `/v2/vulnerability` API is no
  longer called.
- ProjectDiscovery Cloud (PDCP) keys are not used: `vulnx auth` is removed. Set `SECURITYCONTEXT_API_KEY` instead,
  or use vulnx without a key. In Go, use `vulnx.WithAPIKey` (`WithPDCPKey` and `WithKeyFromEnv` are deprecated).
- Only CVE records are served: `vulnx id` with a nuclei template id that has no CVE fails.
- Removed search flags: `--tags`, `--vuln-type`, `--hackerone`, `--highlight`, `--range-facets`. `--product` and
  `--vendor` take one value. `--cvss-score` and `--epss-score` take a minimum (`>=N`).
- Queries are narrower: `||` only between values of one field, at most 5 keywords and 3 facets, no wildcards,
  score minimums only, and fields SecurityContext does not index are rejected with a message.
- `vulnx analyze` counts by at most 3 of the fields `vulnx analyze help` lists, and rejects a positional query
  (it was ignored); filter with `--query`.
- `vulnx mcp` is removed: use the hosted SecurityContext MCP server (see [AI assistants (MCP)](#ai-assistants-mcp)).
  `vulnx update --disable-update-check` is removed.

## Development

For development setup, code quality checks, and contribution guidelines, see [DEVELOPMENT.md](DEVELOPMENT.md).

## License

vulnx is distributed under [MIT License](LICENSE).
