<h1 align="center"> vulnx </h1>

<p align="center">
<a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-_red.svg" alt="MIT License"></a>
<a href="https://goreportcard.com/badge/github.com/projectdiscovery/vulnx"><img src="https://goreportcard.com/badge/github.com/projectdiscovery/vulnx" alt="Go Report Card"></a>
<a href="https://pkg.go.dev/github.com/projectdiscovery/vulnx/pkg/vulnx"><img src="https://img.shields.io/badge/go-reference-blue" alt="Go Reference"></a>
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
CVE records only: nuclei template records without a CVE (`vulnx id <template-id>`) are no longer available. Calls are
anonymous and rate limited per address; vulnx waits out a short rate limit by itself. `VULNX_API_URL` points vulnx at
another SecurityContext deployment.

Queries are `field:value` terms joined with `&&`; `||` works between values of one field
(`severity:critical || severity:high`), a keyword search takes up to 5 words, and a search filters on one vendor or
product. Wildcards, `NOT` on groups, upper bounds on scores and sorting or faceting on fields SecurityContext does not
index are rejected with a message saying so. `vulnx filters` lists every field.

## What vulnx Does

**Search vulnerabilities with precision:**
```bash
vulnx search "severity:critical && is_remote:true"
vulnx search "apache" --limit 20
vulnx search "cvss_score:>8.0 && cve_created_at:2024"
```

**Get detailed vulnerability info:**
```bash
vulnx id CVE-2021-44228
vulnx id CVE-2024-1234 --json
```

**Analyze vulnerability patterns:**
```bash
vulnx analyze --fields severity
vulnx analyze --fields affected_products.vendor
```

## Core Commands

| Command | Purpose | Example |
|---------|---------|---------|
| `search` | Find vulnerabilities with advanced filters | `vulnx search "apache && severity:high"` |
| `id` | Get details for specific CVE | `vulnx id CVE-2021-44228` |
| `filters` | List all available search fields and filters | `vulnx filters` |
| `analyze` | Aggregate data by fields | `vulnx analyze -f severity` |
| `auth` | Configure API access | `vulnx auth` |
| `version` | Show version info and check for updates | `vulnx version` |
| `update` | Update vulnx to latest version | `vulnx update` |
| `healthcheck` | Test connectivity | `vulnx healthcheck` |

## Essential Options

**Output formats:**
```bash
vulnx search "apache" --json              # Machine-readable JSON
vulnx search "apache" --output results.json  # Save to file
vulnx search "apache" --output results.csv   # Save as CSV (format picked by extension)
vulnx search "apache" --silent            # Quiet output
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

The `filters` command shows detailed information about all searchable fields including:
- Field names and data types
- Descriptions and examples
- Whether fields support sorting and faceting
- Available enum values for specific fields
- Search analyzer types

**Example output:**
```
Field: severity
Data Type: string
Description: Vulnerability severity level (e.g., critical, high, medium, low, info)
Can Sort: Yes
Facet Possible: Yes
Search Analyzer: keyword-lower
Examples: severity:critical, severity:high
Enum Values: critical, high, medium, low, info, unknown

Total: 69 filters available
```

Use this command to discover new search possibilities and understand field syntax before building complex queries.

## Common Search Patterns

**Find high-risk vulnerabilities:**
```bash
vulnx search "severity:critical && is_remote:true && is_kev:true"
vulnx search "cvss_score:>8.0 && cve_created_at:>=2024"  # High CVSS from 2024
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
vulnx search "cvss_score:>7.0"            # CVSS score above 7
vulnx search "epss_score:>0.8"            # High EPSS score
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
| `--product` | `-p` | Filter by one product (vendor:product) or vendor | `--product apache:log4j` |
| `--vendor` | | Filter by one vendor | `--vendor microsoft` |
| `--severity` | `-s` | Filter by severity | `--severity critical,high` |
| `--cvss-score` | | Minimum CVSS score | `--cvss-score ">=8"` |
| `--epss-score` | | Minimum EPSS score | `--epss-score ">0.8"` |
| `--vuln-age` | `-a` | Filter by age in days | `--vuln-age "<30"` |
| `--kev` | | In CISA's KEV list (VulnCheck's: query `is_vkev:true`) | `--kev` |
| `--template` | `-t` | Has Nuclei templates | `--template` |
| `--poc` | | Has proof of concept | `--poc` |
| `--remote-exploit` | | Remotely exploitable | `--remote-exploit` |
| `--vuln-status` | | Filter by NVD status | `--vuln-status analyzed` |

Not available with SecurityContext: `--tags`, `--vuln-type`, `--hackerone`, `--highlight`, `--range-facets`.


### Search Control Flags

| Flag | Short | Description | Example |
|------|-------|-------------|---------|
| `--detailed` | | Detailed output like 'id' | `--detailed` |
| `--limit` | `-n` | Number of results | `--limit 50` |
| `--offset` | | Pagination offset | `--offset 100` |
| `--sort-asc` | | Sort ascending (cve_created_at, cve_updated_at, cvss_score, epss_score, trending) | `--sort-asc cvss_score` |
| `--sort-desc` | | Sort descending | `--sort-desc cve_created_at` |
| `--fields` | | Select specific fields | `--fields cve_id,severity` |
| `--term-facets` | | Term facets, at most 3 (see `vulnx analyze help`) | `--term-facets severity=5` |

**Product and vendor filtering:**
```bash
vulnx search --product apache:log4j    # One product, as vendor:product
vulnx search --vendor microsoft         # One vendor
```

**Severity and scoring:**
```bash
vulnx search --severity critical,high   # Filter by severity
vulnx search --cvss-score ">=8"         # Minimum CVSS score
vulnx search --epss-score ">0.8"        # Minimum EPSS score
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

**CVEs affecting one product version** (by CPE, as cvemap's `-cpe` did):
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
on macOS it checks the macOS and Safari versions against Apple's per-release fixes. Only package names and
versions are sent. OS packages in SBOMs from syft or Trivy are judged the same way.

A VEX document has one statement per package and CVE: affected (with the fixed version when known) or under
investigation (with the reason). Clean packages get no statement.

**Fetch everything a search matches** (page by page; anonymous callers get about 1,000 CVEs a minute):
```bash
vulnx search --kev --all -o kev.json
```

**What changed on a CVE** (recorded since 2026-10-02: KEV listings, NVD status, EPSS, patches, labels):
```bash
vulnx id CVE-2026-123218 --history
```

## Vulnerability ID Lookup

**Multiple input methods:**
```bash
# Single ID lookup
vulnx id CVE-2024-1234

# Multiple IDs (comma-separated)
vulnx id CVE-2024-1234,CVE-2024-5678,CVE-2023-9999

# Auto-detection from stdin (no 'id' command needed!)
echo "CVE-2024-1234" | vulnx
echo -e "CVE-2024-1234\nCVE-2024-5678" | vulnx

# File input
vulnx id --file ids.txt
```

**Batch processing:**
```bash
# JSON output for automation
vulnx id --json CVE-2024-1234 CVE-2024-5678

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
| `cvss_score` | CVSS score (0-10) | `7.5`, `>8.0`, `<9.0` |
| `cve_id` | CVE identifier | `CVE-2021-44228` |
| `is_remote` | Remotely exploitable | `true`, `false` |
| `is_kev` | Known exploited vuln | `true`, `false` |
| `is_poc` | Has proof of concept | `true`, `false` |
| `affected_products.vendor` | Vendor name | `apache`, `microsoft` |
| `affected_products.product` | Product name | `tomcat`, `windows` |
| `cve_created_at` | Publication date | `>=2024`, `>2024-01-01`, `<2023` |
| `age_in_days` | Days since publication | `<30`, `>365`, `<=90` |

## Query Syntax

**Basic searches:**
```bash
vulnx search "apache"                     # Simple term
vulnx search "remote code execution"    # Phrase search
vulnx search "severity:critical"          # Field search
```

**Boolean logic:**
```bash
vulnx search "apache && nginx"           # Both terms
vulnx search "severity:critical || severity:high"  # Either value of one field
vulnx search "apache NOT tomcat"          # Exclude term
vulnx search "apache && severity:high"     # Keyword and filter
```

**Ranges and wildcards:**
```bash
vulnx search "cvss_score:>8.0"            # Greater than
vulnx search "cvss_score:>=9"             # At least (lower bounds only)
vulnx search "cve_created_at:>=2024-01-01" # Date comparison
vulnx search "age_in_days:<30"            # Recent vulnerabilities
vulnx search "cve_created_at:2024"        # Published in 2024
```

## Date Queries

**Important**: Date fields require comparison operators (`>=`, `>`, `<`, `<=`).

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
vulnx search "cvss_score:>8.0 && cve_created_at:>=2024"

# Recent vulnerabilities (age-based)
vulnx search "age_in_days:<30"            # Last 30 days
vulnx search "age_in_days:>365"           # Older than 1 year
```

**Supported formats:**
- `2024` (year)
- `2024-01` (year-month)
- `2024-01-15` (full date)

## Configuration

### Rate limits

vulnx calls SecurityContext anonymously, which allows a limited number of requests a minute per address. A short
rate limit is waited out automatically; a longer one stops with a message. `vulnx auth` and PDCP keys are not used by
the SecurityContext backend (a PDCP key is never sent to it).

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

**Rate limit issues:** wait a minute and retry; scripts making many calls should pace them.

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

- **Start immediately**: vulnx works without an API key - just run `vulnx search apache`
- **Stay updated**: vulnx automatically checks for updates; use `--disable-update-check` to disable
- Use `vulnx filters` to discover all available search fields and their syntax
- Start with broad searches, then narrow down with filters
- Use `--json` for scripting and automation
- Combine multiple filters for precise results
- Use `analyze` to understand data patterns
- Save frequently used queries as shell aliases

For advanced usage patterns and examples, see [USAGE.md](USAGE.md).

## Development

For development setup, code quality checks, and contribution guidelines, see [DEVELOPMENT.md](DEVELOPMENT.md).

## License

vulnx is distributed under [MIT License](LICENSE).
