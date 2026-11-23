# vulnx Advanced Usage Guide

Every example below is a valid query for the SecurityContext backend. `vulnx filters` lists the fields; README.md
describes the query rules and the [rate limits](README.md#rate-limits).

## Quick Reference

| Task | Command |
|------|---------|
| **Critical CVEs published in 2024** | `vulnx search "severity:critical && cve_created_at:2024"` |
| **Apache remote code execution** | `vulnx search "vendor:apache && remote code execution"` |
| **High CVSS with public exploits** | `vulnx search "cvss_score:>=8 && is_poc:true"` |
| **Known exploited CVEs** | `vulnx search "is_kev:true"` |
| **CVEs per vendor** | `vulnx analyze -f vendor` |
| **CVEs of one product version** | `vulnx search --product apache:tomcat --version 8.5.62` |

## Vulnerability ID Lookup

```bash
vulnx id CVE-2021-44228                              # one CVE
vulnx id CVE-2021-44228,CVE-2023-4966 CVE-2024-3400  # several, comma- or space-separated
vulnx id --file ids.txt                              # one per line or comma-separated; # starts a comment
vulnx id --history CVE-2024-3400                     # what changed on the record
```

Only CVE ids are accepted, at most 100 per run. Ids that are not found are reported and the rest are still printed.

**Stdin:** text whose lines mostly contain CVE ids is routed to `id` without naming the command:

```bash
echo "Critical vulnerabilities found: CVE-2021-44228, CVE-2023-4966" | vulnx
echo "CVE-2021-44228" | vulnx --json
grep -o 'CVE-[0-9]\{4\}-[0-9]\+' report.txt | vulnx id --json
```

**JSON:** one id gives an object, several give an array:

```bash
vulnx id --json CVE-2021-44228 | jq '{cve_id, severity, cvss_score, is_kev}'
vulnx id --json --file ids.txt | jq -r '.[] | .cve_id + ": " + .severity'
vulnx id --output vulns.csv --file ids.txt
```

## Search Strategies

### Start Broad, Filter Down

```bash
vulnx search "apache"
vulnx search "apache && severity:high"
vulnx search "apache && severity:high && cve_created_at:2024"
vulnx search "apache && severity:high && cve_created_at:2024 && is_remote:true"
```

### Technology Stack Assessment

```bash
vulnx search "vendor:apache && severity:high"
vulnx search "product:oracle:mysql && severity:critical"
vulnx search "product:log4j"                         # a product name NVD gives one vendor
vulnx search "vendor:vmware && spring && is_remote:true"
vulnx search --cpe 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*' --sort-desc cvss_score
```

A search filters on one vendor and one product; run one search per vendor to compare several.

### Threat Intelligence

```bash
vulnx search "is_kev:true && age_in_days:<365"
vulnx search "epss_score:>=0.9" --sort-desc cve_created_at
vulnx search "is_kev:true" --sort-desc cve_created_at --limit 20
vulnx search "is_poc:true && epss_score:>=0.8" --sort-desc epss_score
vulnx search "is_vkev:true && NOT is_kev:true"        # VulnCheck KEV entries CISA has not listed
vulnx search "is_ransomware:true" --sort-desc cve_created_at
vulnx search "age_in_days:<30 && severity:critical && is_remote:true"
```

## Advanced Filtering

### Dates and Age

```bash
vulnx search "age_in_days:<7 && severity:critical"     # last week
vulnx search "cve_created_at:2023-06"                  # published in June 2023
vulnx search "cve_created_at:>=2024-01-01 && cve_created_at:<2024-04-01"   # Q1 2024
vulnx analyze -f severity -q "cve_created_at:2023"
```

### Risk-Based Prioritization

```bash
vulnx search "severity:critical && is_remote:true && is_poc:true"
vulnx search "cvss_score:>=8 && epss_score:>=0.7"
vulnx search "is_remote:true && is_auth:false && is_poc:true"   # no authentication needed
vulnx search "is_template:true && severity:high" --limit 50
```

### Filter Flags

Flags are combined with `&&` and with the query:

```bash
vulnx search --vendor microsoft --severity critical,high --kev
vulnx search --product apache:tomcat --vuln-age "<30"
vulnx search --vuln-status analyzed "severity:critical"
vulnx search --vuln-age ">365" --poc
vulnx search --severity critical --remote-exploit --poc --template
vulnx search --cvss-score ">=9" --epss-score ">=0.5"
```

### Output Control

```bash
vulnx search --detailed "log4j"
vulnx search --fields cve_id,severity,cvss_score,affected_products.vendor "apache"
vulnx search --sort-asc cve_created_at "is_kev:true"
vulnx search --term-facets severity,vendor=5 "remote code execution"
```

`--sort-asc` / `--sort-desc` take `cve_created_at`, `cve_updated_at`, `cvss_score`, `epss_score`, `trending` or
`repositories`. A dotted `--fields` entry keeps that part of a nested value.

## Data Analysis

```bash
vulnx analyze -f severity
vulnx analyze -f vendor --facet-size 20
vulnx analyze -f cwe=10 -q "is_kev:true"
vulnx analyze -f year,severity -q "is_template:true"
vulnx analyze help                      # the fields that can be counted
```

At most 3 fields per call and 50 buckets per field.

## Automation and Scripting

Search JSON is `{"count": N, "results": [...], "total": N}`: `count` is the rows returned, `total` every match.

```bash
# New critical CVEs published today
vulnx search "age_in_days:0 && severity:critical" --json --silent | jq '.total'

# Known exploited criticals, a few fields each
vulnx search "severity:critical && is_kev:true" --json --silent | \
  jq '.results[] | {cve_id, cvss_score, epss_score}'

# CSV
vulnx search "severity:critical" --limit 100 --output critical.csv
vulnx search "severity:critical" --json --silent | jq -r '.results[] | [.cve_id, .severity, .cvss_score] | @csv'

# Every KEV entry for one vendor
vulnx search --kev --vendor microsoft --all --output microsoft-kev.json
```

**Monitoring script:**
```bash
#!/bin/bash
for vendor in apache nginx oracle; do
  echo "=== $vendor ==="
  vulnx search "vendor:$vendor && age_in_days:<7" --silent --limit 5
done
```

### Paging

A search returns at most 1000 rows (`--offset` + `--limit`); `--all` fetches every match, up to 10,000:

```bash
vulnx search "apache" --limit 100 --offset 0
vulnx search "apache" --limit 100 --offset 100
vulnx search "vendor:apache && severity:critical" --all --json --silent | jq '.count'
```

## Scans and VEX

```bash
vulnx scan npm/lodash@4.17.20 pypi/requests@2.19.0
vulnx scan --show 3 pypi/requests@2.19.0                # 3 CVEs per package in the report
vulnx scan --full apache:tomcat@8.5.62                  # every CVE of a product version, not the 10 most urgent
vulnx scan --list versions.txt --json
vulnx scan package-lock.json --vex openvex --vex-author "Acme PSIRT" --output vex.json
vulnx scan --image debian:12-slim --wait 45m            # give a large image longer than the default 20m
```

## Incident Response

```bash
vulnx id CVE-2021-44228 --json | jq '.is_kev'
vulnx search "product:apache:log4j" --sort-desc cvss_score
vulnx search "product:apache:log4j && is_remote:true"
```

## Troubleshooting

```bash
vulnx healthcheck                       # API URL, whether a key is set, and that the API answers
vulnx --debug-req search "apache"       # request dump on stderr
vulnx filters                           # the fields a query can use
```

An `unsupported query` error names the field, operator or sort that SecurityContext does not offer. The usual
fixes: write score filters as minimums (`cvss_score:>=8`, not `>8`), use `||` only between values of one field, keep
keyword searches to 5 words, and search one vendor or product at a time.

## Best Practices

- Start broad and add filters; use `--limit 1` to check a query before a large run.
- Use `--json` and `jq` in scripts, and `--silent` to keep the banner out of output.
- Use `analyze` or `--term-facets` to see how matches are distributed before fetching rows.
- Calls are anonymous and rate limited per address: pace scripted use, and expect a long run to wait out limits.
