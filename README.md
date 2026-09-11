# freshcve

List CVEs by **NVD publication date** (not KEV `date_added`).

## Why

NVD enrichment (CVSS scoring, CPE matching, etc.) often lags behind publication by hours to days. A freshly published, unauthenticated, pre-auth RCE can sit in NVD's "Received" state with no CVSS score yet. Most tooling filters on CVSS and silently drops these. `freshcve` optionally keeps unscored CVEs in view instead of hiding them.

## Requirements

- `curl`
- `jq`
- `column`
- Bash (uses `set -euo pipefail`, associative-array-free — should run on Bash 3.2+)

Optional:
- `NVD_API_KEY` — raises your NVD rate limit from 5 requests/30s to 50 requests/30s. Without it, expect throttling on wide date ranges.

## Installation

```bash
chmod +x freshcve
mv freshcve /usr/local/bin/   # or anywhere on your PATH
```

## Usage

```
freshcve                        CVEs published in the last 14 days
freshcve 7                      last 7 days
freshcve 30 fortinet            last 30 days, filter vendor/product/description (regex)
freshcve 30 --min-cvss 9        last 30 days, only CVSS >= 9
freshcve 5  --unauth            unauthenticated network vector (3.1 OR 4.0), incl. unscored
freshcve 30 --unauth --strict   3.1-only, exclude unscored (legacy/old behavior)
freshcve 30 --sort cvss         sort by CVSS descending instead of by date
freshcve 30 --json              machine-readable output
```

### Arguments and flags

| Arg/Flag | Description |
|---|---|
| `<days>` | Positional. Number of days back from now to search (default: `14`). |
| `<filter>` | Positional. Case-insensitive regex applied to the CVE description (and vendor reference). |
| `--min-cvss <n>` | Only show CVEs with base score `>= n`. Unscored CVEs still pass through unless combined with `--strict` logic that excludes them. |
| `--unauth` | Only show CVEs with an unauthenticated, no-user-interaction network vector. Matches across **both** CVSS v3.1 and v4.0 vectors, and **passes through unscored CVEs** by default (see below). |
| `--strict` | Modifies `--unauth`: restrict to CVSS 3.1-only vectors and **drop** unscored CVEs. This is the old/legacy `--unauth` behavior. |
| `--sort cvss\|date` | Sort by CVSS score (descending) or publish date (descending, default). |
| `--json` | Output a JSON array instead of a formatted table. |

## `--unauth` matching logic

By default (`--unauth` without `--strict`):
- A CVE matches if its vector (3.1 or 4.0) contains `AV:N`, `PR:N`, and `UI:N`, **or**
- The CVE has no CVSS metrics at all yet (`UNSCORED`) — included so a critical, pre-auth RCE isn't dropped just because NVD hasn't scored it.

With `--strict` added:
- Only CVSS 3.1-scored CVEs with the unauth vector match.
- Unscored CVEs are excluded (matches legacy behavior).

> Filtering is done **locally** in `jq`, not via NVD's server-side `cvssV3Metrics` parameter, because that parameter excludes CVSS 4.0-only records and unscored records entirely.

## Caching

Each run writes a cache file to the current working directory:

```
nvd-published-<days>d.json
```

- Cache TTL: 1 hour. If the file exists and is fresh, `freshcve` reads from it instead of hitting the NVD API again.
- The cache stores the **raw**, date-windowed pull with no vector pre-filtering, so different `--unauth`/`--strict`/`--min-cvss` combinations for the same day window can reuse the same cache file.
- Delete the file (or wait an hour) to force a refresh.

## Pagination and rate limiting

- NVD's API caps date windows at ~120 days per request; `freshcve` automatically splits wider ranges into 120-day segments and paginates each with `resultsPerPage=2000`.
- A small delay (`NVD_SLEEP`, default `0.7`s) is added between paginated requests. Override with `NVD_SLEEP=<seconds>` if you have a higher rate limit.
- Without `NVD_API_KEY`, wide ranges will be slow due to the 5 req/30s public rate limit.

## Output

### Table mode (default)

```
=== CVEs published, last 14 days, sort=date ===
PUBLISHED   CVSS       CVE              DESCRIPTION
2026-09-10  UNSCORED   CVE-2026-XXXXX   ...
2026-09-09  9.8        CVE-2026-YYYYY   ...
```

- `UNSCORED` rows indicate NVD hasn't scored the CVE yet — verify the vector manually.
- The raw JSON backing the table is left in `$PWD/nvd-published-<days>d.json` for further inspection.

### JSON mode (`--json`)

Array of objects:

```json
[
  {
    "id": "CVE-2026-XXXXX",
    "published": "2026-09-10T12:00:00.000",
    "cvss": "UNSCORED",
    "vector": "",
    "vendor": "https://example.com/advisory",
    "description": "..."
  }
]
```

## Notes

- If run in a non-TTY context (piped, redirected), ANSI colors are automatically disabled.
- `iso()` handles both GNU date (`date -d`) and BSD/macOS date (`date -r`) for timestamp conversion.
