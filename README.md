# freshcve

freshcve lists CVEs by the date NVD published them. Use it to answer two questions fast: *what dropped this week*, and *how many CVEs has product X picked up lately*. The second question matters more, and an earlier version of this script quietly got it wrong.

A **false zero** is the idea the rest of this README builds on. It's a search that reports "no results" because the tool lost the data, not because the data doesn't exist. If you're using CVE counts to decide whether a product is already crowded with researchers, a false zero isn't neutral. It sends you straight into the crowd.

## Quick start

You need `bash`, `curl`, `jq`, and `column`. Put the script on your `PATH`, then add an NVD API key. The key is optional, but without it NVD allows 5 requests per 30 seconds instead of 50, and long windows crawl.

```sh
ln -s "$PWD/freshcve" /usr/local/bin/freshcve
mkdir -p ~/.config/freshcve
echo 'NVD_API_KEY=<your-key>' > ~/.config/freshcve/apikey
chmod 600 ~/.config/freshcve/apikey
```

The config file is there for a reason. A key exported in your shell profile doesn't always reach the script when a non-interactive wrapper or an agent runs it, but the file always gets read. An `NVD_API_KEY` in the environment still takes priority.

```sh
freshcve                        # last 14 days, newest first
freshcve 30 fortinet            # last 30 days, regex match
freshcve 5 --unauth             # remotely reachable, no login, no user click
freshcve 365 netbox --count     # how busy has this product been?
```

## How the old version lost results

Version one ran a keyword search in two steps. First jq built each table row and cut the description to 70 characters so it would fit on screen. Then `grep` searched for your keyword in that **shortened** row. A CVE whose description named the product at character 71 or later was gone before the search ever saw it.

The bug only showed up when the table was compared against JSON mode, which searched the full text. Same 30-day pull, same keyword:

| Mode | `wordpress` matches |
|---|---|
| table (old) | 917 |
| JSON (old) | 1214 |
| table (fixed) | 1214 |

That's 297 CVEs, about a quarter of the real answer, silently dropped. Product names often sit mid-sentence ("A path traversal in the export handler of Acme Widget…"), so a narrow product search could come back empty while NVD had several entries for it. The fixed version filters once, inside jq, on the full description plus the CPE strings and the CVE ID. Truncation happens only at print time. A CPE string is NVD's machine-readable `vendor:product:version` label, which catches CVEs whose description never names the product.

## Two ways to pull

Picking the right mode matters more than any flag.

**Local mode** (the default) downloads every CVE published in the window and filters on your machine. It's the right tool for broad triage, like "anything unauthenticated and above 9 this week?" The cost is volume. Thirty days was about 17,900 records on 2026-11-25, and a year is several times that.

**Count mode** (`--count`) sends the keyword to NVD's own `keywordSearch` and gets back only the matches. NVD won't accept a date range longer than 120 days, so the script splits the window into 120-day chunks and stitches them together. It then prints the two numbers a crowding check wants:

```
netbox: 17 in window (last 365 days), 10 in last 90d.
```

Use count mode whenever the question is "how many". The keyword goes to NVD as-is, so it has to be plain words, not a regex. The script rejects anything else rather than guessing what you meant.

## Refusing to guess

Every pull now checks itself. NVD reports a `totalResults` figure for each window, and the script counts the records it actually received. If the two don't match, three things happen:

- the table prints `!!! INCOMPLETE PULL: counts below are a floor, not a total`
- the short pull is never cached, so the next run fetches again
- the script exits with code `3`, so scripts that wrap it can notice

A jq failure is also an error now. The old version piped jq errors to `/dev/null` and printed `(none)`, which was a second route to a false zero.

Requests that fail retry four times with a delay before the script gives up. Both modes also de-duplicate by CVE ID, since a record can show up twice if it sits on a chunk boundary or NVD shifts its pages mid-pull.

## Flags

```
--since YYYY-MM-DD   start the window at a date instead of N days ago
--min-cvss N         score floor; unscored CVEs still pass
--unauth             network-reachable, no privileges, no user interaction
--strict             with --unauth: CVSS 3.1 vectors only, drop unscored
--kev                tag CVEs listed in CISA's Known Exploited Vulnerabilities catalog
--count              server-side keyword count (see above)
--sort date|cvss     cvss puts UNSCORED rows first, then highest score
--json               JSON array: id, published, cvss, vector, products, description
--out FILE           copy the raw NVD pull somewhere
--refresh            skip the cache
--rejected           show CVEs NVD has marked Rejected (hidden by default)
```

Mistakes stop the script before it touches the network. It rejects an unknown option like `-x`, a flag with no value, a misplaced day count, a date that doesn't exist, and a keyword regex that won't compile, each with exit code `2` and a one-line reason. To search for a keyword that starts with a dash, put it after `--`: `freshcve 30 -- -rc1`.

`--unauth` works across both CVSS 3.1 and 4.0 vectors, the scoring strings NVD attaches to each CVE. It also lets **unscored** CVEs through: brand-new records NVD hasn't analyzed yet. A pre-auth critical published this morning has no score yet, and a filter that drops it misses exactly the CVE you were looking for. Treat `UNSCORED` as "go read the vector yourself".

Rejected CVEs are hidden by default, because the 30-day pull on 2026-11-25 included 559 of them and every one showed up as `UNSCORED` noise at the top of `--sort cvss`.

## Where files go

Results are cached for one hour in `~/.cache/freshcve/` (override with `FRESHCVE_CACHE`), with one file per mode, window, and keyword. Version one wrote `nvd-published-Nd.json` into whatever directory you happened to run it from. Those older files are safe to delete. The KEV feed is cached for 24 hours in the same place.

## What freshcve does not do

- **It only knows what NVD knows.** Projects that publish advisories only on GitHub, or whose CVE hasn't reached NVD yet, won't show up. For crowding checks, compare against the project's GitHub security advisories too.
- **Count mode matches words, not products.** `--count netbox` also catches `netbox-docker` and anything that mentions NetBox in passing. The count is a starting point. Read the IDs before trusting the number.
- **Who reported it isn't recorded.** Ten CVEs from the vendor's own security team and ten from five outside researchers look identical here. Telling them apart is up to you.
- **KEV tagging is a lookup against CISA's list,** not exploitation intel. Being absent from KEV doesn't mean nobody is exploiting it.
- **The one-hour cache can lag.** A cached relative window (`30`) is anchored to when it was fetched, so it can trail by up to an hour. Use `--refresh` when the last hour matters.

## Exit codes

```
0  ok
1  fetch or parse failed
2  bad arguments
3  pull incomplete: results shown, but treat any count as a floor
```

---

Since the fix, a zero from freshcve means NVD returned the whole window and none of it matched. When the pull is short, the script prints INCOMPLETE and exits with code 3 instead of printing a zero.
