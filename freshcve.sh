#!/usr/bin/env bash
# freshcve - list CVEs by NVD PUBLICATION date (not KEV date_added)
#
# Two fetch modes:
#   local  (default)  pull every CVE published in the window, filter locally.
#                     Good for "what dropped this week", broad triage.
#   --count           ask NVD server-side for one keyword, chunked into
#                     <=120-day spans. Good for "how many CVEs did product X
#                     get this year / last 90 days" (saturation checks).
#
# See README-freshcve.md next to this script, or `freshcve --help`.

set -euo pipefail

for bin in curl jq column; do
    command -v "$bin" >/dev/null || { echo "error: '$bin' not on PATH" >&2; exit 2; }
done

if [[ -t 1 ]]; then
    RED=$'\033[0;31m'; YEL=$'\033[1;33m'; CYA=$'\033[0;36m'; DIM=$'\033[2m'; NC=$'\033[0m'
else
    RED=''; YEL=''; CYA=''; DIM=''; NC=''
fi

usage() {
    cat <<'EOF'
freshcve - list CVEs by NVD publication date

Usage:
  freshcve                          CVEs published in the last 14 days
  freshcve 7                        last 7 days
  freshcve 30 fortinet              last 30 days, keyword regex (description, CPE, CVE id)
  freshcve --since 2026-11-01       everything published since a date
  freshcve 30 --min-cvss 9          CVSS >= 9 only (unscored CVEs still shown)
  freshcve 5  --unauth              network / no-privs / no-UI, CVSS 3.1 + 4.0 + unscored
  freshcve 30 --unauth --strict     3.1 vectors only, drop unscored
  freshcve 30 --kev                 tag rows that are in CISA KEV
  freshcve 365 netbox --count       server-side keyword count, prints window + 90d totals
  freshcve 30 --json                JSON array instead of a table

Flags:
  -h, --help          show this help
  --since YYYY-MM-DD  window start date (overrides the day count)
  --min-cvss N        minimum CVSS base score
  --unauth            network/no-privs/no-UI across CVSS 3.1 and 4.0, passes unscored
  --strict            with --unauth: 3.1-only, drop unscored
  --kev               tag CVEs listed in CISA KEV (feed cached 24h)
  --count             server-side NVD keywordSearch; needs a plain keyword, not a regex
  --sort date|cvss    sort order (default: date; cvss puts UNSCORED first)
  --json              output JSON instead of a table
  --out FILE          also copy the raw NVD pull to FILE
  --refresh           ignore the cache and fetch again
  --rejected          include CVEs NVD marks Rejected (hidden by default)

Environment:
  NVD_API_KEY         50 req/30s instead of 5/30s. Also read from
                      ~/.config/freshcve/apikey (line: NVD_API_KEY=<key>)
  FRESHCVE_CACHE      cache dir (default ~/.cache/freshcve)

Exit codes: 0 ok, 1 fetch failed, 2 usage, 3 pull incomplete (results shown, but
fewer records than NVD reported; do not trust a zero).
EOF
}

die() { echo "error: $*" >&2; exit 2; }

# ---- args ----
DAYS=14
SINCE=""
KEYWORD=""
MIN_CVSS=0
SORT_MODE="date"
UNAUTH=0
STRICT=0
JSON_OUT=0
COUNT=0
KEV=0
OUT_COPY=""
REFRESH=0
REJECTED=0

if [[ "${1:-}" =~ ^[0-9]+$ ]]; then DAYS="$1"; shift; fi

# need_val FLAG VALUE-WHAT "$@": the flag's value must exist and must not be another flag
need_val() {
    local flag="$1" what="$2"; shift 2
    [[ $# -ge 2 ]] || die "$flag needs $what"
    [[ "$2" != -* ]] || die "$flag needs $what, got flag '$2'"
}

set_keyword() {
    [[ -z "$KEYWORD" ]] || die "only one keyword allowed (use a regex: 'a|b'); got '$KEYWORD' and '$1'"
    KEYWORD="$1"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)  usage; exit 0 ;;
        --since)    need_val "$1" "YYYY-MM-DD" "$@"; SINCE="$2"; shift 2 ;;
        --min-cvss) need_val "$1" "a number" "$@"; MIN_CVSS="$2"; shift 2 ;;
        --sort)     need_val "$1" "date|cvss" "$@"; SORT_MODE="$2"; shift 2 ;;
        --out)      need_val "$1" "a file path" "$@"; OUT_COPY="$2"; shift 2 ;;
        --unauth)   UNAUTH=1; shift ;;
        --strict)   STRICT=1; shift ;;
        --kev)      KEV=1; shift ;;
        --count)    COUNT=1; shift ;;
        --json)     JSON_OUT=1; shift ;;
        --refresh)  REFRESH=1; shift ;;
        --rejected) REJECTED=1; shift ;;
        --)         shift; [[ $# -le 1 ]] || die "only one keyword allowed after --"
                    [[ $# -eq 1 ]] && set_keyword "$1"; break ;;
        -[0-9]*)    die "day count must be a positive integer, got '$1'" ;;
        --*=*)      die "use '${1%%=*} VALUE', not '$1'" ;;
        -*)         die "unknown option '$1' (try --help; a keyword starting with '-' goes after --)" ;;
        *)          [[ "$1" =~ ^[0-9]+$ ]] && die "day count must be the first argument, got '$1' later"
                    set_keyword "$1"; shift ;;
    esac
done

[[ "$DAYS" =~ ^[0-9]+$ && "$DAYS" -gt 0 ]] || die "day count must be a positive integer"
[[ "$MIN_CVSS" =~ ^[0-9]+(\.[0-9]+)?$ ]]   || die "--min-cvss must be a number"
[[ "$SORT_MODE" == date || "$SORT_MODE" == cvss ]] || die "--sort must be date or cvss"
(( STRICT == 1 && UNAUTH == 0 )) && die "--strict only makes sense with --unauth"
if (( COUNT == 1 )); then
    [[ -n "$KEYWORD" ]] || die "--count needs a keyword"
    [[ "$KEYWORD" =~ ^[A-Za-z0-9._\ -]+$ ]] \
        || die "--count sends the keyword to NVD verbatim; use plain words, not a regex"
fi

# catch a broken regex now, not after a multi-minute NVD pull
if [[ -n "$KEYWORD" ]] && ! jq -n --arg kw "$KEYWORD" '"" | test($kw; "i")' >/dev/null 2>&1; then
    die "keyword '$KEYWORD' is not a valid regex"
fi

API_BASE="https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_DIR="${FRESHCVE_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/freshcve}"
CACHE_MAX_AGE=3600
KEV_MAX_AGE=86400
mkdir -p "$CACHE_DIR"

iso() { date -u -d "@$1" +"%Y-%m-%dT%H:%M:%S.000" 2>/dev/null || date -u -r "$1" +"%Y-%m-%dT%H:%M:%S.000"; }
mtime() { stat -c %Y "$1" 2>/dev/null || stat -f %m "$1"; }

NOW=$(date +%s)
if [[ -n "$SINCE" ]]; then
    [[ "$SINCE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || die "--since must be YYYY-MM-DD"
    WINDOW_START=$( { date -u -d "$SINCE" +%s || date -u -j -f %Y-%m-%d "$SINCE" +%s; } 2>/dev/null) \
        || die "--since: '$SINCE' is not a real date"
    (( WINDOW_START < NOW )) || die "--since is in the future"
    DAYS=$(( (NOW - WINDOW_START + 86399) / 86400 ))
    WINDOW_LABEL="since $SINCE"
else
    WINDOW_START=$(( NOW - DAYS*86400 ))
    WINDOW_LABEL="last $DAYS days"
fi
CUTOFF=$(iso "$WINDOW_START")
CUTOFF_90=$(iso $(( NOW - 90*86400 )))

# ---- API key: env wins, else first readable config file ----
if [[ -z "${NVD_API_KEY:-}" ]]; then
    for _kf in "${FRESHCVE_API_KEY_FILE:-}" \
               "${XDG_CONFIG_HOME:-$HOME/.config}/freshcve/apikey" \
               "$HOME/.config/freshcve/apikey" \
               "$HOME/.nvd_api_key"; do
        [[ -n "$_kf" && -r "$_kf" ]] || continue
        _k=$(grep -m1 -oE '[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}' "$_kf" 2>/dev/null || true)
        if [[ -n "$_k" ]]; then NVD_API_KEY="$_k"; break; fi
    done
    unset _kf _k
fi

auth_header=()
if [[ -n "${NVD_API_KEY:-}" ]]; then
    auth_header=(-H "apiKey: ${NVD_API_KEY}")
    PAGE_SLEEP="${NVD_SLEEP:-0.7}"
else
    PAGE_SLEEP="${NVD_SLEEP:-6}"
fi

# ---- cache file: keyed by mode + window (+ keyword for --count) ----
if [[ -n "$SINCE" ]]; then win_key="since-$SINCE"; else win_key="${DAYS}d"; fi
if (( COUNT == 1 )); then
    kw_key=$(tr 'A-Z ' 'a-z_' <<< "$KEYWORD")
    CACHE_FILE="$CACHE_DIR/kw-${kw_key}-${win_key}.json"
else
    CACHE_FILE="$CACHE_DIR/pub-${win_key}.json"
fi

need_fetch() {
    (( REFRESH == 1 )) && return 0
    [[ -f "$CACHE_FILE" ]] || return 0
    (( NOW - $(mtime "$CACHE_FILE") > CACHE_MAX_AGE ))
}

INCOMPLETE=0

# fetch_window START END DEST
# Pulls one <=120-day window with pagination and appends one CVE per line to DEST.
# Counts what actually arrived and compares it with NVD's totalResults: a short
# pull is flagged, never silently passed off as the full answer.
fetch_window() {
    local start_ts="$1" end_ts="$2" dest="$3"
    local ps pe page got total=-1 start_index=0 received=0
    ps=$(iso "$start_ts"); pe=$(iso "$end_ts")
    local extra=()
    (( COUNT == 1 )) && extra=(--data-urlencode "keywordSearch=$KEYWORD")

    while :; do
        page=$(curl -sSf --retry 4 --retry-delay 6 --retry-all-errors --max-time 180 \
            "${auth_header[@]}" --get "$API_BASE" \
            --data-urlencode "pubStartDate=$ps" \
            --data-urlencode "pubEndDate=$pe" \
            --data-urlencode "resultsPerPage=2000" \
            --data-urlencode "startIndex=$start_index" \
            "${extra[@]}") || {
                echo "${RED}NVD fetch failed (window $ps -> $pe, index $start_index)${NC}" >&2
                [[ -z "${NVD_API_KEY:-}" ]] && echo "${DIM}no NVD_API_KEY: you are probably rate-limited${NC}" >&2
                return 1
            }
        (( total < 0 )) && total=$(jq -r '.totalResults // 0' <<< "$page")
        got=$(jq '.vulnerabilities | length' <<< "$page")
        jq -c '.vulnerabilities[]' <<< "$page" >> "$dest"
        received=$(( received + got ))
        start_index=$(( start_index + got ))
        (( got == 0 || start_index >= total )) && break
        sleep "$PAGE_SLEEP"
    done

    if (( received < total )); then
        echo "${RED}INCOMPLETE: window $ps -> $pe returned $received of $total records${NC}" >&2
        INCOMPLETE=1
    fi
}

if need_fetch; then
    if (( COUNT == 1 )); then
        echo "${CYA}==> NVD keywordSearch '$KEYWORD', published $WINDOW_LABEL${NC}" >&2
    else
        echo "${CYA}==> NVD, published $WINDOW_LABEL${NC}" >&2
    fi
    [[ -z "${NVD_API_KEY:-}" ]] && echo "${DIM}    no NVD_API_KEY: throttled to 5 req/30s${NC}" >&2
    tmp=$(mktemp); trap 'rm -f "$tmp" "${tmp}.json"' EXIT
    seg_end="$NOW"
    while (( seg_end > WINDOW_START )); do
        seg_start=$(( seg_end - 120*86400 ))
        (( seg_start < WINDOW_START )) && seg_start="$WINDOW_START"
        fetch_window "$seg_start" "$seg_end" "$tmp" || exit 1
        seg_end=$(( seg_start - 1 ))
        (( seg_end > WINDOW_START )) && sleep "$PAGE_SLEEP"
    done
    # de-dupe: a CVE can straddle a segment edge or shift pages mid-pull
    jq -s '{vulnerabilities: (unique_by(.cve.id))}' "$tmp" > "${tmp}.json"
    if (( INCOMPLETE == 0 )); then
        mv "${tmp}.json" "$CACHE_FILE"
        DATA="$CACHE_FILE"
        echo "${DIM}    cached: $CACHE_FILE${NC}" >&2
    else
        DATA="${tmp}.json"     # show it, but never cache a short pull
        [[ -z "$OUT_COPY" ]] && OUT_COPY="$CACHE_DIR/INCOMPLETE-$(basename "$CACHE_FILE")"
    fi
else
    DATA="$CACHE_FILE"
    echo "${CYA}==> cached <1h: $CACHE_FILE  (--refresh to refetch)${NC}" >&2
fi

[[ -n "$OUT_COPY" ]] && cp "$DATA" "$OUT_COPY"

# ---- KEV set (optional) ----
KEV_SET=$(mktemp); trap 'rm -f "${tmp:-}" "${tmp:-}.json" "$KEV_SET"' EXIT
echo '{}' > "$KEV_SET"
if (( KEV == 1 )); then
    KEV_FILE="$CACHE_DIR/kev.json"
    if [[ ! -f "$KEV_FILE" || $(( NOW - $(mtime "$KEV_FILE") )) -gt $KEV_MAX_AGE || $REFRESH == 1 ]]; then
        curl -sSf --retry 3 --max-time 60 "$KEV_URL" -o "$KEV_FILE.tmp" && mv "$KEV_FILE.tmp" "$KEV_FILE" \
            || { echo "${RED}KEV feed download failed${NC}" >&2; exit 1; }
    fi
    jq '[.vulnerabilities[].cveID | {(.): true}] | add // {}' "$KEV_FILE" > "$KEV_SET"
fi

# ---- one jq pass: score, vector, unauth class, keyword, KEV, sort ----
# In --count mode NVD already did the keyword match, so the local regex is skipped.
LOCAL_KW="$KEYWORD"; (( COUNT == 1 )) && LOCAL_KW=""

read -r -d '' JQ_PROG <<'JQEOF' || true
def en_desc: [ .descriptions[]? | select(.lang == "en") | .value ] | (.[0] // "");
def cpes: [ .configurations[]?.nodes[]?.cpeMatch[]?.criteria ];
def products: cpes | map(split(":") | "\(.[3]):\(.[4])") | unique;
[ .vulnerabilities[] | .cve
  | ( [ .metrics.cvssMetricV31[0].cvssData.baseScore,
        .metrics.cvssMetricV40[0].cvssData.baseScore,
        .metrics.cvssMetricV30[0].cvssData.baseScore ]
      | map(select(. != null)) | (.[0] // 0) ) as $score
  | ( .metrics.cvssMetricV31[0].cvssData.vectorString
      // .metrics.cvssMetricV40[0].cvssData.vectorString
      // .metrics.cvssMetricV30[0].cvssData.vectorString // "" ) as $vec
  | ( ( (.metrics.cvssMetricV31 // []) + (.metrics.cvssMetricV40 // [])
      + (.metrics.cvssMetricV30 // []) ) | length == 0 ) as $unscored
  | ( $vec | test("AV:N") and test("PR:N") and test("UI:N") ) as $unauth_vec
  | select(.published >= $cutoff)
  | select($rejected == 1 or .vulnStatus != "Rejected")
  | select($score >= $minc or $unscored)
  | select( if $unauth == 0 then true
            elif $strict == 1 then ($unauth_vec and ($vec | startswith("CVSS:3.1")))
            else ($unauth_vec or $unscored) end )
  | en_desc as $d
  | select( $kw == "" or ((.id + " " + $d + " " + (cpes | join(" "))) | test($kw; "i")) )
  | { id, published,
      cvss: (if $unscored then "UNSCORED" else $score end),
      vector: $vec,
      kev: ($kevset[0][.id] // false),
      products: products,
      description: $d,
      _score: $score, _unscored: $unscored }
]
| if $sort == "cvss"
  then sort_by([(if ._unscored then 1 else 0 end), ._score, .published]) | reverse
  else sort_by(.published) | reverse end
JQEOF

RESULTS=$(jq --arg cutoff "$CUTOFF" --argjson minc "$MIN_CVSS" \
             --argjson unauth "$UNAUTH" --argjson rejected "$REJECTED" --argjson strict "$STRICT" \
             --arg kw "$LOCAL_KW" --arg sort "$SORT_MODE" \
             --slurpfile kevset "$KEV_SET" "$JQ_PROG" "$DATA") \
    || { echo "${RED}jq failed on $DATA; refusing to print an empty result${NC}" >&2; exit 1; }

finish() { (( INCOMPLETE == 1 )) && exit 3; exit 0; }

# ---- JSON ----
if (( JSON_OUT == 1 )); then
    jq --argjson kev "$KEV" 'map(del(._score, ._unscored) | if $kev == 0 then del(.kev) else . end)' <<< "$RESULTS"
    finish
fi

# ---- table ----
TITLE="=== CVEs published, $WINDOW_LABEL"
[[ -n "$KEYWORD" ]] && TITLE+=", $( ((COUNT==1)) && echo "nvd-keyword" || echo "match")=$KEYWORD"
[[ "$MIN_CVSS" != 0 ]] && TITLE+=", cvss>=$MIN_CVSS"
(( UNAUTH == 1 )) && TITLE+=", unauth$( ((STRICT==1)) && echo '(strict 3.1)' || echo '(3.1+4.0+unscored)')"
TITLE+=", sort=$SORT_MODE ==="
echo
echo "${YEL}${TITLE}${NC}"
(( INCOMPLETE == 1 )) && echo "${RED}!!! INCOMPLETE PULL: counts below are a floor, not a total${NC}"

N=$(jq length <<< "$RESULTS")
if (( N == 0 )); then
    echo "  (none)"
else
    jq -r --argjson kev "$KEV" '
        (["PUBLISHED","CVSS"] + (if $kev == 1 then ["KEV"] else [] end) + ["CVE","DESCRIPTION"]),
        (.[] | [ .published[0:10], (.cvss | tostring) ]
               + (if $kev == 1 then [ (if .kev then "KEV" else "-" end) ] else [] end)
               + [ .id, (.description | gsub("\\s+"; " ") | .[0:70]) ])
        | @tsv' <<< "$RESULTS" | column -t -s $'\t'
fi

echo
SUMMARY="$N CVEs"
if (( COUNT == 1 )); then
    N90=$(jq --arg c "$CUTOFF_90" '[.[] | select(.published >= $c)] | length' <<< "$RESULTS")
    SUMMARY="$KEYWORD: $N in window ($WINDOW_LABEL), $N90 in last 90d"
fi
(( KEV == 1 )) && SUMMARY+=", $(jq '[.[] | select(.kev)] | length' <<< "$RESULTS") in KEV"
echo "${DIM}${SUMMARY}. raw json: $( ((INCOMPLETE==1)) && echo "$OUT_COPY (incomplete, not cached)" || echo "$DATA")${NC}"
(( UNAUTH == 1 && STRICT == 0 )) && echo "${DIM}UNSCORED = NVD has not scored it yet; check the vector by hand${NC}"
finish
