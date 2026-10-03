#!/usr/bin/env bash
#
# dnsperftest.sh - DNS resolver latency benchmark
# =================================================
#
# PURPOSE
#   Measures DNS query latency of a configurable list of DNS resolvers
#   (IPv4 and/or IPv6) against a configurable list of test domains, and
#   reports the results as a sorted table / CSV / TSV / JSON.
#
# QUERY ORDER (important!)
#   Queries are interleaved by domain, not grouped by provider:
#
#       domain1 -> provider1
#       domain1 -> provider2
#       ...
#       domain1 -> providerN
#       domain2 -> provider1
#       ...
#
#   This avoids "bursting" many consecutive queries at a single resolver
#   (which can trigger rate limiting / caching effects and skews results
#   if network conditions drift over the runtime of the test) and gives
#   every provider a fair, time-aligned comparison for the same domain.
#
#   With --repeat N, this entire domain x provider matrix is executed as
#   N full passes (pass 1: all domains x all providers, pass 2: all
#   domains x all providers again, ...) instead of repeating the same
#   domain+provider combination N times back-to-back. This spreads
#   repeated measurements out over time, which produces a more robust
#   average and further reduces bias from short-lived network hiccups
#   hitting one resolver disproportionately.
#
#   The progress indicator reflects this: it shows the current query
#   number out of the total (passes x domains x providers), the current
#   pass, the current domain and the current provider.
#
# OUTPUT
#   Regardless of query order, results are grouped and printed per
#   provider (one row per provider, one column per domain, plus an
#   Average column), so the reporting format is unchanged for users of
#   earlier versions of this script.
#
# IMPLEMENTATION NOTES / KNOWN LIMITATIONS
#   - Provider names and domain names are used as parts of an internal
#     "provider|domain" map key (see the measurement loop below) and are
#     also used as the '|' field separator for row data. They must
#     therefore not contain the '|' character; this is validated at
#     startup and the script aborts with an error if violated.
#   - --timeout only supports whole seconds (this is a limitation of
#     dig's +time option and the POSIX "timeout" command used here).
#   - IPv6 support detection uses a local routing-table lookup (see
#     detect_ipv6_support) rather than a live query against one specific
#     external resolver. This is fast and does not depend on any single
#     external server being reachable, but it is a heuristic: it only
#     confirms that an IPv6 route exists, not that the path is actually
#     usable end-to-end.
#   - Table column widths are computed dynamically from the actual
#     rendered content (domain header labels and measured values), not
#     from the raw domain name length. Table headers show a shortened
#     domain label (TLD stripped, e.g. "wikipedia.org" -> "wikipedia")
#     so that columns stay compact even though domain names are usually
#     longer than the "NN.NNms" values printed underneath them. CSV/TSV/
#     JSON output always use the full, untruncated domain name.
#   - Latency color classification in table output is done with pure
#     bash integer arithmetic (values are always formatted as X.YY, so
#     the decimal point is stripped and compared as scaled integers)
#     instead of spawning bc/awk per cell. Because the scaled string can
#     have a leading zero (e.g. "0.50" -> "050"), it is parsed with the
#     explicit base-10 prefix (10#...) to avoid bash misinterpreting it
#     as an octal number.
#
# DEPENDENCIES
#   - dig (package: dnsutils / bind-tools) or drill (package: ldns-utils)
#   - awk, timeout, sort  (all part of coreutils / busybox on most systems)
#   No dependency on bc is required.
#
# EXIT CODES
#   0 = at least one provider answered successfully
#   1 = invalid usage / missing dependency
#   2 = all tested providers failed (error or timeout)
#
set -euo pipefail
export LC_ALL=C

# ---------------------------------------------------------------------------
# Dependency detection
# ---------------------------------------------------------------------------
if command -v drill >/dev/null 2>&1; then
    dig_cmd="drill"
elif command -v dig >/dev/null 2>&1; then
    dig_cmd="dig"
else
    echo "error: neither 'dig' nor 'drill' was found. Please install dnsutils (dig) or ldns-utils (drill)." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Defaults / configuration (can be overridden via CLI options below)
# ---------------------------------------------------------------------------
TIMEOUT_SEC=1
REPEAT_COUNT=1

# Latency color thresholds in ms (configurable)
THRESHOLD_GREEN=25
THRESHOLD_YELLOW=50
THRESHOLD_ORANGE=100

# ANSI color codes
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_ORANGE='\033[0;38;5;208m'
COLOR_RED='\033[0;31m'
COLOR_RESET='\033[0m'

# ---------------------------------------------------------------------------
# usage: print help text
# ---------------------------------------------------------------------------
usage() {
cat <<'EOF2'
Usage:
  dnsperftest.sh [ipv4|ipv6|all] [table|csv|tsv|json] [--sort fastest|slowest] [--repeat N] [--timeout SEC]
  dnsperftest.sh -h|--help

Examples:
  dnsperftest.sh
  dnsperftest.sh ipv4 table
  dnsperftest.sh all csv
  dnsperftest.sh all csv --sort slowest
  dnsperftest.sh ipv6 json --sort fastest
  dnsperftest.sh ipv4 table --repeat 3
  dnsperftest.sh ipv4 table --repeat 3 --timeout 2
  dnsperftest.sh --help

Defaults:
  mode    = ipv4
  format  = table
  sort    = fastest
  repeat  = 1
  timeout = 1 (seconds, per single query)

Query order:
  Queries are interleaved: domain1/provider1, domain1/provider2, ...,
  domain1/providerN, domain2/provider1, ... This gives every provider a
  fair, time-aligned comparison instead of hammering one provider with
  all domains before moving to the next.

  With --repeat N, the full domain x provider matrix is run N times in
  sequence (pass 1 completely, then pass 2, ...) rather than repeating
  a single domain+provider pair N times in a row. The shown average is
  the mean latency (rounded to 2 decimals) of all successful attempts
  across all passes for that domain+provider cell.

  fastest = lowest average latency first
  slowest = highest average latency first

Errors and timeouts:
  If a server is unreachable, "error" is shown for that cell.
  If a server exceeds the configured timeout, "timeout" is shown for
  that cell. If a provider has zero successful replies across all
  domains/passes, "error"/"timeout" is shown as its Average too.

Table format:
  Latencies (including Average) are color-coded (green/yellow/orange/red)
  based on THRESHOLD_GREEN / THRESHOLD_YELLOW / THRESHOLD_ORANGE (ms).
  "error"/"timeout" are highlighted in red. Column widths adapt to the
  actual rendered content; domain headers show a shortened label (TLD
  stripped) so columns stay compact. CSV/TSV/JSON always use full domain
  names.

Exit codes:
  0 = at least one provider answered successfully
  1 = invalid usage / missing dependency
  2 = all tested providers failed (error or timeout)
EOF2
}

# ---------------------------------------------------------------------------
# Provider / domain configuration
# ---------------------------------------------------------------------------
PROVIDERSV4="
1.1.1.1#Cloudflare
8.8.8.8#Google
9.9.9.9#Quad9
9.9.9.11#Quad9-ECS
208.67.222.222#OpenDNS
86.54.11.1#DNS4EU
94.140.14.140#AdGuard-DNS
76.76.2.0#ControlD
176.9.93.198#DNSForge
188.34.161.210#HaGeZi-Root
159.69.155.94#HaGeZi-Wurzn
162.55.58.40#HaGeZi-CTIF
95.217.163.17#HaGeZi-Juuri
"

PROVIDERSV6="
2606:4700:4700::1111#Cloudflare-v6
2001:4860:4860::8888#Google-v6
2620:fe::fe#Quad9-v6
2620:fe::11#Quad9-ECS-v6
2620:119:35::35#OpenDNS-v6
2a13:1001::86:54:11:1#DNS4EU-v6
2a10:50c0::1:ff#AdGuard-DNS-v6
2606:1a40::#ControlD-v6
2a01:4f8:151:34aa::198#DNSForge-v6
2a01:4f8:c17:1c66::1#HaGeZi-Root-v6
2a01:4f8:1c1c:d363::1#HaGeZi-Wurzn-v6
2a01:4f8:1c19:6c19::1#HaGeZi-CTIF-v6
2a01:4f9:c013:dc4e::1#HaGeZi-Juuri-v6
"

DOMAINS2TEST="
google.com
youtube.com
facebook.com
instagram.com
x.com
whatsapp.com
reddit.com
wikipedia.org
amazon.com
tiktok.com
"

# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------
mode="ipv4"
format="table"
sort_mode="fastest"

# First pass: allow -h/--help anywhere, even mixed with other args.
for arg in "$@"; do
    case "$arg" in
        -h|--help)
            usage
            exit 0
            ;;
    esac
done

while [ $# -gt 0 ]; do
    case "$1" in
        ipv4|ipv6|all)
            mode="$1"
            ;;
        table|csv|tsv|json)
            format="$1"
            ;;
        --sort)
            shift
            if [ $# -eq 0 ]; then
                echo "error: --sort requires a value" >&2
                usage
                exit 1
            fi
            case "$1" in
                fastest|slowest)
                    sort_mode="$1"
                    ;;
                *)
                    echo "error: unsupported sort mode: $1" >&2
                    usage
                    exit 1
                    ;;
            esac
            ;;
        --repeat)
            shift
            if [ $# -eq 0 ]; then
                echo "error: --repeat requires a value" >&2
                usage
                exit 1
            fi
            case "$1" in
                ''|*[!0-9]*)
                    echo "error: --repeat requires a positive integer" >&2
                    usage
                    exit 1
                    ;;
                0)
                    echo "error: --repeat must be at least 1" >&2
                    usage
                    exit 1
                    ;;
                *)
                    REPEAT_COUNT="$1"
                    ;;
            esac
            ;;
        --timeout)
            shift
            if [ $# -eq 0 ]; then
                echo "error: --timeout requires a value" >&2
                usage
                exit 1
            fi
            case "$1" in
                ''|*[!0-9]*)
                    echo "error: --timeout requires a positive integer (seconds)" >&2
                    usage
                    exit 1
                    ;;
                0)
                    echo "error: --timeout must be at least 1" >&2
                    usage
                    exit 1
                    ;;
                *)
                    TIMEOUT_SEC="$1"
                    ;;
            esac
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown argument: $1" >&2
            usage
            exit 1
            ;;
    esac
    shift
done

# ---------------------------------------------------------------------------
# IPv6 support detection
# ---------------------------------------------------------------------------
detect_ipv6_support() {
    if command -v ip >/dev/null 2>&1; then
        ip -6 route get 2606:4700:4700::1111 >/dev/null 2>&1 && return 0
        return 1
    fi
    "$dig_cmd" +short +tries=1 +time=2 @2606:4700:4700::1111 www.google.com 2>/dev/null | grep -q '^[0-9]'
}

hasipv6=""
detect_ipv6_support && hasipv6="true"

case "$mode" in
    ipv4)
        providerstotest="$PROVIDERSV4"
        ;;
    ipv6)
        if [ -z "$hasipv6" ]; then
            echo "error: IPv6 support not found. Unable to do the ipv6 test." >&2
            exit 1
        fi
        providerstotest="$PROVIDERSV6"
        ;;
    all)
        if [ -n "$hasipv6" ]; then
            providerstotest="$PROVIDERSV4
$PROVIDERSV6"
        else
            providerstotest="$PROVIDERSV4"
        fi
        ;;
esac

# ---------------------------------------------------------------------------
# Load domains / providers into ordered arrays. Also build a shortened
# "label" per domain (TLD stripped) used only for the table header, and
# validate that no name contains '|' (reserved separator character).
# ---------------------------------------------------------------------------
domains_arr=()
domain_labels=()
domain_label_maxlen=0
while IFS= read -r d; do
    [ -z "$d" ] && continue
    case "$d" in
        *'|'*)
            echo "error: domain '$d' contains the reserved '|' character." >&2
            exit 1
            ;;
    esac
    domains_arr+=("$d")
    label="${d%.*}"
    [ -z "$label" ] && label="$d"
    domain_labels+=("$label")
    [ "${#label}" -gt "$domain_label_maxlen" ] && domain_label_maxlen=${#label}
done <<< "$DOMAINS2TEST"

providers_arr=()
provider_names=()
provider_ips=()
provider_maxlen=8 # minimum width so the empty corner cell stays readable
while IFS= read -r p; do
    [ -z "$p" ] && continue
    pip=${p%%#*}
    pname=${p##*#}
    [ -z "$pname" ] && pname="$pip"
    case "$pname" in
        *'|'*)
            echo "error: provider name '$pname' contains the reserved '|' character." >&2
            exit 1
            ;;
    esac
    providers_arr+=("$p")
    provider_names+=("$pname")
    provider_ips+=("$pip")
    [ "${#pname}" -gt "$provider_maxlen" ] && provider_maxlen=${#pname}
done <<< "$providerstotest"

totaldomains=${#domains_arr[@]}
totalproviders=${#providers_arr[@]}
totalqueries=$(( REPEAT_COUNT * totaldomains * totalproviders ))

if [ "$totalproviders" -eq 0 ]; then
    echo "error: no providers configured for mode '$mode'." >&2
    exit 1
fi

provider_colwidth=$((provider_maxlen + 2))

# ---------------------------------------------------------------------------
# Main measurement loop
#   Order: pass -> domain -> provider  (interleaved, see header comment).
#   Results are accumulated in associative arrays keyed by "provider|domain"
#   so that grouping/printing per provider afterwards is a simple lookup.
# ---------------------------------------------------------------------------
declare -A sum_time      # accumulated successful query time per "provider|domain"
declare -A count_success # number of successful queries per "provider|domain"
declare -A count_timeout # number of timeouts per "provider|domain"

query_num=0
for (( pass=1; pass<=REPEAT_COUNT; pass++ )); do
    for d in "${domains_arr[@]}"; do
        for idx in "${!providers_arr[@]}"; do
            pip="${provider_ips[$idx]}"
            pname="${provider_names[$idx]}"
            key="${pname}|${d}"

            query_num=$((query_num + 1))
            printf "\rTesting DNS servers... [%d/%d] pass %d/%d  %-20s -> %-20s" \
                "$query_num" "$totalqueries" "$pass" "$REPEAT_COUNT" "$d" "$pname" >&2

            set +e
            output=$(timeout "${TIMEOUT_SEC}s" "$dig_cmd" +tries=1 +time="$TIMEOUT_SEC" +stats @"$pip" "$d" 2>&1)
            rc=$?
            set -e

            ttime=$(printf '%s' "$output" | awk '/Query time:/ {print $4; exit}')

            if [ "$rc" -eq 124 ]; then
                count_timeout["$key"]=$(( ${count_timeout["$key"]:-0} + 1 ))
            elif [ -z "${ttime:-}" ]; then
                : # neither a successful reply nor a timeout -> counts as plain error
            else
                sum_time["$key"]=$(( ${sum_time["$key"]:-0} + ttime ))
                count_success["$key"]=$(( ${count_success["$key"]:-0} + 1 ))
            fi
        done
    done
done

printf "\r%*s\r" 100 "" >&2

# ---------------------------------------------------------------------------
# Aggregate results per provider (one row per provider, one value per
# domain, plus an overall Average) from the accumulated maps.
# ---------------------------------------------------------------------------
rows=""
successfulproviders=0

for idx in "${!providers_arr[@]}"; do
    pname="${provider_names[$idx]}"
    row="$pname"
    domain_results=()

    for d in "${domains_arr[@]}"; do
        key="${pname}|${d}"
        dtime=${sum_time["$key"]:-0}
        dsuccess=${count_success["$key"]:-0}
        dtimeout=${count_timeout["$key"]:-0}

        if [ "$dsuccess" -gt 0 ]; then
            result=$(awk -v t="$dtime" -v c="$dsuccess" 'BEGIN{printf "%.2f", t/c}')
        elif [ "$dtimeout" -gt 0 ]; then
            result="timeout"
        else
            result="error"
        fi

        row="${row}|${result}"
        domain_results+=("$result")
    done

    joined=$(IFS=,; echo "${domain_results[*]}")
    read -r avg successcount <<< "$(awk -v s="$joined" '
        BEGIN {
            n = split(s, a, ",")
            sum = 0; cnt = 0
            for (i = 1; i <= n; i++) {
                if (a[i] ~ /^[0-9]+([.][0-9]+)?$/) { sum += a[i]; cnt++ }
            }
            if (cnt > 0) printf "%.2f %d\n", sum/cnt, cnt
            else print "NA 0"
        }')"

    if [ "$successcount" -gt 0 ]; then
        sortkey="$avg"
        successfulproviders=$((successfulproviders + 1))
    else
        avg="error"
        if printf '%s' "$row" | grep -qF '|timeout'; then
            avg="timeout"
        fi
        sortkey="999999"
    fi

    row="${row}|${avg}|${sortkey}"

    if [ -z "$rows" ]; then
        rows="$row"
    else
        rows="${rows}"$'\n'"$row"
    fi
done

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
sort_rows() {
    local keycol=$((totaldomains + 3))
    case "$sort_mode" in
        fastest)
            printf '%s\n' "$rows" | sort -t '|' -k"${keycol}","${keycol}"n
            ;;
        slowest)
            printf '%s\n' "$rows" | sort -t '|' -k"${keycol}","${keycol}"nr
            ;;
    esac
}

colorize_value() {
    local val="$1"
    local unit="${2:-}"
    if [[ "$val" =~ ^[0-9]+\.[0-9]{2}$ ]]; then
        local scaled=${val/./}
        scaled=$((10#$scaled))
        local g=$((THRESHOLD_GREEN * 100))
        local y=$((THRESHOLD_YELLOW * 100))
        local o=$((THRESHOLD_ORANGE * 100))
        local color
        if (( scaled <= g )); then
            color="$COLOR_GREEN"
        elif (( scaled <= y )); then
            color="$COLOR_YELLOW"
        elif (( scaled <= o )); then
            color="$COLOR_ORANGE"
        else
            color="$COLOR_RED"
        fi
        printf '%b%s%s%b' "$color" "$val" "$unit" "$COLOR_RESET"
    elif [ "$val" = "error" ] || [ "$val" = "timeout" ]; then
        printf '%b%s%b' "$COLOR_RED" "$val" "$COLOR_RESET"
    else
        printf '%s' "$val"
    fi
}

# print_table: renders the sorted results as an aligned, color-coded
# table. Column width per domain is computed from the actually rendered
# content (the shortened domain label in the header, and the widest
# "NN.NNms"/"error"/"timeout" value in that column across all providers)
# rather than from the raw (often much longer) domain name. This keeps
# columns compact instead of being stretched out to fit full domain
# names like "wikipedia.org" or "instagram.com".
print_table() {
    local sorted
    sorted=$(sort_rows)

    local -a colwidth
    local i val disp displen avgwidth=7
    for (( i=1; i<=totaldomains; i++ )); do
        displen=${#domain_labels[$((i-1))]}
        colwidth[$i]=$displen
    done

    while IFS= read -r row; do
        [ -z "$row" ] && continue
        IFS='|' read -r -a parts <<< "$row"
        for (( i=1; i<=totaldomains; i++ )); do
            val="${parts[$i]}"
            if [[ "$val" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
                disp="${val}ms"
            else
                disp="$val"
            fi
            displen=${#disp}
            [ "$displen" -gt "${colwidth[$i]}" ] && colwidth[$i]=$displen
        done
        val="${parts[$((totaldomains + 1))]}"
        if [[ "$val" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
            disp="${val}ms"
        else
            disp="$val"
        fi
        displen=${#disp}
        [ "$displen" -gt "$avgwidth" ] && avgwidth=$displen
    done <<< "$sorted"

    printf "%-${provider_colwidth}s" ""
    for (( i=1; i<=totaldomains; i++ )); do
        printf "%-$((colwidth[$i] + 2))s" "${domain_labels[$((i-1))]}"
    done
    printf "%-${avgwidth}s\n" "Average"

    while IFS= read -r row; do
        [ -z "$row" ] && continue
        IFS='|' read -r -a parts <<< "$row"

        printf "%-${provider_colwidth}s" "${parts[0]}"
        for (( i=1; i<=totaldomains; i++ )); do
            val="${parts[$i]}"
            if [[ "$val" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
                disp="${val}ms"
            else
                disp="$val"
            fi
            colored=$(colorize_value "$val" "ms")
            printf "%b" "$colored"
            padlen=$(( colwidth[$i] + 2 - ${#disp} ))
            [ "$padlen" -lt 0 ] && padlen=0
            printf '%*s' "$padlen" ""
        done
        avgval="${parts[$((totaldomains + 1))]}"
        coloredavg=$(colorize_value "$avgval" "ms")
        printf "%b\n" "$coloredavg"
    done <<< "$sorted"
}

print_csv() {
    printf "provider"
    for d in "${domains_arr[@]}"; do
        printf ",%s" "$d"
    done
    printf ",average\n"

    while IFS= read -r row; do
        [ -z "$row" ] && continue
        trimmed="${row%|*}"
        printf "%s\n" "${trimmed//|/,}"
    done < <(sort_rows)
}

print_tsv() {
    printf "provider"
    for d in "${domains_arr[@]}"; do
        printf "\t%s" "$d"
    done
    printf "\taverage\n"

    while IFS= read -r row; do
        [ -z "$row" ] && continue
        printf "%s\n" "$(printf '%s' "${row%|*}" | tr '|' '\t')"
    done < <(sort_rows)
}

print_json() {
    printf '[\n'
    first=1

    while IFS= read -r row; do
        [ -z "$row" ] && continue
        IFS='|' read -r -a parts <<< "$row"

        [ "$first" -eq 1 ] || printf ',\n'
        first=0

        printf '  {"provider":"%s","results":{' "${parts[0]}"
        i=1
        while [ "$i" -le "$totaldomains" ]; do
            [ "$i" -eq 1 ] || printf ','
            val="${parts[$i]}"
            dname="${domains_arr[$((i - 1))]}"
            if [[ "$val" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
                printf '"%s":%s' "$dname" "$val"
            else
                printf '"%s":"%s"' "$dname" "$val"
            fi
            i=$((i + 1))
        done
        avgval="${parts[$((totaldomains + 1))]}"
        if [[ "$avgval" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
            printf '},"average":%s}' "$avgval"
        else
            printf '},"average":"%s"}' "$avgval"
        fi
    done < <(sort_rows)

    printf '\n]\n'
}

case "$format" in
    table) print_table ;;
    csv)   print_csv ;;
    tsv)   print_tsv ;;
    json)  print_json ;;
esac

if [ "$successfulproviders" -eq 0 ]; then
    echo "error: all tested providers failed (error or timeout)." >&2
    exit 2
fi

exit 0
