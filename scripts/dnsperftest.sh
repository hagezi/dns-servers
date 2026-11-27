#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
#
# dnsperftest.sh - DNS resolver latency benchmark
# =================================================
#
# Based on dnsperftest by CleanBrowsing (https://github.com/cleanbrowsing/dnsperftest)
# Copyright (C) 2018 - 2022 CleanBrowsing Inc.
# Copyright (C) 2026 HaGeZi
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# PURPOSE
#   Measures the query latency of a list of DNS resolvers (IPv4 and/or
#   IPv6) for a list of test domains and prints the results as a sorted
#   table, CSV, TSV, or JSON.
#
# QUERY ORDER
#   Queries are interleaved by domain, not grouped by provider:
#
#       domain1 -> provider1
#       domain1 -> provider2
#       ...
#       domain1 -> providerN
#       domain2 -> provider1
#       ...
#
#   No single resolver receives a burst of consecutive queries, which could
#   trigger rate limiting or caching effects, and all providers are measured
#   for the same domain at nearly the same time. If network conditions drift
#   during the run, every provider is affected equally.
#
#   With --repeat N, the whole domain x provider matrix runs N times in a
#   row (pass 1 complete, then pass 2, ...), instead of repeating each
#   domain+provider pair N times back to back. Repeated measurements are
#   spread out over time, so a short network hiccup cannot skew the
#   average of one resolver.
#
#   The progress line shows the query number out of the total
#   (passes x domains x providers), the current pass, domain, and provider.
#
# OUTPUT
#   Whatever the query order, results are printed per provider: one row
#   per provider, one column per domain, plus an Average column.
#
# IMPLEMENTATION NOTES / KNOWN LIMITATIONS
#   - Provider and domain names are used in an internal "provider|domain"
#     map key and '|' is the field separator for row data, so names must
#     not contain '|'. This is checked at startup; the script aborts if
#     a name contains it.
#   - --timeout only accepts whole seconds, because dig's +time option and
#     the POSIX "timeout" command only accept whole seconds.
#   - A reply only counts as successful with RCODE NOERROR; SERVFAIL,
#     NXDOMAIN, REFUSED, etc. count as "error".
#   - Timeouts: dig gets +time=SEC and runs under an outer "timeout" one
#     second longer, so dig's own timeout normally fires first. Both dig's
#     "no reply" exit code (9) and the outer timeout (124) are reported as
#     "timeout". drill has no per-query timeout option and runs under the
#     outer "timeout" alone.
#   - dig and drill report the query time in whole milliseconds, so results
#     have 1 ms resolution (dnsperftest.ps1 measures below 1 ms).
#   - IPv6 support is detected with a local routing-table lookup (see
#     detect_ipv6_support), not with a live query to one external resolver.
#     This is fast and does not depend on a particular server being
#     reachable, but it only confirms that an IPv6 route exists, not that
#     the path actually works end to end.
#   - Table column widths follow the rendered content (header labels and
#     measured values), not the length of the domain names. The headers
#     show the domain without its TLD (e.g. "wikipedia.org" ->
#     "wikipedia") to keep the columns narrow. CSV, TSV, and JSON always
#     use the full domain name.
#   - Latency colors in the table are computed with bash integer
#     arithmetic instead of calling bc or awk per cell. Values are always
#     formatted as X.YY, so the decimal point is removed and the result
#     compared as a scaled integer. Because that string can start with a
#     zero (e.g. "0.50" -> "050"), it is parsed with an explicit base-10
#     prefix (10#...) so bash does not read it as an octal number.
#
# DEPENDENCIES
#   - dig (preferred; package dnsutils / bind-tools) or, as a fallback,
#     drill (package ldns-utils)
#   - awk, timeout, sort (part of coreutils / busybox on most systems)
#   bc is not needed.
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
if command -v dig >/dev/null 2>&1; then
    dig_cmd="dig"
elif command -v drill >/dev/null 2>&1; then
    dig_cmd="drill"
else
    echo "error: neither 'dig' nor 'drill' was found. Please install dnsutils (dig) or ldns-utils (drill)." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Defaults (can be changed with the CLI options below)
# ---------------------------------------------------------------------------
TIMEOUT_SEC=1
REPEAT_COUNT=1

# Latency color thresholds in ms. A value below a threshold gets that
# color; the defaults follow the rating scale in the HaGeZi DNS README
# (< 20 excellent, < 50 very good, < 100 OK, < 200 average/slow).
THRESHOLD_GREEN=20
THRESHOLD_YELLOW=50
THRESHOLD_ORANGE=100
THRESHOLD_RED=200

# ANSI color codes
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_ORANGE='\033[0;38;5;208m'
COLOR_RED='\033[0;31m'
COLOR_DARKRED='\033[1;31m'   # bold red: very slow (>= THRESHOLD_RED)
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
  domain1/providerN, domain2/provider1, ... All providers are measured
  for the same domain at nearly the same time, and no provider gets all
  domains in a row before the next one starts.

  With --repeat N, the full domain x provider matrix runs N times in a
  row (pass 1 complete, then pass 2, ...) instead of repeating each
  domain+provider pair N times back to back. Each cell shows the mean
  latency (rounded to 2 decimals) of all successful attempts across
  all passes.

  fastest = lowest average latency first
  slowest = highest average latency first

Errors and timeouts:
  A cell shows "error" if the server is unreachable or answers with an
  error code (SERVFAIL, NXDOMAIN, REFUSED, ...), and "timeout" if it
  does not answer within the timeout. A provider without a single
  successful reply shows "error" or "timeout" as its Average too.

Table format:
  Latencies (including Average) are colored on the same scale as the
  HaGeZi DNS README: green < 20 ms (excellent), yellow < 50 ms (very
  good), orange < 100 ms (OK), red < 200 ms (average to slow), bold
  red >= 200 ms (very slow). "error" and "timeout" are shown in red.
  Column widths follow the content, and domain headers omit the TLD to
  keep the columns narrow. CSV, TSV, and JSON always use full domain
  names.

Exit codes:
  0 = at least one provider answered successfully
  1 = invalid usage / missing dependency
  2 = all tested providers failed (error or timeout)
EOF2
}

# ---------------------------------------------------------------------------
# Providers and test domains
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

# First pass: accept -h/--help anywhere, even between other arguments.
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
# Load domains and providers into ordered arrays. Each domain also gets a
# short label without its TLD for the table header. Names containing '|'
# (the reserved separator) are rejected.
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
#   Order: pass -> domain -> provider (interleaved, see header comment).
#   Results are collected in associative arrays keyed by "provider|domain",
#   so printing them per provider afterwards is a simple lookup.
# ---------------------------------------------------------------------------
# run_query IP DOMAIN: one A query with a hard per-query timeout. dig gets
# its own +time limit, and the outer "timeout" is one second longer, so
# dig's own timeout normally fires first and is reported cleanly (exit
# code 9). drill has no per-query timeout option, so the outer "timeout"
# is its only limit. dig-only options are never passed to drill.
run_query() {
    local ip="$1" domain="$2"
    if [ "$dig_cmd" = "dig" ]; then
        timeout "$((TIMEOUT_SEC + 1))s" dig +tries=1 +time="$TIMEOUT_SEC" +stats @"$ip" "$domain" A 2>&1
    else
        timeout "${TIMEOUT_SEC}s" drill @"$ip" "$domain" A 2>&1
    fi
}

# is_timeout RC OUTPUT: true if the query timed out rather than failing in
# some other way (124 = killed by "timeout", 9 = dig "no reply from
# server").
is_timeout() {
    [ "$1" -eq 124 ] && return 0
    [ "$dig_cmd" = "dig" ] && [ "$1" -eq 9 ] && return 0
    case "$2" in
        *"timed out"*) return 0 ;;
    esac
    return 1
}

declare -A sum_time      # summed query time of successful queries per "provider|domain"
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
            output=$(run_query "$pip" "$d")
            rc=$?
            set -e

            # Query time and RCODE ("status:" in dig, "rcode:" in drill).
            ttime=$(printf '%s' "$output" | awk '/Query time:/ {print $4; exit}')
            rcode=$(printf '%s' "$output" | awk 'match($0, /(status|rcode): [A-Z]+/) {
                s = substr($0, RSTART, RLENGTH); sub(/.*: /, "", s); print s; exit }')

            if is_timeout "$rc" "$output"; then
                count_timeout["$key"]=$(( ${count_timeout["$key"]:-0} + 1 ))
            elif [ -z "${ttime:-}" ] || [ "${rcode:-}" != "NOERROR" ]; then
                : # no usable reply, or an error RCODE (SERVFAIL, NXDOMAIN, ...) -> plain error
            else
                sum_time["$key"]=$(( ${sum_time["$key"]:-0} + ttime ))
                count_success["$key"]=$(( ${count_success["$key"]:-0} + 1 ))
            fi
        done
    done
done

printf "\r%*s\r" 100 "" >&2

# ---------------------------------------------------------------------------
# Build one result row per provider (one value per domain plus the overall
# Average) from the collected maps.
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
        local r=$((THRESHOLD_RED * 100))
        local color
        if (( scaled < g )); then
            color="$COLOR_GREEN"
        elif (( scaled < y )); then
            color="$COLOR_YELLOW"
        elif (( scaled < o )); then
            color="$COLOR_ORANGE"
        elif (( scaled < r )); then
            color="$COLOR_RED"
        else
            color="$COLOR_DARKRED"
        fi
        printf '%b%s%s%b' "$color" "$val" "$unit" "$COLOR_RESET"
    elif [ "$val" = "error" ] || [ "$val" = "timeout" ]; then
        printf '%b%s%b' "$COLOR_RED" "$val" "$COLOR_RESET"
    else
        printf '%s' "$val"
    fi
}

# print_table: prints the sorted results as an aligned, colored table.
# Each domain column is as wide as its widest rendered cell: the short
# header label or the widest "NN.NNms"/"error"/"timeout" value in that
# column. Full domain names such as "instagram.com" would make the
# columns much wider than the values below them.
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
