#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# hagezi-dns-check.sh – connectivity and function test for HaGeZi DNS
# Copyright (C) 2026 HaGeZi
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

set -u
export LC_ALL=C   # stable, parseable output from ping and kdig

VERSION="1.0.0"

# name  IPv4            IPv6
SERVERS="
root  188.34.161.210  2a01:4f8:c17:1c66::1
wurzn 159.69.155.94   2a01:4f8:1c1c:d363::1
juuri 95.217.163.17   2a01:4f9:c013:dc4e::1
ctif  162.55.58.40    2a01:4f8:1c19:6c19::1
"

PROTOCOLS="Do53 DoT DoH DoQ"
RESOLVE_DOMAINS=(example.com wikipedia.org)
# DNSSEC: the AD flag is not passed on (Technitium -> Unbound),
# so validation is tested via the result for signed and deliberately broken zones
DNSSEC_OK="isc.org"                                            # correctly signed -> NOERROR expected
DNSSEC_BOGUS=(dnssec-failed.org sigfail.verteiltesysteme.net)  # broken signature -> SERVFAIL expected
BLOCK_DOMAIN="app-measurement.com"   # 0.0.0.0 expected on full-protection servers, not on ctif
TIMEOUT=5
PING_COUNT=10

# Exit codes
EXIT_OK=0; EXIT_FAIL=1; EXIT_USAGE=2; EXIT_DEPS=3

# ---------------------------------------------------------------------------

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; B=$'\033[1m'; N=$'\033[0m'
else
  G=""; R=""; Y=""; B=""; N=""
fi

usage() {
  cat <<EOF
hagezi-dns-check.sh $VERSION – test script for HaGeZi DNS

Tests every HaGeZi DNS server over Do53, DoT, DoH and DoQ (IPv4 and IPv6):
resolution, DNSSEC validation, blocking behaviour and ping latency.

Usage: ./hagezi-dns-check.sh [options] [server ...]

Options:
  -4             test IPv4 only
  -6             test IPv6 only
  -v, --verbose  show the result of every single query
  -h, --help     show this help
  -V, --version  show version and license

Servers: root wurzn juuri ctif (default: all)

Exit codes: 0 all passed, 1 at least one check failed,
            2 invalid arguments, 3 missing dependencies

Requires: bash, kdig (Knot DNS utilities), ping (optional, for latency)
Set NO_COLOR=1 to disable colored output.

DoH and DoQ need a recent kdig built with HTTP/2 and QUIC support. Older
distribution builds (e.g. Debian 12, kdig 3.2) may lack QUIC; those tests
are then skipped. Newer packages for Debian/Ubuntu: CZ.NIC repository,
https://pkg.labs.nic.cz/doc/?project=knot-dns
EOF
}

version() {
  cat <<EOF
hagezi-dns-check.sh $VERSION
Copyright (C) 2026 HaGeZi
License GPLv3+: GNU GPL version 3 or later <https://www.gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
EOF
}

install_hint() {
  local id="" like="" cmd=""
  echo "${R}kdig (Knot DNS utilities) is required but not installed.${N}"
  echo
  if [ "$(uname -s)" = Darwin ]; then
    id=macos
  elif [ -r /etc/os-release ]; then
    id=$(. /etc/os-release && echo "${ID:-}")
    like=$(. /etc/os-release && echo "${ID_LIKE:-}")
  fi
  case " $id $like " in
    *" macos "*)                             cmd="brew install knot   (Homebrew: https://brew.sh)" ;;
    *debian*|*ubuntu*|*raspbian*)            cmd="sudo apt install knot-dnsutils" ;;
    *fedora*|*rhel*|*centos*|*rocky*|*alma*) cmd="sudo dnf install knot-utils   (RHEL/Rocky/Alma: enable EPEL first)" ;;
    *arch*|*manjaro*)                        cmd="sudo pacman -S knot" ;;
    *suse*)                                  cmd="sudo zypper install knot" ;;
    *alpine*)                                cmd="sudo apk add knot-utils" ;;
  esac
  if [ -n "$cmd" ]; then
    echo "Install it with:"
    echo "  ${B}$cmd${N}"
  else
    echo "Install the Knot DNS utilities with your package manager, e.g.:"
    echo "  Debian/Ubuntu:  sudo apt install knot-dnsutils"
    echo "  Fedora/RHEL:    sudo dnf install knot-utils"
    echo "  Arch:           sudo pacman -S knot"
    echo "  openSUSE:       sudo zypper install knot"
    echo "  Alpine:         sudo apk add knot-utils"
    echo "  macOS:          brew install knot"
  fi
  echo
  echo "Note: DoH and DoQ need a recent kdig built with HTTP/2 and QUIC support."
  echo "If those tests show SKIP, install a newer kdig:"
  echo "  Debian/Ubuntu:  CZ.NIC repository, https://pkg.labs.nic.cz/doc/?project=knot-dns"
  echo "  Other systems:  https://www.knot-dns.cz/download/"
}

# --- arguments -------------------------------------------------------------

FAMILIES="4 6"; FAMILY_FORCED=0; SELECT=""; VERBOSE=0
for arg in "$@"; do
  case $arg in
    -4) FAMILIES=4; FAMILY_FORCED=1 ;;
    -6) FAMILIES=6; FAMILY_FORCED=1 ;;
    -v|--verbose) VERBOSE=1 ;;
    -h|--help) usage; exit $EXIT_OK ;;
    -V|--version) version; exit $EXIT_OK ;;
    root|wurzn|juuri|ctif) SELECT="$SELECT $arg" ;;
    root.hagezi.org|wurzn.hagezi.org|juuri.hagezi.org|ctif.hagezi.org) SELECT="$SELECT ${arg%%.*}" ;;
    *) echo "Unknown argument: $arg" >&2; echo >&2; usage >&2; exit $EXIT_USAGE ;;
  esac
done

command -v kdig >/dev/null 2>&1 || { install_hint; exit $EXIT_DEPS; }

# --- helpers ---------------------------------------------------------------

# q <proto> <ip> <tls-hostname> <domain> [extra kdig args...]
q() {
  local proto=$1 ip=$2 host=$3 dom=$4; shift 4
  local a=()
  case $proto in
    DoT) a=(+tls) ;;
    DoH) a=(+https=/dns-query) ;;
    DoQ) a=(+quic) ;;
  esac
  # certificate is validated against the system CA store and the server hostname
  [ "$proto" != Do53 ] && a+=(+tls-ca +tls-hostname="$host" +tls-sni="$host")
  # run in a subshell so a kdig crash (e.g. +quic on builds without QUIC) is caught
  local out rc
  out=$( (kdig @"$ip" ${a[@]+"${a[@]}"} +time="$TIMEOUT" +retry=0 "$@" "$dom" A) 2>&1 ); rc=$?
  printf '%s\n' "$out"
  [ $rc -ge 128 ] && echo "kdig crashed (signal $((rc-128)))"
  return 0
}

status()      { grep -m1 -oE 'status: [A-Z]+' <<<"$1" || echo 'no response'; }
first_a()     { awk '/ANSWER SECTION/{f=1;next} f&&NF==0{exit} f&&$4=="A"{print $5;exit}' <<<"$1"; }
ede()         { grep -m1 -oE 'EDE: [0-9]+ \([^)]*\)' <<<"$1"; }
unsupported() { grep -qiE 'invalid parameter|not (compiled|supported|available)|unsupported|kdig crashed' <<<"$1"; }

mark() {
  case $1 in
    1) printf '%s✓%s' "$G" "$N" ;;
    2) printf '%s?%s' "$Y" "$N" ;;
    *) printf '%s✗%s' "$R" "$N" ;;
  esac
}

# trace <label> <kdig output>  -> one line per query in verbose mode
trace() {
  [ "$VERBOSE" = 1 ] || return 0
  local s a e
  s=$(status "$2"); a=$(first_a "$2"); e=$(ede "$2")
  [ -z "$a" ] && a=$(awk 'NF' <<<"$2" | grep -E '^[0-9.]+$' | head -1)   # +short output
  grep -q 'status:' <<<"$2" || s=""                                       # +short has no header
  printf '        %-42s %s%s%s\n' "$1" "${s#status: }" "${a:+ $a}" "${e:+ [$e]}"
}

# ping_avg <ip> <family>  -> prints rounded average in ms, or nothing
ping_avg() {
  local ip=$1 fam=$2 out avg
  local c=()
  command -v ping >/dev/null 2>&1 || return 0
  if [ "$fam" = 6 ]; then
    if command -v ping6 >/dev/null 2>&1; then c=(ping6); else c=(ping -6); fi
  else
    c=(ping)
  fi
  out=$("${c[@]}" -c "$PING_COUNT" -i 0.2 "$ip" 2>&1)
  # retry with the default interval if -i 0.2 was rejected (non-root, BusyBox, ...)
  grep -q 'transmitted' <<<"$out" || out=$("${c[@]}" -c "$PING_COUNT" "$ip" 2>&1)
  avg=$(sed -nE 's#.*min/avg/max[^=]*= *[0-9.]+/([0-9.]+)/.*#\1#p' <<<"$out" | head -1)
  [ -n "$avg" ] && awk -v x="$avg" 'BEGIN{printf "%d", int(x+0.5)}'   # commercial rounding
  return 0
}

has_ipv6() {
  if command -v ip >/dev/null 2>&1; then
    ip -6 route get "$1" >/dev/null 2>&1
  elif command -v route >/dev/null 2>&1; then
    route -n get -inet6 "$1" >/dev/null 2>&1
  else
    return 0
  fi
}

# --- checks ----------------------------------------------------------------

PASS=0; FAIL=0; SKIP=0; WARN=0; RANK=""

# check_proto <proto> <ip> <fqdn> <name>
check_proto() {
  local proto=$1 ip=$2 fqdn=$3 name=$4
  local out first sess d i reason details="" rok=1 dok=1 bok=1 verdict
  local bogus_servfail=0 bogus_open=0

  # first query doubles as connection/TLS test and as first resolution test
  first=$(q "$proto" "$ip" "$fqdn" "${RESOLVE_DOMAINS[0]}")
  if unsupported "$first"; then
    printf '  %-5s %sSKIP%s  not supported by this kdig build\n' "$proto" "$Y" "$N"
    grep -q 'kdig crashed' <<<"$first" && printf '        kdig crashed, update kdig (see --help)\n'
    SKIP=$((SKIP+1)); return
  fi
  if ! grep -q 'status:' <<<"$first"; then
    printf '  %-5s %sFAIL%s  no response (connection failed, timeout or certificate error)\n' "$proto" "$R" "$N"
    reason=$(grep -m1 -iE 'warning|error|fail' <<<"$first")
    [ -z "$reason" ] && reason=$(awk 'NF' <<<"$first" | tail -1)
    [ -n "$reason" ] && printf '        kdig: %s\n' "$reason"
    [ "$proto" = DoQ ] && printf '        (DoQ uses UDP port 853, which some networks block)\n'
    FAIL=$((FAIL+1)); return
  fi
  sess=$(grep -m1 -oE ';; (TLS|HTTP|QUIC) session \([^)]*\)' <<<"$first" | sed -E 's/.*\(([^)]*)\)/\1/')

  # resolution
  for i in "${!RESOLVE_DOMAINS[@]}"; do
    d=${RESOLVE_DOMAINS[$i]}
    if [ "$i" = 0 ]; then out=$first; else out=$(q "$proto" "$ip" "$fqdn" "$d"); fi
    trace "resolve $d" "$out"
    if ! grep -q 'status: NOERROR' <<<"$out" || [ -z "$(first_a "$out")" ]; then
      rok=0; details="$details        resolve $d: $(status "$out")\n"
    fi
  done

  # DNSSEC: signed zone must resolve, bogus zones must be rejected
  out=$(q "$proto" "$ip" "$fqdn" "$DNSSEC_OK")
  trace "dnssec valid $DNSSEC_OK" "$out"
  if ! grep -q 'status: NOERROR' <<<"$out"; then
    dok=0; details="$details        dnssec $DNSSEC_OK (valid): $(status "$out"), expected NOERROR\n"
  fi
  for d in "${DNSSEC_BOGUS[@]}"; do
    out=$(q "$proto" "$ip" "$fqdn" "$d")
    trace "dnssec bogus $d" "$out"
    case $(status "$out") in
      "status: SERVFAIL") bogus_servfail=$((bogus_servfail+1)) ;;
      "status: NOERROR")  bogus_open=$((bogus_open+1))
                          details="$details        dnssec $d (bogus): NOERROR, signature not validated\n" ;;
      *)                  details="$details        dnssec $d (bogus): $(status "$out" | sed "s/status: //"), test domain may no longer exist\n" ;;
    esac
  done
  if [ $bogus_open -gt 0 ]; then dok=0
  elif [ $dok = 1 ] && [ $bogus_servfail -eq 0 ]; then dok=2   # inconclusive
  fi

  # blocking
  out=$(q "$proto" "$ip" "$fqdn" "$BLOCK_DOMAIN" +short)
  trace "block $BLOCK_DOMAIN" "$out"
  if [ "$name" = ctif ]; then
    [[ "$out" == *0.0.0.0* ]] && { bok=0; details="$details        block $BLOCK_DOMAIN: blocked, but ctif is threat-only\n"; }
  else
    [[ "$out" != *0.0.0.0* ]] && { bok=0; details="$details        block $BLOCK_DOMAIN: not blocked\n"; }
  fi

  if [ $rok = 0 ] || [ $dok = 0 ] || [ $bok = 0 ]; then
    verdict="${R}FAIL${N}"; FAIL=$((FAIL+1))
  elif [ $dok = 2 ]; then
    verdict="${Y}WARN${N}"; WARN=$((WARN+1))
  else
    verdict="${G}OK  ${N}"; PASS=$((PASS+1))
  fi

  printf '  %-5s %s  resolve %s  dnssec %s  block %s%s\n' \
    "$proto" "$verdict" "$(mark $rok)" "$(mark $dok)" "$(mark $bok)" "${sess:+   [$sess]}"
  [ -n "$details" ] && printf '%b' "$details"
}

# --- main ------------------------------------------------------------------

if [[ " $FAMILIES " == *" 6 "* ]] && ! has_ipv6 2a01:4f8:c17:1c66::1; then
  if [ $FAMILY_FORCED = 1 ]; then
    echo "${R}IPv6 is not available on this connection.${N}" >&2
    exit $EXIT_FAIL
  fi
  echo "${Y}IPv6 is not available on this connection, skipping IPv6 tests.${N}"
  FAMILIES=4
fi

echo "${B}HaGeZi DNS check $VERSION${N}  ($(kdig -V 2>&1 | head -1))"
echo

while read -r name v4 v6 <&3; do
  [ -z "$name" ] && continue
  if [ -n "$SELECT" ]; then case " $SELECT " in *" $name "*) ;; *) continue ;; esac; fi
  fqdn="$name.hagezi.org"
  for fam in $FAMILIES; do
    if [ "$fam" = 4 ]; then ip=$v4; else ip=$v6; fi
    avg=$(ping_avg "$ip" "$fam")
    if [ -n "$avg" ]; then
      pingtxt="ping avg ${avg} ms"
      RANK="$RANK$avg $fqdn IPv$fam\n"
    else
      pingtxt="ping n/a"
    fi
    echo "${B}== $fqdn${N}  IPv$fam $ip  ($pingtxt)"
    for p in $PROTOCOLS; do check_proto "$p" "$ip" "$fqdn" "$name"; done
    echo
  done
done 3<<<"$SERVERS"

if [ -n "$RANK" ]; then
  echo "${B}Latency (average of $PING_COUNT pings, lowest first):${N}"
  printf '%b' "$RANK" | sed '/^$/d' | sort -n | awk '{printf "  %4d ms  %s %s\n", $1, $2, $3}'
  echo
fi

echo "${B}Result:${N} ${G}$PASS passed${N}, ${R}$FAIL failed${N}, ${Y}$WARN warning(s)${N}, ${Y}$SKIP skipped${N}"
if [ $FAIL -gt 0 ]; then
  echo "A VPN or a router intercepting DNS can cause failures. Need help? support@hagezi.org"
  exit $EXIT_FAIL
fi
exit $EXIT_OK
