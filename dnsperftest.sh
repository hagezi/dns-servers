#!/usr/bin/env bash
set -euo pipefail

command -v bc >/dev/null 2>&1 || {
  echo "error: bc was not found. Please install bc." >&2
  exit 1
}

if command -v drill >/dev/null 2>&1; then
  dig_cmd="drill"
elif command -v dig >/dev/null 2>&1; then
  dig_cmd="dig"
else
  echo "error: dig was not found. Please install dnsutils." >&2
  exit 1
fi

usage() {
  cat <<'EOF2'
Usage:
  dnstest.sh [ipv4|ipv6|all] [table|csv|tsv|json] [--sort fastest|slowest]

Examples:
  dnstest.sh
  dnstest.sh ipv4 table
  dnstest.sh all csv
  dnstest.sh all csv --sort slowest
  dnstest.sh ipv6 json --sort fastest

Defaults:
  mode   = ipv4
  format = table
  sort   = fastest

Notes:
  fastest = lowest average latency first
  slowest = highest average latency first
EOF2
}

PROVIDERSV4="
1.1.1.1#Cloudflare
8.8.8.8#Google
9.9.9.9#Quad9
208.67.222.222#OpenDNS
94.140.14.140#AdGuard-DNS
76.76.2.0#ControlD
188.34.161.210#HaGeZi-Root
159.69.155.94#HaGeZi-Wurzn
162.55.58.40#HaGeZi-CTIF
95.217.163.17#HaGeZi-Juuri
"

PROVIDERSV6="
2606:4700:4700::1111#Cloudflare-v6
2001:4860:4860::8888#Google-v6
2620:fe::fe#Quad9-v6
2620:119:35::35#OpenDNS-v6
2a10:50c0::1:ff#AdGuard-DNS-v6
2606:1a40::#ControlD-v6
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

mode="ipv4"
format="table"
sort_mode="fastest"

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
      [ $# -gt 0 ] || {
        echo "error: --sort requires a value" >&2
        usage
        exit 1
      }
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

hasipv6=""
$dig_cmd +short +tries=1 +time=2 +stats @2a0d:2a00:1::1 www.google.com 2>/dev/null | grep -q "216.239.38.120" && hasipv6="true"

case "$mode" in
  ipv4)
    providerstotest="$PROVIDERSV4"
    ;;
  ipv6)
    [ -n "$hasipv6" ] || {
      echo "error: IPv6 support not found. Unable to do the ipv6 test." >&2
      exit 1
    }
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

totaldomains=0
for d in $DOMAINS2TEST; do
  totaldomains=$((totaldomains + 1))
done

rows=""
for p in $providerstotest; do
  [ -z "$p" ] && continue
  pip=${p%%#*}
  pname=${p##*#}
  [ -z "$pname" ] && pname="$pip"

  ftime=0
  row="$pname"

  for d in $DOMAINS2TEST; do
    ttime=$($dig_cmd +tries=1 +time=2 +stats @"$pip" "$d" 2>/dev/null | awk '/Query time:/ {print $4; exit}')

    if [ -z "${ttime:-}" ]; then
      ttime=1000
    elif [ "$ttime" = "0" ]; then
      ttime=1
    fi

    row="${row}|${ttime}"
    ftime=$((ftime + ttime))
  done

  avg=$(bc -l <<< "scale=2; $ftime/$totaldomains")
  row="${row}|${avg}"

  if [ -z "$rows" ]; then
    rows="$row"
  else
    rows="${rows}"$'\n'"$row"
  fi
done

sort_rows() {
  case "$sort_mode" in
    fastest)
      printf '%s\n' "$rows" | sort -t '|' -k"$((totaldomains + 2))","$((totaldomains + 2))"n
      ;;
    slowest)
      printf '%s\n' "$rows" | sort -t '|' -k"$((totaldomains + 2))","$((totaldomains + 2))"nr
      ;;
  esac
}

print_table() {
  printf "%-21s" ""
  i=1
  while [ "$i" -le "$totaldomains" ]; do
    printf "%-10s" "Test$i"
    i=$((i + 1))
  done
  printf "%-10s\n" "Average"

  while IFS= read -r row; do
    [ -z "$row" ] && continue
    IFS='|' read -r -a parts <<< "$row"

    printf "%-21s" "${parts[0]}"
    i=1
    while [ "$i" -le "$totaldomains" ]; do
      printf "%-10s" "${parts[$i]}ms"
      i=$((i + 1))
    done
    printf "%s\n" "${parts[$((totaldomains + 1))]}"
  done < <(sort_rows)
}

print_csv() {
  printf "provider"
  i=1
  while [ "$i" -le "$totaldomains" ]; do
    printf ",test%s" "$i"
    i=$((i + 1))
  done
  printf ",average\n"

  while IFS= read -r row; do
    [ -z "$row" ] && continue
    printf "%s\n" "${row//|/,}"
  done < <(sort_rows)
}

print_tsv() {
  printf "provider"
  i=1
  while [ "$i" -le "$totaldomains" ]; do
    printf "\ttest%s" "$i"
    i=$((i + 1))
  done
  printf "\taverage\n"

  while IFS= read -r row; do
    [ -z "$row" ] && continue
    printf "%s\n" "$(printf '%s' "$row" | tr '|' '\t')"
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

    printf '  {"provider":"%s","results":[' "${parts[0]}"
    i=1
    while [ "$i" -le "$totaldomains" ]; do
      [ "$i" -eq 1 ] || printf ','
      printf '%s' "${parts[$i]}"
      i=$((i + 1))
    done
    printf '],"average":"%s"}' "${parts[$((totaldomains + 1))]}"
  done < <(sort_rows)

  printf '\n]\n'
}

case "$format" in
  table) print_table ;;
  csv)   print_csv ;;
  tsv)   print_tsv ;;
  json)  print_json ;;
esac

exit 0
