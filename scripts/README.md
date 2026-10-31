# HaGeZi DNS: Test Scripts

Small tools to measure how fast HaGeZi DNS (and other public resolvers) answer from **your** connection. Results depend on your location, ISP routing, and network, so measure yourself before picking a server.

| Script | Platform | Protocols | Compares |
|---|---|---|---|
| [`dnsperftest.sh`](dnsperftest.sh) | Linux, macOS, BSD (bash) | Do53 (UDP/53) | 13 public resolvers side by side |
| [`dnsperftest.ps1`](dnsperftest.ps1) | Windows (PowerShell 5.1+ / 7) | Do53 (UDP/53) | 13 public resolvers side by side |
| [`encdnsperftest.py`](encdnsperftest.py) | Any OS with Python 3.10+ | Do53, DoT, DoH, DoH3, DoQ | One resolver, protocol by protocol |

> [!NOTE]
> The resolver comparison scripts only test plain, unencrypted DNS. To see how a server performs over the encrypted protocols you will actually use, run `encdnsperftest.py`.

## dnsperftest.sh / dnsperftest.ps1

Queries 10 popular domains against Cloudflare, Google, Quad9, OpenDNS, DNS4EU, AdGuard DNS, ControlD, DNSForge, and all four HaGeZi DNS servers, then prints one row per resolver with the latency per domain and an overall average, sorted fastest first.

**Requirements:** `dig` (package `dnsutils` / `bind-tools`) or `drill` (`ldns-utils`) for the shell script; nothing extra for PowerShell.

```sh
./dnsperftest.sh                        # IPv4, table
./dnsperftest.sh all --repeat 3         # IPv4 + IPv6, 3 passes
./dnsperftest.sh ipv4 csv > results.csv
```

```powershell
.\dnsperftest.ps1
.\dnsperftest.ps1 all -Repeat 3
.\dnsperftest.ps1 ipv4 json -Sort slowest
```

If Windows blocks the script, run it once with `powershell -ExecutionPolicy Bypass -File .\dnsperftest.ps1`.

| Option | Values | Default |
|---|---|---|
| Mode | `ipv4`, `ipv6`, `all` | `ipv4` |
| Format | `table`, `csv`, `tsv`, `json` | `table` |
| `--sort` / `-Sort` | `fastest`, `slowest` | `fastest` |
| `--repeat N` / `-Repeat N` | full passes over all domains and resolvers | `1` |
| `--timeout S` / `-Timeout S` | per-query timeout in seconds | `1` |

Queries are interleaved (domain 1 against every resolver, then domain 2, …), so no single resolver is hit with a burst and every resolver is measured under the same network conditions. In table output, values are colored green (≤ 25 ms), yellow (≤ 50 ms), orange (≤ 100 ms), and red (above). `error` means no usable answer, `timeout` means no answer in time.

Exit codes: `0` at least one resolver answered, `1` invalid usage or missing dependency, `2` every resolver failed.

## encdnsperftest.py

Tests one resolver over one or more protocols. For the encrypted protocols, a single connection is opened, warmed up, and kept alive for the whole run, so you measure query latency rather than repeated TLS/QUIC handshakes, which is what a real client does too. At the end it prints a summary (min, max, average, median, P95, P99, jitter, error rate) and a plain-language rating per protocol.

**Requirements:**

```sh
pip install "dnspython>=2.8" "httpcore>=1.0.0" "httpx[http2]>=0.28.0" "h2>=4.2.0" "aioquic>=0.9"
```

`aioquic` is only needed for DoQ and DoH3. If DoH fails with `'_HTTPTransport' object has no attribute '_pool'`, upgrade `h2` to 4.2.0 or later.

**Example** (HaGeZi `root`, all protocols, 20 rounds, ranked recommendation):

```sh
python3 encdnsperftest.py --proto do53,dot,doh,doh3,doq \
    --server 188.34.161.210 --hostname root.hagezi.org \
    --loop --max-rounds 20 --recommend \
    google.com wikipedia.org example.com
```

For the other servers, swap in the matching IP and hostname from the [server table](../README.md#server-locations).

| Option | Purpose |
|---|---|
| `--proto` | Comma-separated: `do53`, `dot`, `doh`, `doh3`, `doq` (required) |
| `--server`, `--hostname` | Resolver IP and its TLS hostname (both required, also for `do53`) |
| `--loop`, `--max-rounds N`, `--interval S` | Repeat in rounds (default 10 rounds, 1 s apart; `0` = unlimited) |
| `--quiet-rounds` | One self-updating progress line instead of a table per round |
| `--recommend` | Add a ranked protocol recommendation at the end |
| `--shuffle`, `--seed N` | Randomize query order per round (reproducible with a seed) |
| `--domains-file PATH` | Read domains from a file, one per line |
| `--csv PATH`, `--json PATH` | Export results (JSON includes the summary) |
| `--timeout MS`, `--retries N`, `--rtype TYPE`, `--port`, `--path`, `--no-verify`, `--no-answer`, `--no-warmup` | Fine-tuning; see `--help` |

A query only counts as successful with `NOERROR` and a non-empty answer, so a domain that does not exist shows up as an error. Latency ratings: below 20 ms excellent, 20 to 50 ms very good, 50 to 100 ms OK, 100 to 120 ms average, 120 to 200 ms slow, above that very slow. The recommendation never picks plaintext Do53 over a reasonably fast encrypted protocol.

## Fair use

All HaGeZi DNS servers enforce rate limits. The default settings stay well within them; very high `--repeat` / `--max-rounds` values with short intervals may get throttled and distort the results. Tor exit nodes are blocked entirely, so tests routed through Tor will fail.
