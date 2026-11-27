# HaGeZi DNS: Test Scripts

Small tools to check that HaGeZi DNS works from your connection and to measure how fast it and other public resolvers answer. The results depend on your location, your ISP's routing, and your network, so measure for yourself before you pick a server.

| Script | Platform | Protocols | Purpose |
|---|---|---|---|
| [`hagezi-dns-check.sh`](hagezi-dns-check.sh) | Linux, macOS, BSD (bash) | Do53, DoT, DoH, DoQ | Function check of all four HaGeZi DNS servers |
| [`hagezi-dns-check.ps1`](hagezi-dns-check.ps1) | Windows (PowerShell 5.1+ / 7) | Do53, DoT, DoH, DoQ | Function check of all four HaGeZi DNS servers |
| [`dnsperftest.sh`](dnsperftest.sh) | Linux, macOS, BSD (bash) | Do53 (UDP/53) | Latency of 13 public resolvers side by side |
| [`dnsperftest.ps1`](dnsperftest.ps1) | Windows (PowerShell 5.1+ / 7) | Do53 (UDP/53) | Latency of 13 public resolvers side by side |
| [`encdnsperftest.py`](encdnsperftest.py) | Any OS with Python 3.10+ | Do53, DoT, DoH, DoH3, DoQ | Latency of one resolver, protocol by protocol |

> [!TIP]
> Something not working? Start with `hagezi-dns-check.sh` (or `hagezi-dns-check.ps1` on Windows). It shows which server, protocol, or IP version fails, and support will ask for its output.

> [!NOTE]
> The resolver comparison scripts only test plain, unencrypted DNS. To see how a server performs over the encrypted protocols you actually use, run `encdnsperftest.py`.

## hagezi-dns-check.sh / hagezi-dns-check.ps1

Tests every HaGeZi DNS server (`root`, `wurzn`, `juuri`, `ctif`) over Do53, DoT, DoH, and DoQ, on IPv4 and IPv6. For each combination it checks:

| Check | Passes when |
|---|---|
| Connection | The server answers; for DoT, DoH, and DoQ the TLS certificate must be valid for the server's hostname |
| Resolve | `example.com` and `wikipedia.org` return an A record |
| DNSSEC | A correctly signed zone resolves, and zones with deliberately broken signatures are rejected with `SERVFAIL` |
| Block | A known tracker resolves to `0.0.0.0` on the full-protection servers and is not blocked on `ctif` (threat-only) |

It also pings each server and ends with a latency ranking. Both versions run the same checks and print the same report.

### Linux, macOS, BSD

**Requirements:** `kdig` (Knot DNS utilities). If it is missing, the script prints the install command for your system. `ping` is optional and only used for the latency figures.

```sh
sudo apt install knot-dnsutils   # Debian, Ubuntu, Raspberry Pi OS
brew install knot                # macOS
```

```sh
./hagezi-dns-check.sh            # all servers, IPv4 and IPv6
./hagezi-dns-check.sh root ctif  # selected servers only
./hagezi-dns-check.sh -4 -v      # IPv4 only, show every single query
```

### Windows

**Requirements:** none. The script runs in Windows PowerShell 5.1, which comes with every Windows 10 and 11, and in PowerShell 7. Only DoQ needs more: PowerShell 7.4 or newer on Windows 11 or Server 2022 (see [Updating PowerShell](#updating-powershell)). Without it, DoQ shows `SKIP` and everything else is tested as usual.

```powershell
Unblock-File .\hagezi-dns-check.ps1      # once, after downloading
.\hagezi-dns-check.ps1                   # all servers, IPv4 and IPv6
.\hagezi-dns-check.ps1 root ctif         # selected servers only
.\hagezi-dns-check.ps1 -IPv4 -Verbose    # IPv4 only, show every single query
```

If Windows refuses to start the script, see [Running the PowerShell scripts](#running-the-powershell-scripts).

### Options

| Shell | PowerShell | Purpose |
|---|---|---|
| `root` `wurzn` `juuri` `ctif` | same | Test only these servers (default: all; `root.hagezi.org` etc. also works) |
| `-4` / `-6` | `-IPv4` / `-IPv6` | Test IPv4 or IPv6 only (default: both; IPv6 is skipped automatically if unavailable) |
| `-v`, `--verbose` | `-Verbose` | Show the result of every single query |
| `-h`, `--help` / `-V`, `--version` | `-Help` / `-Version` | Help / version and license |

Set `NO_COLOR=1` for output without colors, for example when saving it to a file (PowerShell: `$env:NO_COLOR = 1`).

### Reading the result

Each line shows `OK`, `FAIL`, `WARN`, or `SKIP` per protocol, followed by ✓/✗ for resolve, DNSSEC, and block, and the negotiated TLS/HTTP/QUIC session. Windows PowerShell 5.1 outside Windows Terminal prints `+`/`x` instead of ✓/✗.

- `WARN`: the DNSSEC test was inconclusive, usually because one of the broken test zones no longer exists.
- `SKIP`: the protocol cannot be tested on your system. In the shell version, your `kdig` build lacks support for it; older distribution packages (for example Debian 12) often lack QUIC, and sometimes HTTP/2. Newer packages for Debian and Ubuntu are available from the [CZ.NIC repository](https://pkg.labs.nic.cz/doc/?project=knot-dns). In the PowerShell version, only DoQ can be skipped (see the requirements above).

The PowerShell version always uses HTTP/1.1 for DoH, while `kdig` uses HTTP/2. Both test the same endpoint.

If a check fails although the servers are up, the usual causes are a VPN or a router that intercepts DNS, or a network that blocks UDP port 853 (DoQ).

Exit codes: `0` all checks passed, `1` at least one check failed, `2` invalid arguments, `3` `kdig` missing (shell version only).

## dnsperftest.sh / dnsperftest.ps1

Queries 10 popular domains against Cloudflare, Google, Quad9 (with and without ECS), OpenDNS, DNS4EU, AdGuard DNS, ControlD, DNSForge, and all four HaGeZi DNS servers. It then prints one row per resolver with the latency per domain and an overall average, fastest first.

**Requirements:** for the shell script, `dig` (package `dnsutils` / `bind-tools`), or `drill` (`ldns-utils`) as a fallback. PowerShell needs nothing extra.

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

If Windows refuses to start the script, see [Running the PowerShell scripts](#running-the-powershell-scripts).

| Option | Values | Default |
|---|---|---|
| Mode | `ipv4`, `ipv6`, `all` | `ipv4` |
| Format | `table`, `csv`, `tsv`, `json` | `table` |
| `--sort` / `-Sort` | `fastest`, `slowest` | `fastest` |
| `--repeat N` / `-Repeat N` | full passes over all domains and resolvers | `1` |
| `--timeout S` / `-Timeout S` | per-query timeout in seconds | `1` |

The queries are interleaved (domain 1 against every resolver, then domain 2, …). No resolver gets a burst of queries, and all of them are measured under the same network conditions. In the table, values are colored on the same scale as the [rating table](../README.md#latency) in the main README: green below 20 ms (excellent), yellow below 50 ms (very good), orange below 100 ms (OK), red below 200 ms (average to slow), and dark red from 200 ms (very slow). `error` means no usable answer, `timeout` means no answer in time.

Exit codes: `0` at least one resolver answered, `1` invalid usage or missing dependency, `2` every resolver failed.

## encdnsperftest.py

Tests one resolver over one or more protocols. For each encrypted protocol it opens a single connection, warms it up, and keeps it open for the whole run, as a real client does. The results therefore show query latency and not repeated TLS/QUIC handshakes. At the end it prints a summary (min, max, average, median, P95, P99, jitter, error rate) and a plain-language rating per protocol.

**Requirements:**

```sh
pip install --upgrade "dnspython[doh,doq]>=2.8"
```

The `doh` and `doq` extras install the packages your dnspython version needs (httpx for 2.8, httpx2 for 2.9 and later), and the script works with both. `doq` (aioquic) is only needed for DoQ and DoH3. If the packages for a protocol are missing, that protocol is skipped with a hint and the run continues.

On Debian or Raspberry Pi OS, where a system-wide `pip install` is blocked, either use a venv or install for your user only with `pip install --user --break-system-packages ...`.

**Example** (HaGeZi `root`, all protocols, 20 rounds, ranked recommendation):

```sh
python3 encdnsperftest.py --proto do53,dot,doh,doh3,doq \
    --server 188.34.161.210 --hostname root.hagezi.org \
    --loop --max-rounds 20 --recommend \
    google.com wikipedia.org example.com
```

For the other servers, use the matching IP and hostname from the [server table](../README.md#server-locations).

| Option | Purpose |
|---|---|
| `--proto` | Comma-separated: `do53`, `dot`, `doh`, `doh3`, `doq` (required) |
| `--server`, `--hostname` | Resolver IP and its TLS hostname (both required, also for `do53`) |
| `--loop`, `--max-rounds N`, `--interval S` | Repeat in rounds (default 10 rounds, 1 s apart; `0` = unlimited) |
| `--quiet-rounds` | One progress line that updates in place instead of a table per round |
| `--recommend` | Add a ranked protocol recommendation at the end |
| `--shuffle`, `--seed N` | Randomize the query order per round (reproducible with a seed) |
| `--domains-file PATH` | Read domains from a file, one per line |
| `--csv PATH`, `--json PATH` | Export results (JSON includes the summary) |
| `--timeout MS`, `--retries N`, `--rtype TYPE`, `--port`, `--path`, `--no-verify`, `--no-answer`, `--no-warmup` | Fine-tuning; see `--help` |

A query only counts as successful with `NOERROR` and a non-empty answer, so a domain that does not exist shows up as an error. Latency ratings: below 20 ms excellent, 20 to 50 ms very good, 50 to 100 ms OK, 100 to 120 ms average, 120 to 200 ms slow, above that very slow. The recommendation never picks plaintext Do53 over an encrypted protocol that is reasonably fast.

## Running the PowerShell scripts

By default, Windows does not run scripts downloaded from the internet. The fix depends on the error message:

| Error message | Cause | Fix |
|---|---|---|
| "… is not digitally signed" / "… ist nicht digital signiert" | The file carries the download mark | Unblock the file once |
| "… running scripts is disabled on this system" / "… die Ausführung von Skripts ist auf diesem System deaktiviert" | Script execution is switched off entirely (Windows default) | Allow scripts for your user once |

**Unblock the file** (recommended). This removes the download mark from the file, and it starts normally afterwards:

```powershell
Unblock-File .\hagezi-dns-check.ps1
Get-ChildItem *.ps1 | Unblock-File     # all scripts in the current folder
```

**Allow scripts for your user.** A one-time, permanent change that only affects your Windows account. `RemoteSigned` runs your own scripts and unblocked downloads, but still refuses downloads you have not unblocked:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

**Without a permanent change**, either for the current PowerShell window only or for a single run:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass      # until the window is closed
powershell -ExecutionPolicy Bypass -File .\hagezi-dns-check.ps1  # one run, Windows PowerShell 5.1
pwsh -ExecutionPolicy Bypass -File .\hagezi-dns-check.ps1        # one run, PowerShell 7
```

On company computers, the execution policy may be enforced by Group Policy. Then none of these work, and only your IT department can help.

### Updating PowerShell

Check your version with:

```powershell
$PSVersionTable.PSVersion
```

Windows ships with **Windows PowerShell 5.1** (`powershell.exe`). It is part of Windows, cannot be updated, and stays installed. The current version is **PowerShell 7** (`pwsh.exe`), which installs alongside it. All scripts run on both; only DoQ in `hagezi-dns-check.ps1` needs PowerShell 7.4 or newer.

Install or update PowerShell 7 with winget:

```powershell
winget install --id Microsoft.PowerShell --source winget   # install
winget upgrade --id Microsoft.PowerShell                   # update an existing installation
```

If `winget` is not found (older Windows 10), install "App Installer" from the Microsoft Store first, or install PowerShell from the Microsoft Store or as an MSI package; see [Installing PowerShell on Windows](https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-windows).

Afterwards, open **PowerShell 7** from the Start menu (or type `pwsh` in any terminal) and run the scripts from there. The plain "Windows PowerShell" entry still starts version 5.1.

## Fair use

All HaGeZi DNS servers enforce rate limits. The default settings of all scripts stay well within them. Very high `--repeat` / `--max-rounds` values with short intervals may get throttled and distort the results. Tor exit nodes are blocked entirely, so tests routed through Tor will fail.

## License

All scripts are free software under the GNU General Public License version 3. `hagezi-dns-check.sh`, `hagezi-dns-check.ps1`, and `encdnsperftest.py` are licensed GPL-3.0-or-later. `dnsperftest.sh` and `dnsperftest.ps1` are based on [dnsperftest](https://github.com/cleanbrowsing/dnsperftest) by CleanBrowsing, which is licensed GPL-3.0-only, so they stay GPL-3.0-only. See the header of each script for details.
