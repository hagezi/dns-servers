#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
#
# encdnsperftest.py - encrypted DNS latency tester
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
"""
encdnsperftest.py

Measures the latency of one DNS resolver over classic unencrypted DNS
(Do53), DNS-over-TLS (DoT), DNS-over-HTTPS (DoH), DNS-over-HTTPS/3 (DoH3),
and DNS-over-QUIC (DoQ), using dnspython. For each encrypted protocol, one
connection is opened and kept alive for the whole run, so the TLS/QUIC
handshake happens once and not on every query. Do53 (plain UDP) has no
handshake and serves as a plaintext baseline.

Some public resolvers close long-lived TLS sessions after a number of
queries or seconds, even while they are in use. If a DoT query fails with
the typical EOF/BAD_LENGTH TLS errors, the script rebuilds the DoT socket
once and retries the query on the new connection, without printing
anything during the rounds. The time spent on the failed attempt and the
new handshake is subtracted from that query's latency, so a reconnect
does not show up as a latency spike. The number of reconnects is shown
in a note below the end-of-run summary.

Each round prints a results table (or, with --quiet-rounds, a single
progress line that updates in place). At the end the script prints a
summary table (min/max/avg/median/P95/P99/jitter per protocol), a table
of the rating criteria, and a plain-language rating per protocol. A
ranked protocol recommendation is added only with --recommend.

Domains can be given as positional arguments, read from a file (one
domain per line, via --domains-file), or both.

--------------------------------------------------------------------------
REQUIREMENTS
--------------------------------------------------------------------------
pip install --upgrade "dnspython[doh,doq]>=2.8"

The "doh" and "doq" extras install the HTTP/QUIC packages the installed
dnspython version expects, so nothing has to be pinned by hand:
- dnspython 2.8.x (Python 3.10+): httpx, httpcore, h2>=4.2.0
- dnspython 2.9+  (Python 3.11+): httpx2, httpcore2, h2>=4.4
  (httpx2 is the Pydantic-maintained continuation of httpx with the same
  API). The script uses whichever library the installed dnspython uses.

- If DoH is reported as disabled, a package needed for DoH is missing or
  too old (typically an h2 installed by the OS). Run the pip command
  above again with --upgrade.
- aioquic ("doq" extra) is needed for doq and doh3.
- do53 and dot need no extra packages.
- A protocol whose connection cannot be set up (missing package, blocked
  port, ...) is skipped with a message; the others are still tested.

Python < 3.10: dnspython 2.8 requires Python 3.10 or newer. Use
  pip install "dnspython[doh,doq]>=2.7,<2.8"

--------------------------------------------------------------------------
PARAMETERS
--------------------------------------------------------------------------
--proto PROTO[,PROTO...]  do53, dot, doh, doh3, doq (comma-separated)
--server IP               resolver IP address
--hostname NAME           TLS/SNI hostname (and DoH/DoH3 URL host)
--port PORT               default: 53/do53, 853/dot+doq, 443/doh+doh3
--path PATH               DoH/DoH3 URL path (default: /dns-query)
--rtype TYPE              record type (default: A)
--timeout MS              per-query timeout in ms (default: 1000)
--shuffle                 randomize the (domain, protocol) query order
--seed N                  seed for --shuffle (reproducible order)
--no-verify               disable TLS certificate verification
--no-warmup               skip the warm-up query (see RETRY LOGIC)
--retries N               extra connection/warm-up attempts (default: 1)
--loop                    repeat all queries in rounds
--interval SECONDS        pause between rounds (default: 1.0)
--max-rounds N            round limit with --loop (default: 10, 0=unlimited)
--quiet-rounds            show one progress line "Round (n/x)" that
                          updates in place instead of a table per round;
                          only works with --loop (see QUIET ROUNDS)
--recommend               add the ranked recommendation (see below)
--csv PATH                write results as CSV (overwritten at the start
                          of a run, then extended after every round)
--json PATH               write results and summary as JSON
--no-answer               hide the Answer column (table/CSV/JSON)
--domains-file PATH       file with one domain per line
domains (positional)      domain names to query

--------------------------------------------------------------------------
RATING
--------------------------------------------------------------------------
Always printed at the end, under the heading "-- Rating --". First comes
the table of rating criteria, so it is clear what "Excellent",
"reliable", or "stable" mean:

Category    Rating                  Criteria
----------- ----------------------- --------------------------------
Latency     Excellent               < 20 ms
Latency     Very good               20-50 ms
Latency     OK                      50-100 ms
Latency     Average                 100-120 ms
Latency     Slow                    120-200 ms
Latency     Very slow / problematic > 200 ms
----------- ----------------------- --------------------------------
Reliability reliable                0% error rate
Reliability mostly reliable         <= 5% error rate
Reliability unreliable              > 5% error rate
Reliability not usable              100% (every query failed)
----------- ----------------------- --------------------------------
Stability   stable                  jitter <= 30% of average latency
Stability   noticeably inconsistent jitter > 30% of average latency

(Latency values are the average latency of successful queries only.)

Then one line per protocol, for example:

DOH   ***** Excellent (15.4 ms average) - reliable, stable
DOH3  ***** Excellent (12.5 ms average) - reliable, stable
DOQ   ***** Excellent (11.3 ms average) - reliable, stable

The table is built from the same constants the classification uses
(RATING_THRESHOLDS_MS, RELIABILITY_MOSTLY_THRESHOLD_PCT,
STABILITY_JITTER_RATIO_THRESHOLD), so the two cannot drift apart. The
latency tiers follow commonly published reference values for DNS
resolution times. The worst tier is shown as "-" instead of stars,
because zero stars would print as an empty field.

--------------------------------------------------------------------------
RANKED RECOMMENDATION (--recommend)
--------------------------------------------------------------------------
Only printed with --recommend. Example:

Ranked Recommendation:

1. DOH3 - Excellent (12.5 ms average). DOH3 runs over port 443/UDP
   like HTTP/3 web traffic, so it is very hard for firewalls to block
   without also breaking normal web browsing; being QUIC-based, it
   also avoids TCP's head-of-line blocking (one lost packet does not
   stall other in-flight queries) and benefits from fast connection
   setup and seamless network switching (e.g. Wi-Fi to mobile)
   without dropping the connection.
2. DOH - Excellent (15.4 ms average). ...
3. DOQ - Excellent (11.3 ms average). ...

DOH3 is the best overall choice on this resolver, closely followed
by DOH, DOQ.

How the ranking works:
- Every encrypted protocol that is reliable (0% errors), stable, and
  rated Excellent or Very good is listed. Naming a single winner when
  several protocols perform about equally well would wrongly suggest
  that the others are worse.
- If no protocol reaches that bar, the single fastest protocol rated OK
  or Average is named instead (ACCEPTABLE_FALLBACK_RATINGS), as a plain
  sentence rather than a list.
- The list is sorted by performance tier first (Excellent before Very
  good), so a real latency gap always wins. Within a tier, the order
  follows a fixed priority, DoH3 > DoH > DoQ > DoT (PROTOCOL_PRIORITY,
  explained in PROTOCOL_NOTES), and latency only breaks ties:
  * DoH and DoH3 use port 443, like ordinary HTTPS and HTTP/3 traffic,
    so firewalls and censors can hardly block them without breaking
    normal web browsing.
  * DoH3 and DoQ run on QUIC: no transport-level head-of-line blocking,
    fast or 0-RTT reconnection, and connection migration (a connection
    survives a network change, e.g. from Wi-Fi to mobile).
  * DoT and DoQ use the DNS-specific port 853, which a restrictive
    network can identify and block more easily than port 443.
  DoH3 has both advantages (port 443 and QUIC), so it ranks ahead of
  DoH (port 443, but TCP) and DoQ (QUIC, but port 853).
- DO53 (plaintext) is never recommended just for being fastest; a note
  says so when this happens. If no encrypted protocol is usable, DO53 is
  named as a last resort, with a reminder that it offers no privacy or
  protection.

This section covers the whole run (all rounds), is printed to the
console only, and is not included in the CSV or JSON export.
--no-answer and --quiet-rounds do not affect it.

--------------------------------------------------------------------------
QUIET ROUNDS (--quiet-rounds)
--------------------------------------------------------------------------
Normally every round prints a "-- Round n --" heading and its results
table. With --quiet-rounds, --loop, and a finite --max-rounds, these are
replaced by one progress line that is overwritten in place (carriage
return "\\r", no newline). A blank line before it separates it from the
setup messages:

[DOT] Warm-up done in 13.5 ms (connection is now warm and reused for all following queries)

Round (274/500)

When the loop ends (--max-rounds reached or Ctrl+C), a newline is
written so the summary starts on its own line.

Only the console output changes. CSV and JSON export, the summary, the
DoT reconnect count, the rating, and the recommendation still use every
round's data. Without --loop, or with --max-rounds 0 (no known total),
--quiet-rounds has no effect, because there is no "n/total" to show.

--------------------------------------------------------------------------
JSON EXPORT (--json)
--------------------------------------------------------------------------
Writes {"meta": {...}, "rounds": [{"round": N, "results": [...]}], "summary": [...]}.
The column names in "rounds"[i]["results"] match the table and CSV
(respecting --no-answer). "summary" holds the same figures as the summary
table as numbers, or null if a protocol had no successful queries. The
file is rewritten after every round, so an interrupted run still leaves
valid JSON on disk, and once more at the end with "summary" added. This
happens with or without --quiet-rounds.

--------------------------------------------------------------------------
RANDOM QUERY ORDER (--shuffle)
--------------------------------------------------------------------------
By default each round queries all protocols for domain 1, then all
protocols for domain 2, and so on, in the same order every round.
--shuffle randomizes the (domain, protocol) order in every round (the
same order each run if --seed is given), which is closer to mixed
real-world traffic and cache behavior. Only the order changes. With
--shuffle, the separator line between domains in the round table
appears much more often; that is expected.

--------------------------------------------------------------------------
QUERY TIMEOUT
--------------------------------------------------------------------------
--timeout (default 1000 ms) limits every single query, including the
warm-up query, through the timeout= parameter of dns.query.udp/tls/
https/quic. A query that takes longer is reported with status "ERROR"
instead of stalling the run. The timeout does not cover connection setup
(the TCP/TLS/QUIC handshake in setup_protocol); a handshake that hangs is
handled by the retry logic, which gives up after --retries attempts.

--------------------------------------------------------------------------
END-OF-RUN SUMMARY
--------------------------------------------------------------------------
-- Summary: Errors & Performance per Protocol --

Protocol Queries Errors Error Rate Min (ms) Max (ms) Avg (ms) Median (ms) P95 (ms) P99 (ms) Jitter (ms)
-------- ------- ------ ---------- -------- -------- -------- ----------- -------- -------- -----------
DO53     10      10     100.0%     -        -        -        -           -        -        -
DOH      10      0      0.0%       13.5     17.9     15.4     15.1        17.5     17.9     1.3
DOH3     10      0      0.0%       11.6     14.0     12.5     12.4        13.8     14.0     0.7
DOT      10      2      20.0%      9.9      14.5     12.3     12.0        14.2     14.5     1.6
DOQ      10      0      0.0%       10.5     12.0     11.3     11.2        11.9     12.0     0.5

Min/Max/Avg/Median/P95/P99/Jitter only use successful ("OK") queries.
The median is less affected by outliers than the average; P95 and P99
show the near-worst case better than a single maximum; jitter
(population standard deviation) shows how consistent the latency is. A
protocol without successful queries shows "-" (null in JSON), not 0.

Below the table, a note shows how many DoT reconnects were needed, e.g.:

Note: DoT performed 3 transparent reconnect(s) due to TLS EOF/BAD_LENGTH
errors during this run.

--------------------------------------------------------------------------
RETRY LOGIC
--------------------------------------------------------------------------
For DoT, DoH, DoH3, and DoQ, connection setup and warm-up query are
retried together: build the connection, send the warm-up query (limited
by --timeout), and on failure print a message and start over, up to
--retries more times. If all attempts fail, the run continues anyway and
the rows for that protocol will most likely show ERROR. All of these
messages are printed before the first round. Do53 has no connection to
retry.

In addition, each DoT query has the one-time reconnect described at the
top: on a TLS EOF/BAD_LENGTH error mid-run (e.g. because the resolver
closed the session), the old socket is closed, a new TLS connection is
built without console output, and the query is retried once before an
error is reported. If rebuilding the connection fails, the next DoT
query tries to reconnect first, so dnspython does not quietly open a
new, uncounted connection for every query. Only the initial DoT setup
is logged; reconnects during the rounds are only counted (DOT_RECONNECTS).

--------------------------------------------------------------------------
STATUS / ERROR DETECTION
--------------------------------------------------------------------------
"OK" requires: no timeout, RCODE NOERROR (otherwise ERROR with
"RCODE=<code>"), and a non-empty answer section (otherwise ERROR with
"NODATA (empty answer section)").

--------------------------------------------------------------------------
Do53 / DoH3 NOTES
--------------------------------------------------------------------------
Do53 (plain UDP, port 53) has no handshake or retry logic and only serves
as a plaintext baseline. dnspython implements DoH3 on the same QUIC code
as DoQ (dns.quic), not on httpx/httpx2, which have no HTTP/3 support:
dns.query.https(..., http_version=dns.query.HTTPVersion.HTTP_3) with a
persistent dns.quic.SyncQuicConnection (h3=True) as the session.

--------------------------------------------------------------------------
WARM-UP QUERY AND TWO DoH FIXES
--------------------------------------------------------------------------
httpx/httpx2 (used for DoH) only opens its TCP/TLS/HTTP2 connection with
the first real request. The warm-up query makes that happen before the
measured rounds start. Two fixes apply to DoH only:
1. TCP_NODELAY: dnspython's bootstrap_address network backend never
   turns off Nagle's algorithm. _NoDelayNetworkBackend does.
2. Idle keep-alive: the client's default keepalive_expiry of 5.0 s could
   close the DoH connection between rounds. Limits(keepalive_expiry=None)
   is passed to the transport itself, because httpx/httpx2 ignore
   Client(limits=...) once a custom transport is set.

--------------------------------------------------------------------------
INTERRUPTING A RUN (Ctrl+C)
--------------------------------------------------------------------------
Ctrl+C during the rounds stops the loop cleanly. The round in progress is
discarded; the summary, the rating, and (with --json) the final JSON file
with "summary" are still produced from all completed rounds. Ctrl+C
during connection setup aborts at once.

--------------------------------------------------------------------------
EXAMPLES
--------------------------------------------------------------------------
# Single pass (no --loop): query once and print the results and rating
python3 encdnsperftest.py --proto do53,dot,doh --server 203.0.113.53 \
    --hostname resolver.example example.com google.com

# 20 rounds with the ranked recommendation
python3 encdnsperftest.py --proto do53,dot,doh,doh3,doq --server 203.0.113.53 \
    --hostname resolver.example --recommend --loop --max-rounds 20 \
    example.com google.com

# Long run with a single progress line instead of a table per round
python3 encdnsperftest.py --proto do53,dot,doh --server 203.0.113.53 \
    --hostname resolver.example --loop --max-rounds 500 --interval 0.10 \
    --shuffle --quiet-rounds example.com google.com facebook.com

# Export results and the final summary to JSON
python3 encdnsperftest.py --proto do53,dot,doh,doh3,doq --server 203.0.113.53 \
    --hostname resolver.example --loop --max-rounds 20 --json results.json \
    example.com google.com

# Also write every round's results to a CSV file
python3 encdnsperftest.py --proto do53,doh --server 203.0.113.53 \
    --hostname resolver.example --loop --max-rounds 20 --csv results.csv \
    example.com google.com

# Shuffled but reproducible query order (same seed -> same order)
python3 encdnsperftest.py --proto do53,dot,doh,doh3,doq --server 203.0.113.53 \
    --hostname resolver.example --shuffle --seed 42 --loop --max-rounds 20 \
    example.com google.com facebook.com wikipedia.org

# Read the domains from a file (can be combined with positional domains)
python3 encdnsperftest.py --proto do53,doh --server 203.0.113.53 \
    --hostname resolver.example --domains-file domains.txt --loop \
    --max-rounds 10

# AAAA records on a non-standard DoT port, without certificate
# verification (e.g. a resolver with a self-signed certificate)
python3 encdnsperftest.py --proto dot --server 203.0.113.53 \
    --hostname resolver.example --port 8853 --rtype AAAA --no-verify \
    example.com

# Narrower table without the Answer column
python3 encdnsperftest.py --proto do53,doh --server 203.0.113.53 \
    --hostname resolver.example --no-answer --loop --max-rounds 10 \
    example.com google.com

# Slow or distant resolver: longer per-query timeout and more
# setup/warm-up attempts
python3 encdnsperftest.py --proto dot,doh3 --server 203.0.113.53 \
    --hostname resolver.example --timeout 3000 --retries 3 example.com
"""

import argparse
import csv
import json
import math
import random
import socket
import ssl
import statistics
import sys
import textwrap
import time
from contextlib import ExitStack
from datetime import datetime, timezone

import dns.message
import dns.query
import dns.rcode
import dns.version

DOT_RECONNECTS = 0


def build_tls_socket(server: str, port: int, hostname: str, verify: bool):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((server, port))
    raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return ctx.wrap_socket(raw, server_hostname=hostname)


class _NoDelayNetworkBackend:
    """Wraps the httpx/httpcore network backend so that TCP_NODELAY is set
    on every connection it opens (see WARM-UP QUERY AND TWO DoH FIXES in
    the module docstring)."""

    def __init__(self, inner):
        self._inner = inner

    def _disable_nagle(self, stream):
        sock = None
        try:
            sock = stream.get_extra_info("socket")
        except Exception:
            pass
        if sock is None:
            sock = getattr(stream, "_sock", None)
        if sock is not None:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass

    def connect_tcp(self, *args, **kwargs):
        stream = self._inner.connect_tcp(*args, **kwargs)
        self._disable_nagle(stream)
        return stream

    def connect_unix_socket(self, *args, **kwargs):
        return self._inner.connect_unix_socket(*args, **kwargs)


def build_persistent_doh_session(server: str, hostname: str, verify: bool):
    """Build an HTTP client session that connects to `server` (IP), checks
    TLS SNI and the certificate against `hostname`, and stays open across
    many dns.query.https() calls. Uses dnspython's internal
    dns.query._HTTPTransport, wraps its network backend with
    _NoDelayNetworkBackend, and turns off the idle keep-alive expiry.

    dnspython 2.8 builds DoH on httpx, 2.9+ on httpx2 (same API). The
    session must come from the library dnspython itself uses, so it is
    taken from dns.query instead of being imported separately."""
    httpx = getattr(dns.query, "httpx2", None) or getattr(dns.query, "httpx", None)
    if httpx is None:
        raise RuntimeError("dnspython provides no HTTP client library for DoH")

    # httpx/httpx2 ignore Client(limits=...) when a custom transport is
    # given, so the keep-alive setting has to be passed to the transport.
    limits = httpx.Limits(keepalive_expiry=None)
    transport = dns.query._HTTPTransport(  # noqa: SLF001 - intentional use of dnspython internal
        http1=True, http2=True, verify=verify, bootstrap_address=server, limits=limits,
    )
    pool = transport._pool  # noqa: SLF001
    pool._network_backend = _NoDelayNetworkBackend(pool._network_backend)  # noqa: SLF001
    # In case a future dnspython stops passing limits= on to the pool.
    if hasattr(pool, "_keepalive_expiry"):
        pool._keepalive_expiry = None  # noqa: SLF001
    return httpx.Client(http1=True, http2=True, verify=verify, transport=transport)


def print_table(rows, headers, group_col=None):
    """Print a simple aligned ASCII table without external dependencies.
    If group_col is given, a separator line is printed whenever that
    column's value changes between rows. The separator spans all columns
    as one continuous line."""
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))

    def fmt_row(cells):
        return " ".join(str(c).ljust(widths[i]) for i, c in enumerate(cells))

    sep = " ".join("-" * w for w in widths)
    print(fmt_row(headers))
    print(sep)
    prev_key = None
    for row in rows:
        if group_col is not None and prev_key is not None and row[group_col] != prev_key:
            print(sep)
        print(fmt_row(row))
        prev_key = row[group_col] if group_col is not None else None


def compute_table_width(rows, headers):
    """Return the total width print_table would use, so other output can
    be wrapped to the same width."""
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    return sum(widths) + (len(widths) - 1)  # single-space separator, as in print_table


def write_csv(path, rows, headers, append):
    mode = "a" if append else "w"
    write_header = not append
    with open(path, mode, newline="") as f:
        writer = csv.writer(f)
        if write_header:
            writer.writerow(headers)
        writer.writerows(rows)


def rows_to_dicts(rows, headers):
    return [dict(zip(headers, row)) for row in rows]


def write_json(path, meta, rounds_data, summary=None):
    """Rewrite the JSON export file (after every round, and once more at
    the end with `summary`), so an interrupted run still leaves valid
    JSON on disk."""
    data = {"meta": meta, "rounds": rounds_data}
    if summary is not None:
        data["summary"] = summary
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


HEADERS_FULL = ["Protocol", "Domain", "Type", "Latency (ms)", "Status", "Answer"]
DOMAIN_COL = HEADERS_FULL.index("Domain")
LATENCY_COL = HEADERS_FULL.index("Latency (ms)")
STATUS_COL = HEADERS_FULL.index("Status")
PROTOCOL_COL = HEADERS_FULL.index("Protocol")


def _take_overhead_ms(query_fn):
    """Return and reset the time (ms) query_fn spent on work outside the
    query itself (currently only DoT reconnects), so it can be subtracted
    from the measured latency."""
    overhead = getattr(query_fn, "overhead_ms", 0.0)
    if overhead:
        query_fn.overhead_ms = 0.0
    return overhead


def query_and_collect(proto, name, rtype, query_fn):
    q = dns.message.make_query(name, rtype)
    start = time.perf_counter()
    try:
        resp = query_fn(q)
        dt = (time.perf_counter() - start) * 1000 - _take_overhead_ms(query_fn)

        rcode = resp.rcode()
        if rcode != dns.rcode.NOERROR:
            return [proto.upper(), name, rtype, f"{dt:.1f}", "ERROR",
                    f"RCODE={dns.rcode.to_text(rcode)}"]

        if not resp.answer:
            return [proto.upper(), name, rtype, f"{dt:.1f}", "ERROR",
                    "NODATA (empty answer section)"]

        answers = ", ".join(str(r) for rrset in resp.answer for r in rrset)
        return [proto.upper(), name, rtype, f"{dt:.1f}", "OK", answers]
    except Exception as e:
        dt = (time.perf_counter() - start) * 1000 - _take_overhead_ms(query_fn)
        return [proto.upper(), name, rtype, f"{dt:.1f}", "ERROR", str(e)]


def do_warmup(query_fn, domain, rtype, label):
    """Send one throwaway query so the connection actually opens. Raises
    on failure, so setup_protocol can decide whether to retry."""
    print(f"{label} Sending warm-up query ({domain}) to force the connection open ...")
    q = dns.message.make_query(domain, rtype)
    t0 = time.perf_counter()
    try:
        query_fn(q)
    finally:
        _take_overhead_ms(query_fn)
    print(f"{label} Warm-up done in {(time.perf_counter()-t0)*1000:.1f} ms "
          f"(connection is now warm and reused for all following queries)")


def setup_protocol(proto, args, stack, warm_domain):
    """Build the connection or session for `proto` and, unless
    --no-warmup is set, send a warm-up query. On failure, the whole setup
    (connection and warm-up) starts over, up to args.retries more times."""
    label = f"[{proto.upper()}]"
    max_attempts = args.retries + 1
    last_exc = None

    for attempt in range(1, max_attempts + 1):
        try:
            query_fn = SETUP_FUNCS[proto](args, stack)
        except Exception as e:
            last_exc = e
            print(f"{label} Connection setup failed (attempt {attempt}/{max_attempts}): {e}")
            if attempt < max_attempts:
                print(f"{label} Retrying connection setup (attempt {attempt + 1}/{max_attempts}) ...")
                continue
            raise

        if proto == "do53" or args.no_warmup:
            return query_fn

        try:
            do_warmup(query_fn, warm_domain, args.rtype, label)
            return query_fn
        except Exception as e:
            last_exc = e
            print(f"{label} Warm-up failed (attempt {attempt}/{max_attempts}): {e}")
            if attempt < max_attempts:
                print(f"{label} Retrying connection setup + warm-up "
                      f"(attempt {attempt + 1}/{max_attempts}) ...")
                continue
            print(f"{label} Warm-up still failing after {max_attempts} attempt(s); "
                  f"continuing anyway (queries for this protocol will likely show ERROR).")
            return query_fn

    raise last_exc  # pragma: no cover - unreachable, kept for safety


def setup_do53(args, stack):
    port = args.port or 53
    timeout = args.timeout / 1000.0
    print(f"[DO53] Using plain UDP DNS to {args.server}:{port} (no encryption, "
          f"no handshake -- classic Do53).")

    def query_fn(q):
        return dns.query.udp(q, args.server, port=port, timeout=timeout)

    return query_fn


def setup_dot(args, stack):
    """Set up a persistent DoT connection. Some resolvers close long-lived
    TLS sessions (EOF/BAD_LENGTH); the returned query_fn then rebuilds the
    TLS socket once, without console output, and retries the query on the
    new connection before reporting an error. Only the initial connection
    below is logged (see RETRY LOGIC in the module docstring). The initial
    setup itself is retried by setup_protocol according to --retries."""
    global DOT_RECONNECTS
    port = args.port or 853
    timeout = args.timeout / 1000.0

    def make_sock(log: bool):
        if log:
            print(f"[DOT] Connecting to {args.server}:{port} (SNI={args.hostname}) ...")
        t0 = time.perf_counter()
        s = build_tls_socket(args.server, port, args.hostname, not args.no_verify)
        if log:
            print(f"[DOT] TLS handshake completed in {time.perf_counter()-t0:.3f}s (cipher: {s.cipher()})")
        return s

    # Initial connection: logged once, before the first round.
    sock = make_sock(log=True)

    def close_sock():
        nonlocal sock
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
            sock = None

    stack.callback(close_sock)

    def reconnect():
        """Rebuild the TLS socket without output (counted, not logged)."""
        nonlocal sock
        global DOT_RECONNECTS
        close_sock()
        sock = make_sock(log=False)
        DOT_RECONNECTS += 1

    def query_fn(q):
        t_start = time.perf_counter()

        def _do_query():
            return dns.query.tls(q, args.server, port=port, sock=sock, timeout=timeout)

        if sock is None:
            # A previous reconnect failed: try again first instead of letting
            # dnspython silently open a new connection for every query.
            reconnect()
            query_fn.overhead_ms = (time.perf_counter() - t_start) * 1000
            return _do_query()

        try:
            return _do_query()
        except Exception as e:
            msg = str(e)
            if not ("EOF" in msg or "connection has been closed" in msg
                    or "BAD_LENGTH" in msg):
                raise
            # Reconnect without console output; only counted in
            # DOT_RECONNECTS (see the note after the summary). The time spent
            # on the failed attempt and the new handshake is subtracted from
            # the measured latency via overhead_ms.
            reconnect()
            query_fn.overhead_ms = (time.perf_counter() - t_start) * 1000
            return _do_query()

    query_fn.overhead_ms = 0.0
    return query_fn


def setup_doh(args, stack):
    if not getattr(dns.query, "have_doh", True):
        raise RuntimeError(
            f"dnspython {dns.version.version} has DoH support disabled because a "
            "package it requires for DoH is missing or too old (often an "
            "OS-provided h2). "
            'Fix: pip install --upgrade "dnspython[doh,doq]"')
    url = f"https://{args.hostname}{args.path}"
    timeout = args.timeout / 1000.0
    print(f"[DOH] Creating persistent HTTP/2 client session, connecting to "
          f"{args.server} (URL={url}) ...")
    session = build_persistent_doh_session(args.server, args.hostname, not args.no_verify)
    stack.callback(session.close)

    def query_fn(q):
        return dns.query.https(q, url, session=session, timeout=timeout)

    return query_fn


def setup_doh3(args, stack):
    import dns.quic
    port = args.port or 443
    timeout = args.timeout / 1000.0
    url = f"https://{args.hostname}{args.path}"
    print(f"[DOH3] Establishing QUIC/HTTP-3 connection to {args.server}:{port} "
          f"(hostname={args.hostname}, URL={url}) ...")
    manager = dns.quic.SyncQuicManager(
        verify_mode=ssl.CERT_NONE if args.no_verify else ssl.CERT_REQUIRED,
        server_name=args.hostname, h3=True
    )
    stack.enter_context(manager)
    t0 = time.perf_counter()
    connection = manager.connect(args.server, port)
    print(f"[DOH3] Connection established in {time.perf_counter()-t0:.3f}s")

    def query_fn(q):
        return dns.query.https(
            q, url, port=port, session=connection,
            bootstrap_address=args.server,
            http_version=dns.query.HTTPVersion.HTTP_3,
            timeout=timeout,
        )

    return query_fn


def setup_doq(args, stack):
    import dns.quic
    port = args.port or 853
    timeout = args.timeout / 1000.0
    print(f"[DOQ] Establishing QUIC connection to {args.server}:{port} "
          f"(hostname={args.hostname}) ...")
    manager = dns.quic.SyncQuicManager(
        verify_mode=ssl.CERT_NONE if args.no_verify else ssl.CERT_REQUIRED,
        server_name=args.hostname
    )
    stack.enter_context(manager)
    t0 = time.perf_counter()
    connection = manager.connect(args.server, port)
    print(f"[DOQ] QUIC connection established in {time.perf_counter()-t0:.3f}s")

    def query_fn(q):
        return dns.query.quic(q, args.server, connection=connection, timeout=timeout)

    return query_fn


SETUP_FUNCS = {
    "do53": setup_do53,
    "dot": setup_dot,
    "doh": setup_doh,
    "doh3": setup_doh3,
    "doq": setup_doq,
}


def load_domains(args):
    domains = list(args.domains or [])
    if args.domains_file:
        with open(args.domains_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    domains.append(line)
    if not domains:
        sys.exit("No domains given: pass at least one domain argument or use --domains-file")
    return domains


def run_round(domains, protocols, query_fns, rtype, shuffle=False, rng=None):
    """Run one round: every domain against every protocol, in domain order
    by default. With shuffle=True, the list of (domain, protocol) pairs is
    shuffled with `rng`."""
    pairs = [(name, proto) for name in domains for proto in protocols]
    if shuffle:
        rng.shuffle(pairs)
    rows = []
    for name, proto in pairs:
        rows.append(query_and_collect(proto, name, rtype, query_fns[proto]))
    return rows


def _percentile(sorted_vals, pct):
    """Percentile with linear interpolation (numpy's default method).
    `sorted_vals` must be sorted ascending and not empty."""
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    k = (len(sorted_vals) - 1) * (pct / 100)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_vals[int(k)]
    d0 = sorted_vals[int(f)] * (c - k)
    d1 = sorted_vals[int(c)] * (k - f)
    return d0 + d1


def compute_protocol_stats(all_rows, protocols):
    """Compute queries, errors, error rate, and latency statistics
    (min/max/avg/median/P95/P99/jitter, from "OK" queries only) per
    protocol. Returns a list of dicts with numbers or None."""
    stats = {proto.upper(): {"total": 0, "errors": 0, "latencies": []} for proto in protocols}
    for row in all_rows:
        key = row[PROTOCOL_COL]
        if key not in stats:
            continue
        stats[key]["total"] += 1
        if row[STATUS_COL] == "ERROR":
            stats[key]["errors"] += 1
        else:
            try:
                stats[key]["latencies"].append(float(row[LATENCY_COL]))
            except ValueError:
                pass

    results = []
    for proto in protocols:
        key = proto.upper()
        s = stats[key]
        total, errors = s["total"], s["errors"]
        lat = sorted(s["latencies"])
        entry = {
            "protocol": key,
            "queries": total,
            "errors": errors,
            "error_rate_percent": round(errors / total * 100, 1) if total else None,
            "min_ms": round(lat[0], 1) if lat else None,
            "max_ms": round(lat[-1], 1) if lat else None,
            "avg_ms": round(sum(lat) / len(lat), 1) if lat else None,
            "median_ms": round(statistics.median(lat), 1) if lat else None,
            "p95_ms": round(_percentile(lat, 95), 1) if lat else None,
            "p99_ms": round(_percentile(lat, 99), 1) if lat else None,
            "jitter_ms": round(statistics.pstdev(lat), 1) if lat else None,
        }
        results.append(entry)
    return results


SUMMARY_HEADERS = ["Protocol", "Queries", "Errors", "Error Rate",
                   "Min (ms)", "Max (ms)", "Avg (ms)", "Median (ms)",
                   "P95 (ms)", "P99 (ms)", "Jitter (ms)"]


def print_summary(stats):
    """Print the end-of-run summary table and the note on DoT reconnects.
    Returns the printed width of the table, so later output can be
    wrapped to match."""

    def fmt(v):
        return f"{v:.1f}" if v is not None else "-"

    summary_rows = []
    for s in stats:
        rate = f"{s['error_rate_percent']:.1f}%" if s["error_rate_percent"] is not None else "-"
        summary_rows.append([
            s["protocol"], str(s["queries"]), str(s["errors"]), rate,
            fmt(s["min_ms"]), fmt(s["max_ms"]), fmt(s["avg_ms"]), fmt(s["median_ms"]),
            fmt(s["p95_ms"]), fmt(s["p99_ms"]), fmt(s["jitter_ms"]),
        ])

    print("\n-- Summary: Errors & Performance per Protocol --\n")
    print_table(summary_rows, SUMMARY_HEADERS)
    print(f"\nNote: DoT performed {DOT_RECONNECTS} transparent reconnect(s) "
          f"due to TLS EOF/BAD_LENGTH errors during this run.")
    return compute_table_width(summary_rows, SUMMARY_HEADERS)


# Latency rating tiers, following commonly published reference values for
# DNS resolution: < 20 ms Excellent, 20-50 ms Very good, 50-100 ms OK,
# 100-120 ms Average, 120-200 ms Slow, > 200 ms Very slow / problematic.
RATING_THRESHOLDS_MS = [
    (20, "Excellent"),
    (50, "Very good"),
    (100, "OK"),
    (120, "Average"),
    (200, "Slow"),
]
RATING_FALLBACK_LABEL = "Very slow / problematic"

# The worst tier gets "-" instead of an empty string, so the star field
# in the per-protocol line is never blank.
RATING_STARS = {
    "Excellent": "*****",
    "Very good": "****",
    "OK": "***",
    "Average": "**",
    "Slow": "*",
    RATING_FALLBACK_LABEL: "-",
}

# Ratings good enough for the ranked recommendation list.
GOOD_RATINGS = ("Excellent", "Very good")
# Usable ratings that are only considered when no protocol reaches
# GOOD_RATINGS (see choose_recommendation). The two tuples do not
# overlap, so each tier is checked exactly once.
ACCEPTABLE_FALLBACK_RATINGS = ("OK", "Average")
RELIABILITY_MOSTLY_THRESHOLD_PCT = 5  # error rate <= this % is "mostly reliable"
STABILITY_JITTER_RATIO_THRESHOLD = 0.30  # jitter/avg > this ratio is "noticeably inconsistent"

# Properties of each protocol that do not depend on the measured speed:
# how easy it is to block (port and transport) and the QUIC advantages
# (fast or 0-RTT handshakes, no transport-level head-of-line blocking,
# connection migration). The ranked recommendation uses these notes to
# explain why one protocol ranks above another within the same tier.
PROTOCOL_NOTES = {
    "DOH3": ("runs over port 443/UDP like HTTP/3 web traffic, so it is very hard for "
             "firewalls to block without also breaking normal web browsing; being "
             "QUIC-based, it also avoids TCP's head-of-line blocking (one lost "
             "packet does not stall other in-flight queries) and benefits from fast "
             "connection setup and seamless network switching (e.g. Wi-Fi to "
             "mobile) without dropping the connection"),
    "DOH": ("runs over port 443/TCP, the same port as regular HTTPS traffic, so it "
            "blends in with normal web browsing and is difficult for firewalls to "
            "block selectively; being TCP-based, a single lost packet can still "
            "stall it briefly, unlike the QUIC-based options"),
    "DOQ": ("is built directly on QUIC, giving fast connection setup, no "
            "head-of-line blocking, and seamless network switching, but it "
            "typically runs on the DNS-specific port 853/UDP, which is easier for "
            "restrictive networks to identify and block than port 443 traffic"),
    "DOT": ("encrypts DNS over the dedicated port 853/TCP, which is easy for "
            "firewalls to identify and block outright if they choose to, and, "
            "being TCP-based, is also subject to head-of-line blocking on packet "
            "loss"),
    "DO53": ("sends DNS in plaintext over port 53, trivially inspected, blocked, or "
             "tampered with by anyone on the network path"),
}

# Order within the same performance tier (see _rank_key): protocols that
# are hardest to block and/or run on QUIC come first.
PROTOCOL_PRIORITY = {"DOH3": 0, "DOH": 1, "DOQ": 2, "DOT": 3}


def rate_latency(avg_ms):
    """Classify an average latency using RATING_THRESHOLDS_MS."""
    if avg_ms is None:
        return None
    for threshold, label in RATING_THRESHOLDS_MS:
        if avg_ms < threshold:
            return label
    return RATING_FALLBACK_LABEL


def rate_reliability(error_rate_percent):
    """Classify an error rate using RELIABILITY_MOSTLY_THRESHOLD_PCT."""
    if error_rate_percent is None:
        return "unknown"
    if error_rate_percent == 0:
        return "reliable"
    if error_rate_percent <= RELIABILITY_MOSTLY_THRESHOLD_PCT:
        return "mostly reliable (occasional errors)"
    if error_rate_percent < 100:
        return "unreliable (frequent errors)"
    return "not usable (every query failed)"


def rate_stability(avg_ms, jitter_ms):
    """Classify jitter relative to the average latency using
    STABILITY_JITTER_RATIO_THRESHOLD."""
    if avg_ms is None or jitter_ms is None or avg_ms == 0:
        return None
    return ("noticeably inconsistent" if (jitter_ms / avg_ms) > STABILITY_JITTER_RATIO_THRESHOLD
            else "stable")


def _build_rating_criteria_rows():
    """Build the (Category, Rating, Criteria) rows of the rating criteria
    table from the same constants that rate_latency, rate_reliability,
    and rate_stability use, so the table always matches the
    classification."""
    rows = []
    prev = 0
    for thr, label in RATING_THRESHOLDS_MS:
        criteria = f"< {thr} ms" if prev == 0 else f"{prev}-{thr} ms"
        rows.append(["Latency", label, criteria])
        prev = thr
    rows.append(["Latency", RATING_FALLBACK_LABEL, f"> {prev} ms"])

    pct = RELIABILITY_MOSTLY_THRESHOLD_PCT
    rows.append(["Reliability", "reliable", "0% error rate"])
    rows.append(["Reliability", "mostly reliable", f"<= {pct}% error rate"])
    rows.append(["Reliability", "unreliable", f"> {pct}% error rate"])
    rows.append(["Reliability", "not usable", "100% (every query failed)"])

    ratio_pct = int(STABILITY_JITTER_RATIO_THRESHOLD * 100)
    rows.append(["Stability", "stable", f"jitter <= {ratio_pct}% of average latency"])
    rows.append(["Stability", "noticeably inconsistent", f"jitter > {ratio_pct}% of average latency"])
    return rows


def print_rating_criteria(wrap_width=78):
    """Print the rating criteria as a Category / Rating / Criteria table,
    with a separator line between categories."""
    rows = _build_rating_criteria_rows()
    headers = ["Category", "Rating", "Criteria"]
    print("Rating criteria used:\n")
    print_table(rows, headers, group_col=0)
    print("\n(Latency values are the average latency of successful queries only.)")


def gather_good_protocols(stats, exclude_do53=True):
    """Return (protocol, avg_ms, rating) for every protocol that is
    reliable (0% errors), stable, and rated Excellent or Very good."""
    good = []
    for s in stats:
        if s["avg_ms"] is None:
            continue
        if exclude_do53 and s["protocol"] == "DO53":
            continue
        if s["error_rate_percent"] != 0:
            continue
        rating = rate_latency(s["avg_ms"])
        stability = rate_stability(s["avg_ms"], s["jitter_ms"])
        if rating in GOOD_RATINGS and stability != "noticeably inconsistent":
            good.append((s["protocol"], s["avg_ms"], rating))
    return good


def _rank_key(entry):
    """Sort key for the ranked recommendation: performance tier first (so
    a real latency gap such as Excellent vs. Very good always counts),
    then the fixed priority DoH3 > DoH > DoQ > DoT within a tier, then
    raw speed as the last tie-break."""
    proto, avg_ms, rating = entry
    tier_rank = {"Excellent": 0, "Very good": 1}.get(rating, 2)
    priority = PROTOCOL_PRIORITY.get(proto, 9)
    return (tier_rank, priority, avg_ms)


def choose_recommendation(stats):
    """Decide which protocol(s) to recommend. Returns (group, note): group
    is a ranked list of (protocol, avg_ms, rating), best first; note is a
    string or None.

    Protocols rated GOOD_RATINGS are checked first. Only if there are none
    does it fall back to the single fastest protocol rated
    ACCEPTABLE_FALLBACK_RATINGS. See _rank_key, PROTOCOL_NOTES, and RANKED
    RECOMMENDATION in the module docstring."""
    do53_entry = next((s for s in stats if s["protocol"] == "DO53"
                       and s["avg_ms"] is not None and s["error_rate_percent"] == 0), None)

    good_encrypted = gather_good_protocols(stats, exclude_do53=True)

    if good_encrypted:
        group = sorted(good_encrypted, key=_rank_key)
    else:
        fallback_encrypted = [(s["protocol"], s["avg_ms"], rate_latency(s["avg_ms"])) for s in stats
                              if s["protocol"] != "DO53" and s["avg_ms"] is not None
                              and s["error_rate_percent"] == 0
                              and rate_latency(s["avg_ms"]) in ACCEPTABLE_FALLBACK_RATINGS]
        group = [min(fallback_encrypted, key=lambda x: x[1])] if fallback_encrypted else []

    note = None
    if do53_entry and group and do53_entry["avg_ms"] < min(g[1] for g in group):
        note = (f"Although DO53 (unencrypted) was technically faster at "
                f"{do53_entry['avg_ms']:.1f} ms, encrypted DNS should be preferred "
                f"whenever its performance is still reasonable, so it was not "
                f"recommended here.")

    if not group and do53_entry:
        group = [("DO53", do53_entry["avg_ms"], rate_latency(do53_entry["avg_ms"]))]
        note = ("No encrypted protocol reached acceptable performance in this test, "
                "so DO53 (unencrypted) is named here as a fallback. Keep in mind that "
                "it offers no privacy or protection against manipulation.")

    return group, note


def print_beginner_summary(stats, wrap_width=78, show_recommendation=False):
    """Print the "-- Rating --" section: the rating criteria table and one
    plain-language line per protocol. With show_recommendation=True
    (--recommend), also print the ranked recommendation."""
    print("\n-- Rating --\n")
    print_rating_criteria(wrap_width)
    print()

    any_working = False
    failed = []
    for s in stats:
        proto = s["protocol"]
        if s["queries"] == 0:
            continue
        if s["avg_ms"] is None:
            failed.append(proto)
            print(f"{proto:<6} FAILED - every query errored out "
                  f"({s['error_rate_percent']:.0f}% errors); this protocol could not be "
                  f"tested successfully on this server.")
            continue

        any_working = True
        rating = rate_latency(s["avg_ms"])
        stars = RATING_STARS[rating]
        reliability = rate_reliability(s["error_rate_percent"])
        stability = rate_stability(s["avg_ms"], s["jitter_ms"])

        line = f"{proto:<6} {stars} {rating} ({s['avg_ms']:.1f} ms average) - {reliability}"
        if stability:
            line += f", {stability}"
        print(line)

    if not any_working:
        print()
        print(textwrap.fill(
            "Overall verdict: none of the tested protocols returned a usable answer on "
            "this server. Please double-check the server address, hostname, and ports.",
            width=wrap_width))
        return

    if not show_recommendation:
        return  # without --recommend, stop after the rating lines

    print()
    group, note = choose_recommendation(stats)
    if not group:
        print(textwrap.fill(
            "None of the tested protocols reached a usable performance level in this "
            "test.", width=wrap_width))
        return

    if len(group) > 1:
        print("Ranked Recommendation:\n")
        for i, (proto, avg, rating) in enumerate(group, start=1):
            why = PROTOCOL_NOTES.get(proto, "")
            entry_text = f"{i}. {proto} - {rating} ({avg:.1f} ms average). {proto} {why}."
            print(textwrap.fill(entry_text, width=wrap_width, subsequent_indent="   "))
        print()
        top_proto = group[0][0]
        others = ", ".join(p for p, _, _ in group[1:])
        closing = (f"{top_proto} is the best overall choice on this resolver, closely "
                   f"followed by {others}.")
        if note:
            closing += " " + note
        if failed:
            closing += (f" {', '.join(failed)} could not be used on this server (every "
                        f"query failed) -- this may be intentional (e.g. plaintext Do53 "
                        f"disabled for privacy) or indicate a misconfiguration worth "
                        f"double-checking.")
        print(textwrap.fill(closing, width=wrap_width))
    else:
        proto, avg, rating = group[0]
        why = PROTOCOL_NOTES.get(proto, "")
        sentences = [f"Overall, this resolver performs {rating.upper()} on the working "
                     f"encrypted protocol(s) tested, with {proto} being the fastest "
                     f"usable option at {avg:.1f} ms on average. {proto} {why}."]
        if note:
            sentences.append(note)
        if failed:
            sentences.append(f"{', '.join(failed)} could not be used on this server "
                              f"(every query failed) -- this may be intentional (e.g. "
                              f"plaintext Do53 disabled for privacy) or indicate a "
                              f"misconfiguration worth double-checking.")
        print(textwrap.fill(" ".join(sentences), width=wrap_width))


def loop_runner(args, domains, protocols, query_fns):
    headers = HEADERS_FULL[:-1] if args.no_answer else HEADERS_FULL
    rng = random.Random(args.seed) if args.shuffle else None
    all_rows = []
    rounds_data = []
    meta = {
        "server": args.server,
        "hostname": args.hostname,
        "protocols": protocols,
        "rtype": args.rtype,
        "timeout_ms": args.timeout,
        "shuffle": args.shuffle,
        "seed": args.seed,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    round_no = 1
    # The total is only known with --loop and --max-rounds > 0. Otherwise
    # there is no "n/total" to show, and --quiet-rounds has no effect (see
    # QUIET ROUNDS in the module docstring).
    total_rounds = args.max_rounds if args.loop and args.max_rounds else None
    quiet_progress_active = bool(args.quiet_rounds and args.loop and total_rounds)

    if quiet_progress_active:
        # Blank line between the setup/warm-up messages and the progress line.
        print()

    interrupted = False
    completed_rounds = 0
    try:
        while True:
            if quiet_progress_active:
                # Overwrite the same console line instead of printing a new
                # line every round.
                sys.stdout.write(f"\rRound ({round_no}/{total_rounds})")
                sys.stdout.flush()
            else:
                print(f"\n-- Round {round_no} --\n")

            rows = run_round(domains, protocols, query_fns, args.rtype,
                              shuffle=args.shuffle, rng=rng)
            all_rows.extend(rows)
            completed_rounds += 1
            display_rows = [row[:-1] for row in rows] if args.no_answer else rows

            if not quiet_progress_active:
                print_table(display_rows, headers, group_col=DOMAIN_COL)

            if args.csv:
                write_csv(args.csv, display_rows, headers, append=(round_no > 1))
            if args.json:
                rounds_data.append({"round": round_no, "results": rows_to_dicts(display_rows, headers)})
                write_json(args.json, meta, rounds_data)
            if not args.loop:
                break
            if args.max_rounds and round_no >= args.max_rounds:
                if not quiet_progress_active:
                    print(f"\nReached --max-rounds {args.max_rounds}, stopping.")
                break
            round_no += 1
            time.sleep(args.interval)
    except KeyboardInterrupt:
        interrupted = True

    if quiet_progress_active:
        # End the progress line so the summary starts on its own line.
        sys.stdout.write("\n")
        sys.stdout.flush()

    if interrupted:
        print(f"\nInterrupted by user after {completed_rounds} completed round(s).")
        if completed_rounds == 0:
            print("No round was completed, so there is nothing to summarize.")
            return

    stats = compute_protocol_stats(all_rows, protocols)
    table_width = print_summary(stats)
    print_beginner_summary(stats, wrap_width=max(table_width, 60),
                            show_recommendation=args.recommend)
    if args.json:
        write_json(args.json, meta, rounds_data, summary=stats)


def run(args):
    domains = load_domains(args)
    protocols = list(dict.fromkeys(args.proto))

    with ExitStack() as stack:
        query_fns = {}
        for proto in protocols:
            try:
                query_fns[proto] = setup_protocol(proto, args, stack, domains[0])
            except Exception as e:
                # A protocol that cannot be set up (missing package, blocked
                # port, ...) is skipped instead of ending the whole run.
                print(f"[{proto.upper()}] Skipping this protocol: {e}")

        active = [p for p in protocols if p in query_fns]
        if not active:
            sys.exit("No protocol could be set up, nothing to test.")
        loop_runner(args, domains, active, query_fns)


def parse_protocols(value):
    protocols = [p.strip().lower() for p in value.split(",") if p.strip()]
    valid = set(SETUP_FUNCS.keys())
    invalid = [p for p in protocols if p not in valid]
    if invalid:
        raise argparse.ArgumentTypeError(
            f"invalid protocol(s) {invalid}, choose from {sorted(valid)}"
        )
    if not protocols:
        raise argparse.ArgumentTypeError("--proto must not be empty")
    return protocols


def main():
    p = argparse.ArgumentParser(
        description="Persistent Do53/DoT/DoH/DoH3/DoQ tester -- one or more protocols per run",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--proto", required=True, type=parse_protocols,
                   help="Protocol(s) to test, comma-separated: do53, dot, doh, doh3, doq")
    p.add_argument("--server", required=True, help="Resolver IP address")
    p.add_argument("--port", type=int, default=None,
                   help="Port for all selected protocols (default: 53/do53, 853/dot+doq, 443/doh+doh3)")
    p.add_argument("--hostname", required=True,
                   help="TLS/SNI hostname (and DoH/DoH3 URL host); unused but required for do53")
    p.add_argument("--path", default="/dns-query", help="DoH/DoH3 URL path (default: /dns-query)")
    p.add_argument("--rtype", default="A", help="Record type (A, AAAA, TXT, ...)")
    p.add_argument("--timeout", type=int, default=1000,
                   help="Per-query timeout in milliseconds (default: 1000)")
    p.add_argument("--shuffle", action="store_true",
                   help="Randomize the (domain, protocol) query order within each round")
    p.add_argument("--seed", type=int, default=None,
                   help="Random seed for --shuffle, for a reproducible query order")
    p.add_argument("--no-verify", action="store_true", help="Disable TLS certificate verification")
    p.add_argument("--no-warmup", action="store_true",
                   help="Skip the warm-up query (has no effect on do53)")
    p.add_argument("--retries", type=int, default=1,
                   help="Additional attempts if setup/warm-up fails (default: 1)")
    p.add_argument("--loop", action="store_true", help="Send queries repeatedly in rounds")
    p.add_argument("--interval", type=float, default=1.0,
                   help="Seconds between rounds when --loop is set (default: 1.0)")
    p.add_argument("--max-rounds", type=int, default=10,
                   help="Maximum number of rounds when --loop is set (default: 10, 0=unlimited)")
    p.add_argument("--quiet-rounds", action="store_true",
                   help="Show a single progress line 'Round (n/total)' that "
                        "updates in place instead of a table per round; only "
                        "works with --loop and a finite --max-rounds")
    p.add_argument("--recommend", action="store_true",
                   help="Add the ranked protocol recommendation at the end "
                        "(the rating criteria and per-protocol ratings are "
                        "always shown)")
    p.add_argument("--csv", help="Optional path to write results as CSV (overwritten at the start of a run, then extended after every round)")
    p.add_argument("--json", help="Optional path to write results and summary as JSON")
    p.add_argument("--no-answer", action="store_true",
                   help="Suppress the Answer column in table/CSV/JSON output")
    p.add_argument("--domains-file", help="Text file with one domain per line")
    p.add_argument("domains", nargs="*", help="Domain names to test")
    args = p.parse_args()

    run(args)


if __name__ == "__main__":
    main()
