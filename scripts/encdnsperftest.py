#!/usr/bin/env python3
"""
encdnsperftest.py

Tests classic unencrypted DNS (Do53), DNS-over-TLS (DoT), DNS-over-HTTPS
(DoH), DNS-over-HTTPS/3 (DoH3), and DNS-over-QUIC (DoQ) using dnspython
(>=2.7). For the encrypted protocols, exactly ONE connection/session is
opened and kept alive for the entire run -- the TLS/QUIC handshake happens
only once, not on every single query. Do53 has no handshake to keep warm
(plain UDP) and is included as a plaintext baseline.

IMPORTANT: For DoT specifically, some public resolvers may close
long-lived TLS sessions after some number of queries or seconds even
when they are still being used. To avoid DoT getting permanently stuck
on a dead TLS socket, this script includes a small, **silent** reconnect
shim: if a DoT query fails with characteristic EOF/BAD_LENGTH TLS
errors, the DoT socket is transparently rebuilt once and the query
retried on the new connection **without extra logging during the
rounds**. The number of such DoT reconnects is shown as a note under the
end-of-run summary table.

Results are printed as a table per round (or, with --quiet-rounds, as a
single in-place progress line instead -- see QUIET ROUNDS below),
followed at the end by a technical summary table (min/max/avg/median/
P95/P99/jitter per protocol), an explicit RATING CRITERIA table
explaining exactly how "Excellent", "reliable", and "stable" etc. are
defined, and a plain-language, per-protocol verdict (see RATING below).
The RANKED protocol recommendation is an OPT-IN section only shown when
--recommend is passed (see RANKED RECOMMENDATION (--recommend) below) --
everything else described here is always shown.

Domains to test can be given as positional arguments, read from a file
(one domain per line, via --domains-file), or both at once.

--------------------------------------------------------------------------
REQUIREMENTS
--------------------------------------------------------------------------
pip install "dnspython>=2.8" "httpcore>=1.0.0" "httpx[http2]>=0.28.0" \
    "h2>=4.2.0" "aioquic>=0.9"

- dnspython 2.8's DoH feature check requires h2>=4.2.0 (stricter than
  httpx's own h2<5,>=3); an old OS-provided h2 (e.g. 4.1.0) can
  silently disable DoH and cause AttributeError:
  '_HTTPTransport' object has no attribute '_pool'.
  Fix: pip install --upgrade "h2>=4.2.0"
- aioquic: needed for --proto doq and doh3
- do53/dot: no extra packages needed

NOTE for Python < 3.10: dnspython >=2.8 requires Python 3.10+. Use:
  pip install "dnspython>=2.7,<2.8" "httpcore>=1.0.0" \
      "httpx[http2]>=0.26.0" "h2>=4.1.0" "aioquic>=1.0.0"

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
--shuffle                 randomize (domain, protocol) query order
--seed N                  seed for --shuffle (reproducible order)
--no-verify               disable TLS certificate verification
--no-warmup               skip the warm-up query (see RETRY LOGIC)
--retries N               extra connection/warm-up attempts (default: 1)
--loop                    repeat all queries in rounds
--interval SECONDS        pause between rounds (default: 1.0)
--max-rounds N            rounds limit with --loop (default: 10, 0=inf)
--quiet-rounds            suppress per-round tables and show only a
                          single, in-place progress line "Round (n/x)"
                          that overwrites itself on the console instead;
                          only meaningful when --loop is used (see
                          QUIET ROUNDS below)
--recommend               show the RANKED RECOMMENDATION section
                          (see below); without this flag, only the
                          per-protocol plain-language lines and the
                          rating criteria table are shown
--csv PATH                append results as CSV
--json PATH               write results + summary as JSON
--no-answer               hide the Answer column (table/CSV/JSON)
--domains-file PATH       file with one domain per line
domains (positional)      domain names to query

--------------------------------------------------------------------------
RATING CRITERIA
--------------------------------------------------------------------------
Printed as a short table right before the per-protocol plain-language
lines, so the ratings used there are fully transparent instead of opaque
labels. Rendered with the same print_table() helper used for the other
tables in this script, so the separator lines run continuously across
ALL columns (including "Category"), not just under "Rating"/"Criteria":

Rating criteria used:

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

These thresholds are the same ones used by rate_latency, rate_reliability,
and rate_stability, and by extension by compute_protocol_stats/
choose_recommendation -- the table and the actual classification always
stay in sync since they read from the same constants
(RATING_THRESHOLDS_MS, RELIABILITY_MOSTLY_THRESHOLD_PCT,
STABILITY_JITTER_RATIO_THRESHOLD -- note the stability threshold is 30%
of the average latency). The latency tiers/labels mirror common
published DNS-resolution reference values (< 20 ms Excellent, 20-50 ms
Very good, 50-100 ms OK, 100-120 ms Average, 120-200 ms Slow, > 200 ms
Very slow / problematic).

--------------------------------------------------------------------------
RATING (always shown)
--------------------------------------------------------------------------
-- Rating --

Rating criteria used:

Category    Rating                  Criteria
----------- ----------------------- --------------------------------
Latency     Excellent               < 20 ms
...
----------- ----------------------- --------------------------------
Reliability reliable                0% error rate
...

DOH   ***** Excellent (15.4 ms average) - reliable, stable
DOH3  ***** Excellent (12.5 ms average) - reliable, stable
DOQ   ***** Excellent (11.3 ms average) - reliable, stable

This part -- the rating criteria table and the per-protocol star/
reliability/stability lines -- is ALWAYS printed, independent of
--recommend. A protocol rated "Very slow / problematic" (the worst
tier) is shown with a "-" placeholder instead of stars, since 0 stars
would otherwise print as a blank/invisible field.

--------------------------------------------------------------------------
RANKED RECOMMENDATION (--recommend)
--------------------------------------------------------------------------
Only printed when --recommend is passed. When enabled, it adds:

Ranked Recommendation:

1. DOH3 - Excellent (12.5 ms average). DOH3 runs over port 443/UDP
   like HTTP/3 web traffic, so it is very hard for firewalls to block
   without also breaking normal web browsing; being QUIC-based, it
   also avoids TCP's head-of-line blocking (one lost packet does not
   stall other in-flight queries) and benefits from fast connection
   setup and seamless network switching (e.g. Wi-Fi to mobile)
   without dropping the connection.
2. DOH - Excellent (15.4 ms average). DOH runs over port 443/TCP, the
   same port as regular HTTPS traffic, so it blends in with normal
   web browsing and is difficult for firewalls to block selectively;
   being TCP-based, a single lost packet can still stall it briefly,
   unlike the QUIC-based options.
3. DOQ - Excellent (11.3 ms average). DOQ is built directly on QUIC,
   giving fast connection setup, no head-of-line blocking, and
   seamless network switching, but it typically runs on the
   DNS-specific port 853/UDP, which is easier for restrictive
   networks to identify and block than port 443 traffic.

DOH3 is the best overall choice on this resolver, closely followed
by DOH, DOQ.

Protocol choice depends on more than raw speed, so the ranking:
- Groups every encrypted protocol that is reliable (0% errors), stable,
  and rated Excellent/Very good into one list, instead of naming only a
  single "winner" when several protocols perform essentially equally
  well (which would misleadingly suggest the others are worse).
- If NO protocol reaches that Excellent/Very good + stable + reliable
  bar, falls back to the single fastest protocol rated OK or Average
  instead (see ACCEPTABLE_FALLBACK_RATINGS) -- a plain descriptive
  sentence, not a ranked list, since there is only one entry.
- Sorts the Excellent/Very good group PRIMARILY by performance tier
  (Excellent ranks above Very good) -- so a real, meaningful latency gap
  is never overridden by the qualitative priority below; latency is
  only used as a tie-break WITHIN the same tier, where the millisecond
  difference is small enough not to matter in practice.
- WITHIN the same tier, ranks by a fixed real-world-usability priority:
  DoH3 > DoH > DoQ > DoT (see PROTOCOL_NOTES/PROTOCOL_PRIORITY), based
  on published, factual protocol characteristics:
  * DoH and DoH3 run on port 443, the same port as ordinary
    HTTPS/HTTP-3 web traffic, making them very hard for firewalls or
    censors to block without also breaking normal web browsing.
  * DoH3 and DoQ are built on QUIC, which has no transport-layer
    head-of-line blocking, supports fast/0-RTT reconnection, and
    supports connection migration (a connection can survive a network
    change, e.g. switching from Wi-Fi to mobile, without being
    re-established).
  * DoT and DoQ use the DNS-specific port 853, which is easier for a
    restrictive network to selectively identify and block than
    ordinary port 443 traffic.
  DoH3 combines BOTH advantages (port 443 concealment and QUIC
  benefits), which is why it is prioritized ahead of DoH (port 443 but
  TCP-based) and DoQ (QUIC-based but on the identifiable port 853).
- Never recommends DO53 (plaintext) just for being numerically fastest;
  an explanatory note is added when this override happens. If NO
  encrypted protocol is usable, DO53 is used as a last resort, with an
  explicit reminder that it offers no privacy/protection.

This section is printed to the console only and reflects the FULL run
(all rounds combined); it is unaffected by --no-answer/--quiet-rounds
and is not currently included in --csv or --json output.

--------------------------------------------------------------------------
QUIET ROUNDS (--quiet-rounds)
--------------------------------------------------------------------------
By default, every round prints a "-- Round n --" heading followed by the
full results table for that round. With --quiet-rounds (only meaningful
together with --loop and a finite --max-rounds), the per-round heading
and table are replaced by a SINGLE progress line that is continuously
OVERWRITTEN IN PLACE (using a carriage return, "\\r", with no newline)
rather than printed anew for every round. A blank line is printed once
before the progress line starts, separating it visually from the setup
messages (e.g. "[DOT] Connecting ...") printed just before it:

[DOT] Warm-up done in 13.5 ms (connection is now warm and reused for all following queries)

Round (274/500)

Only the number changes as rounds complete; the terminal shows exactly
one line, updated in place, instead of one line per round. Once the loop
ends (either --max-rounds is reached or the run is interrupted), a
newline is written so subsequent output (the end-of-run summary etc.)
starts cleanly on its own line.

This only affects what is printed to the console during the loop --
CSV export, JSON export, the end-of-run summary table, DoT reconnect
counting, and the RATING/RANKED RECOMMENDATION sections at the end are
completely unaffected and still reflect every round's data. Without
--loop (a single pass), or with --loop but --max-rounds 0 (unlimited
rounds, no known total), --quiet-rounds has no effect and the normal
per-round heading/table is still printed, since a meaningful "n/total"
progress indicator cannot be shown without a known total.

--------------------------------------------------------------------------
JSON EXPORT (--json)
--------------------------------------------------------------------------
Writes {"meta": {...}, "rounds": [{"round": N, "results": [...]}], "summary": [...]}.
Column names in "rounds"[i]["results"] match the table/CSV (respecting
--no-answer). "summary" mirrors the technical summary table but with real
numeric values (or null, never a misleading 0, when a protocol had no
successful queries). The file is rewritten after every round (so an
interrupted --loop run still leaves valid JSON on disk) and rewritten once
more at the end with "summary" added. This happens regardless of
--quiet-rounds -- only the console output is affected by that flag.

--------------------------------------------------------------------------
RANDOM QUERY ORDER (--shuffle)
--------------------------------------------------------------------------
By default, each round queries all protocols for domain 1, then all
protocols for domain 2, etc., identically every round. --shuffle
randomizes the (domain, protocol) order per round (re-shuffled every
round unless --seed is given for reproducibility), better simulating mixed
real-world traffic and cache behaviour. Only the ORDER changes. With
--shuffle, the domain-grouping separator line in the printed table appears
far more often -- expected, not a bug. (Not visible at all when
--quiet-rounds suppresses the per-round table.)

--------------------------------------------------------------------------
QUERY TIMEOUT
--------------------------------------------------------------------------
--timeout (default 1000 ms) bounds every single query (including the
warm-up query) via dnspython's timeout= parameter on dns.query.udp/tls/
https/quic. A query exceeding it is reported as Status "ERROR" instead of
hanging the whole run. It does NOT bound the initial connection setup
(TCP/TLS/QUIC handshake in setup_protocol); a hanging handshake is instead
handled by RETRY LOGIC giving up after --retries attempts.

--------------------------------------------------------------------------
END-OF-RUN SUMMARY: ERRORS & PERFORMANCE
--------------------------------------------------------------------------
-- Summary: Errors & Performance per Protocol --

Protocol Queries Errors Error Rate Min (ms) Max (ms) Avg (ms) Median (ms) P95 (ms) P99 (ms) Jitter (ms)
-------- ------- ------ ---------- -------- -------- -------- ----------- -------- -------- -----------
DO53     10      10     100.0%     -        -        -        -           -        -        -
DOH      10      0      0.0%       13.5     17.9     15.4     15.1        17.5     17.9     1.3
DOH3     10      0      0.0%       11.6     14.0     12.5     12.4        13.8     14.0     0.7
DOT      10      2      20.0%      9.9      14.5     12.3     12.0        14.2     14.5     1.6
DOQ      10      0      0.0%       10.5     12.0     11.3     11.2        11.9     12.0     0.5

Min/Max/Avg/Median/P95/P99/Jitter use ONLY successful ("OK") queries.
Median resists outliers better than Avg; P95/P99 show near-worst-case
latency more usefully than a single Max value; Jitter (population stdev)
measures consistency independent of raw speed. Zero successful queries ->
"-" (or null in JSON), never a misleading 0. See RATING CRITERIA above for
exactly how these numbers translate into the plain-language ratings.

Below this table, a note is printed that shows how many DoT queries had
to transparently reconnect due to TLS EOF/BAD_LENGTH errors during the
run, e.g.:

Note: DoT performed 3 transparent reconnect(s) due to TLS EOF/BAD_LENGTH
errors during this run.

--------------------------------------------------------------------------
RETRY LOGIC
--------------------------------------------------------------------------
For DoT/DoH/DoH3/DoQ, connection setup + warm-up query are one retryable
unit: build connection -> send warm-up (bounded by --timeout) -> on
failure, print a labelled message and rebuild from scratch up to
--retries additional times -> after exhausting attempts, continue anyway
(rows will likely show ERROR). All these setup-level messages print
BEFORE the results table/progress line. Do53 has no connection/handshake
to retry.

For DoT specifically, in addition to this setup-level retry logic, each
query ALSO has a one-shot, silent reconnect shim (see the module
docstring's IMPORTANT note above): when a DoT query fails mid-run with
characteristic TLS EOF/BAD_LENGTH errors (e.g. because the resolver
closed the long-lived session), the script transparently closes the old
socket, rebuilds a fresh TLS connection (without printing anything to
the console during the rounds), and retries the query once on that new
socket before reporting an error. Only the INITIAL DoT connection setup
before the first round is logged; reconnects during the loop are silent
and only counted (see DOT_RECONNECTS and the note under the end-of-run
summary table).

--------------------------------------------------------------------------
STATUS / ERROR DETECTION
--------------------------------------------------------------------------
"OK" requires: no timeout, RCODE == NOERROR (else ERROR with
"RCODE=<code>"), and a non-empty answer section (else ERROR with
"NODATA (empty answer section)").

--------------------------------------------------------------------------
Do53 / DoH3 NOTES
--------------------------------------------------------------------------
Do53 (plain UDP/port 53) has no handshake/retry logic and is included
purely as a plaintext baseline. DoH3 is implemented by dnspython on the
same QUIC infrastructure as DoQ (dns.quic), not httpx (no native HTTP/3
support): dns.query.https(..., http_version=dns.query.HTTPVersion.HTTP_3)
with a persistent dns.quic.SyncQuicConnection (h3=True) as the session.

--------------------------------------------------------------------------
WHY THE WARM-UP QUERY EXISTS, AND TWO DoH-SPECIFIC FIXES BUILT IN
--------------------------------------------------------------------------
httpx (DoH) opens its TCP/TLS/HTTP2 connection lazily on the first real
request; the warm-up query forces that before the measured rounds start.
Two DoH-only fixes:
1. TCP_NODELAY: dnspython's bootstrap_address network backend never
   disables Nagle's algorithm -- fixed via _NoDelayNetworkBackend.
2. Idle keep-alive expiry: httpx.Client's default 5.0s keepalive_expiry
   could silently close the DoH connection between rounds -- fixed via
   httpx.Limits(keepalive_expiry=None).

--------------------------------------------------------------------------
EXAMPLES
--------------------------------------------------------------------------
# Single pass (no --loop): query once and print results plus rating
python3 encdnsperftest.py --proto do53,dot,doh --server 203.0.113.53 \
    --hostname resolver.example example.com google.com

# Loop for 20 rounds and show the ranked, opinionated recommendation
python3 encdnsperftest.py --proto do53,dot,doh,doh3,doq --server 203.0.113.53 \
    --hostname resolver.example --recommend --loop --max-rounds 20 \
    example.com google.com

# Long loop with a compact, in-place single-line progress indicator
# instead of printing the full table every round (good for hundreds of
# rounds where the per-round table would just scroll past)
python3 encdnsperftest.py --proto do53,dot,doh --server 203.0.113.53 \
    --hostname resolver.example --loop --max-rounds 500 --interval 0.10 \
    --shuffle --quiet-rounds example.com google.com facebook.com

# Export results and the final summary to JSON for later analysis
python3 encdnsperftest.py --proto do53,dot,doh,doh3,doq --server 203.0.113.53 \
    --hostname resolver.example --loop --max-rounds 20 --json results.json \
    example.com google.com

# Append every round's results to a CSV file as well
python3 encdnsperftest.py --proto do53,doh --server 203.0.113.53 \
    --hostname resolver.example --loop --max-rounds 20 --csv results.csv \
    example.com google.com

# Reproducible shuffled query order across a run (same seed -> same order)
python3 encdnsperftest.py --proto do53,dot,doh,doh3,doq --server 203.0.113.53 \
    --hostname resolver.example --shuffle --seed 42 --loop --max-rounds 20 \
    example.com google.com facebook.com wikipedia.org

# Read the domain list from a file instead of (or in addition to)
# positional arguments
python3 encdnsperftest.py --proto do53,doh --server 203.0.113.53 \
    --hostname resolver.example --domains-file domains.txt --loop \
    --max-rounds 10

# Query AAAA records instead of A, against a non-standard DoT port, with
# certificate verification disabled (e.g. testing a self-signed resolver)
python3 encdnsperftest.py --proto dot --server 203.0.113.53 \
    --hostname resolver.example --port 8853 --rtype AAAA --no-verify \
    example.com

# Hide the Answer column for a more compact table when you only care
# about latency/status, not the actual resolved records
python3 encdnsperftest.py --proto do53,doh --server 203.0.113.53 \
    --hostname resolver.example --no-answer --loop --max-rounds 10 \
    example.com google.com

# Be more patient with a slow or distant resolver: longer per-query
# timeout and more setup/warm-up retries before giving up
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
    """Wraps httpx/httpcore's network backend so TCP_NODELAY is set on
    every connection it opens (see WHY THE WARM-UP QUERY EXISTS section
    in the module docstring for why this is needed for DoH)."""

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
    """Build an httpx.Client whose connections are forced to `server` (IP)
    while TLS SNI/certificate checks use `hostname`, kept alive across
    many dns.query.https() calls. Relies on dnspython's internal
    dns.query._HTTPTransport; wraps its network backend with
    _NoDelayNetworkBackend and disables httpx's idle keep-alive expiry."""
    import httpx

    transport = dns.query._HTTPTransport(  # noqa: SLF001 - intentional use of dnspython internal
        http1=True, http2=True, verify=verify, bootstrap_address=server,
    )
    transport._pool._network_backend = _NoDelayNetworkBackend(  # noqa: SLF001
        transport._pool._network_backend  # noqa: SLF001
    )

    limits = httpx.Limits(keepalive_expiry=None)
    return httpx.Client(http1=True, http2=True, verify=verify, transport=transport, limits=limits)


def print_table(rows, headers, group_col=None):
    """Print a simple aligned ASCII table without external dependencies.
    If group_col is given, a separator line is inserted whenever that
    column's value changes between consecutive rows. The separator spans
    ALL columns (built from every column width), so it is a single
    continuous line, never indented under any one column."""
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
    """Compute the total printed width print_table would use, so other
    output can be word-wrapped to visually line up with it."""
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    return sum(widths) + 2 * (len(widths) - 1)


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
    """Overwrite the JSON export file (after every round, and once more
    at the end with `summary` included) so an interrupted run still
    leaves valid, parseable JSON on disk."""
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


def query_and_collect(proto, name, rtype, query_fn):
    q = dns.message.make_query(name, rtype)
    start = time.time()
    try:
        resp = query_fn(q)
        dt = (time.time() - start) * 1000

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
        dt = (time.time() - start) * 1000
        return [proto.upper(), name, rtype, f"{dt:.1f}", "ERROR", str(e)]


def do_warmup(query_fn, domain, rtype, label):
    """Send one throwaway query to force the connection to actually open.
    Raises on failure so setup_protocol can decide whether to retry."""
    print(f"{label} Sending warm-up query ({domain}) to force the connection open ...")
    q = dns.message.make_query(domain, rtype)
    t0 = time.time()
    query_fn(q)
    print(f"{label} Warm-up done in {(time.time()-t0)*1000:.1f} ms "
          f"(connection is now warm and reused for all following queries)")


def setup_protocol(proto, args, stack, warm_domain):
    """Build the connection/session for `proto` and, unless --no-warmup,
    send a warm-up query. Retries the WHOLE setup (connection + warm-up)
    from scratch up to args.retries additional times on failure."""
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
    """Set up a persistent DoT connection. To handle resolvers that close
    long-lived TLS sessions (EOF/BAD_LENGTH), this returns a query_fn
    that will silently rebuild the TLS socket once when such an error is
    seen and retry the query on the new connection -- WITHOUT printing
    anything during the loop -- before surfacing an error. Only the
    INITIAL connection setup below is logged; see the module docstring's
    RETRY LOGIC section for details. The initial setup itself is still
    subject to the higher-level RETRY LOGIC in setup_protocol via
    --retries."""
    global DOT_RECONNECTS
    port = args.port or 853
    timeout = args.timeout / 1000.0

    def make_sock(log: bool):
        if log:
            print(f"[DOT] Connecting to {args.server}:{port} (SNI={args.hostname}) ...")
        t0 = time.time()
        s = build_tls_socket(args.server, port, args.hostname, not args.no_verify)
        if log:
            print(f"[DOT] TLS handshake completed in {time.time()-t0:.3f}s (cipher: {s.cipher()})")
        return s

    # Initial connection: logged, exactly once, before the first round.
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

    def query_fn(q):
        nonlocal sock
        global DOT_RECONNECTS

        def _do_query():
            return dns.query.tls(q, args.server, port=port, sock=sock, timeout=timeout)

        try:
            return _do_query()
        except Exception as e:
            msg = str(e)
            if ("EOF" in msg or "connection has been closed" in msg
                    or "BAD_LENGTH" in msg):
                # Silent reconnect during the loop: no console output,
                # only counted via DOT_RECONNECTS (see end-of-run note).
                close_sock()
                try:
                    sock = make_sock(log=False)
                    DOT_RECONNECTS += 1
                    return _do_query()
                except Exception as e2:
                    raise e2
            raise

    return query_fn


def setup_doh(args, stack):
    url = f"https://{args.hostname}{args.path}"
    timeout = args.timeout / 1000.0
    print(f"[DOH] Creating persistent httpx.Client session, connecting to "
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
        verify_mode=not args.no_verify, server_name=args.hostname, h3=True
    )
    stack.enter_context(manager)
    t0 = time.time()
    connection = manager.connect(args.server, port)
    print(f"[DOH3] Connection established in {time.time()-t0:.3f}s")

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
        verify_mode=not args.no_verify, server_name=args.hostname
    )
    stack.enter_context(manager)
    t0 = time.time()
    connection = manager.connect(args.server, port)
    print(f"[DOQ] QUIC connection established in {time.time()-t0:.3f}s")

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
    """Run one round: every domain against every protocol. Fixed
    domain-major order by default; if shuffle is True, the (domain,
    protocol) pair list is shuffled in place using `rng`."""
    pairs = [(name, proto) for name in domains for proto in protocols]
    if shuffle:
        rng.shuffle(pairs)
    rows = []
    for name, proto in pairs:
        rows.append(query_and_collect(proto, name, rtype, query_fns[proto]))
    return rows


def _percentile(sorted_vals, pct):
    """Linear-interpolation percentile (numpy's default convention),
    computed manually. `sorted_vals` must be sorted ascending, non-empty."""
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
    """Compute per-protocol Queries/Errors/Error Rate and latency stats
    (min/max/avg/median/P95/P99/jitter, from "OK" queries only) as a list
    of dicts with real numeric values (or None)."""
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
    """Print the end-of-run summary table, followed by a note on how many
    DoT reconnects occurred; returns the table's printed character width
    so callers can word-wrap other output to line up with it."""

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


# Latency rating tiers, aligned with commonly published DNS resolution
# reference values: < 20 ms Excellent, 20-50 ms Very good, 50-100 ms OK,
# 100-120 ms Average, 120-200 ms Slow, > 200 ms Very slow / problematic.
RATING_THRESHOLDS_MS = [
    (20, "Excellent"),
    (50, "Very good"),
    (100, "OK"),
    (120, "Average"),
    (200, "Slow"),
]
RATING_FALLBACK_LABEL = "Very slow / problematic"

# "-" placeholder for the worst tier instead of an empty string, so the
# per-protocol line never prints a blank/invisible field where the star
# rating would otherwise go.
RATING_STARS = {
    "Excellent": "*****",
    "Very good": "****",
    "OK": "***",
    "Average": "**",
    "Slow": "*",
    RATING_FALLBACK_LABEL: "-",
}

# Best-tier ratings that alone justify a top recommendation slot.
GOOD_RATINGS = ("Excellent", "Very good")
# Fallback-tier ratings: usable, but not good enough to headline the
# ranked recommendation; only considered when no protocol reaches
# GOOD_RATINGS (see choose_recommendation). Deliberately excludes
# GOOD_RATINGS so the two tiers are checked exactly once each, with no
# overlap between gather_good_protocols() and the fallback lookup.
ACCEPTABLE_FALLBACK_RATINGS = ("OK", "Average")
RELIABILITY_MOSTLY_THRESHOLD_PCT = 5  # error rate <= this % is "mostly reliable"
STABILITY_JITTER_RATIO_THRESHOLD = 0.30  # jitter/avg > this ratio is "noticeably inconsistent"

# Qualitative, protocol-inherent notes (independent of measured speed) --
# based on published, factual protocol characteristics: firewall/
# censorship resistance (which port/transport is used) and QUIC-specific
# advantages (fast/0-RTT handshakes, no transport-level head-of-line
# blocking, connection migration). Used by the ranked recommendation to
# explain WHY a protocol is prioritized over another within the same
# performance tier.
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

# Tie-break priority WITHIN the same performance tier (see _rank_key):
# prefer protocols that are hardest to block and/or benefit from QUIC.
PROTOCOL_PRIORITY = {"DOH3": 0, "DOH": 1, "DOQ": 2, "DOT": 3}


def rate_latency(avg_ms):
    """Classify an average latency into a plain-language rating using
    the thresholds documented in RATING CRITERIA (RATING_THRESHOLDS_MS)."""
    if avg_ms is None:
        return None
    for threshold, label in RATING_THRESHOLDS_MS:
        if avg_ms < threshold:
            return label
    return RATING_FALLBACK_LABEL


def rate_reliability(error_rate_percent):
    """Classify an error rate using the thresholds documented in RATING
    CRITERIA (RELIABILITY_MOSTLY_THRESHOLD_PCT)."""
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
    """Classify jitter relative to average latency using the threshold
    documented in RATING CRITERIA (STABILITY_JITTER_RATIO_THRESHOLD)."""
    if avg_ms is None or jitter_ms is None or avg_ms == 0:
        return None
    return ("noticeably inconsistent" if (jitter_ms / avg_ms) > STABILITY_JITTER_RATIO_THRESHOLD
            else "stable")


def _build_rating_criteria_rows():
    """Build the (Category, Rating, Criteria) rows for the rating
    criteria table from the same constants used by rate_latency/
    rate_reliability/rate_stability, so the printed table can never
    drift out of sync with the actual classification logic."""
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
    """Print the rating criteria as a table (Category / Rating /
    Criteria, grouped with a separator line per category) so the
    thresholds behind Excellent/reliable/stable etc. are easy to scan at
    a glance. Uses print_table(), so each separator line runs
    continuously across ALL columns rather than being indented under
    "Category". Reads from the same constants used by rate_latency/
    rate_reliability/rate_stability (via _build_rating_criteria_rows), so
    the table can never drift out of sync with the actual classification
    logic."""
    rows = _build_rating_criteria_rows()
    headers = ["Category", "Rating", "Criteria"]
    print("Rating criteria used:\n")
    print_table(rows, headers, group_col=0)
    print("\n(Latency values are the average latency of successful queries only.)")


def gather_good_protocols(stats, exclude_do53=True):
    """Return (protocol, avg_ms, rating) tuples for every protocol that is
    reliable (0% errors), stable, AND rated Excellent or Very good
    (GOOD_RATINGS)."""
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
    """Sort key for the ranked recommendation: PRIMARILY by performance
    tier (so a real latency gap, e.g. Excellent vs. Very good, is never
    overridden by the qualitative priority below), then by a fixed
    censorship-resistance/QUIC-benefit priority (DoH3 > DoH > DoQ > DoT)
    used only as a tie-break WITHIN the same tier, then by raw speed as a
    final tie-break."""
    proto, avg_ms, rating = entry
    tier_rank = {"Excellent": 0, "Very good": 1}.get(rating, 2)
    priority = PROTOCOL_PRIORITY.get(proto, 9)
    return (tier_rank, priority, avg_ms)


def choose_recommendation(stats):
    """Decide which protocol(s) to recommend, ranked, plus an optional
    explanatory note. Returns (group, note); group is a ranked list of
    (protocol, avg_ms, rating) tuples (best first), note is str or None.

    Checks GOOD_RATINGS (via gather_good_protocols) first; only if that
    yields nothing does it fall back to the single fastest protocol in
    ACCEPTABLE_FALLBACK_RATINGS -- the two tiers are mutually exclusive,
    so no protocol is ever considered against both checks. See
    _rank_key/PROTOCOL_NOTES and the module docstring's RANKED
    RECOMMENDATION section for the full ranking logic."""
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
    """Print the RATING CRITERIA table and the per-protocol
    plain-language lines (ALWAYS shown, under the "-- Rating --"
    heading). If show_recommendation is True (i.e. --recommend was
    passed), additionally print the ranked recommendation section
    described in the module docstring's RANKED RECOMMENDATION
    (--recommend) section."""
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
        return  # --recommend not set: everything above is always shown, this part is opt-in

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
    # Only known/finite when --loop and --max-rounds > 0; otherwise there
    # is no meaningful "n/total" to show, so --quiet-rounds has no effect
    # (see QUIET ROUNDS in the module docstring).
    total_rounds = args.max_rounds if args.loop and args.max_rounds else None
    quiet_progress_active = bool(args.quiet_rounds and args.loop and total_rounds)

    if quiet_progress_active:
        # Blank line to visually separate the progress line from any
        # setup/warm-up messages printed just before the loop starts.
        print()

    while True:
        if quiet_progress_active:
            # Overwrite the same console line in place instead of
            # printing a new line every round.
            sys.stdout.write(f"\rRound ({round_no}/{total_rounds})")
            sys.stdout.flush()
        else:
            print(f"\n-- Round {round_no} --\n")

        rows = run_round(domains, protocols, query_fns, args.rtype,
                          shuffle=args.shuffle, rng=rng)
        all_rows.extend(rows)
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

    if quiet_progress_active:
        # End the in-place progress line with a newline so the summary
        # below starts cleanly on its own line.
        sys.stdout.write("\n")
        sys.stdout.flush()

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
            query_fns[proto] = setup_protocol(proto, args, stack, domains[0])

        loop_runner(args, domains, protocols, query_fns)


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
                   help="Suppress per-round tables and show only a single, "
                        "in-place progress line 'Round (n/total)' that "
                        "overwrites itself; only meaningful with --loop and "
                        "a finite --max-rounds")
    p.add_argument("--recommend", action="store_true",
                   help="Show the ranked protocol recommendation section at the end "
                        "(opt-in; without this flag, only the always-shown per-protocol "
                        "plain-language lines and rating criteria table are printed)")
    p.add_argument("--csv", help="Optional path to append results as CSV")
    p.add_argument("--json", help="Optional path to write results and summary as JSON")
    p.add_argument("--no-answer", action="store_true",
                   help="Suppress the Answer column in table/CSV/JSON output")
    p.add_argument("--domains-file", help="Text file with one domain per line")
    p.add_argument("domains", nargs="*", help="Domain names to test")
    args = p.parse_args()

    run(args)


if __name__ == "__main__":
    main()
