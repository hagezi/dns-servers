#Requires -Version 5.1
# SPDX-License-Identifier: GPL-3.0-only
#
# dnsperftest.ps1 - DNS resolver latency benchmark (PowerShell port)
# ====================================================================
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
#   table, CSV, TSV, or JSON. Works the same way as dnsperftest.sh.
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
#   With -Repeat N, the whole domain x provider matrix runs N times in a
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
#   - DNS queries are sent as raw UDP packets instead of through
#     Resolve-DnsName, which keeps the overhead in the measurement low.
#     Every query uses the fixed transaction ID 0x1234. That is safe
#     because the queries run strictly one after another, each on its own
#     UDP socket. A reply is only accepted if it comes from the queried
#     server, carries the same transaction ID, has the QR (response) bit
#     set, and reports RCODE NOERROR. Anything else (stray packets,
#     SERVFAIL, NXDOMAIN, REFUSED, ...) counts as "error", as in
#     dnsperftest.sh. If the script ever sends queries in parallel, each
#     in-flight query needs its own random transaction ID.
#   - Latencies are printed with exactly two decimals and '.' as decimal
#     separator, whatever the Windows locale, so table, CSV, and TSV output
#     match dnsperftest.sh. In JSON, latencies and the average are numbers;
#     only "error" and "timeout" are strings.
#   - IPv6 support is detected by connecting a UDP socket, which only
#     makes the OS look up the outgoing route (Connect() on a UDP socket
#     sends no packet). No live query goes to an external resolver, so the
#     check is fast and does not depend on that server being reachable,
#     but it only confirms that an IPv6 route exists, not that the path
#     actually works end to end.
#   - Provider and domain names are part of an internal "provider|domain"
#     hashtable key, so they must not contain '|'. This is checked at
#     startup.
#   - Table column widths follow the rendered content (header labels and
#     measured values), not the length of the domain names. The headers
#     show the domain without its TLD (e.g. "wikipedia.org" ->
#     "wikipedia") to keep the columns narrow. CSV, TSV, and JSON always
#     use the full domain name.
#   - Errors are reported with the Write-ErrorMessage helper instead of
#     Write-Error. With $ErrorActionPreference = 'Stop' (set below),
#     Write-Error is a terminating error and would end the script before
#     the explicit `exit 1` / `exit 2`, so the documented exit codes would
#     not be returned. Write-ErrorMessage writes to stderr and lets the
#     following `exit N` run.
#
# EXIT CODES
#   0 = at least one provider answered successfully
#   1 = invalid usage / missing dependency
#   2 = all tested providers failed (error or timeout)
#
# RUNNING THE SCRIPT
#   Windows blocks downloaded scripts that are not signed. Remove the
#   download mark once with:
#     Unblock-File .\dnsperftest.ps1
#   If running scripts is disabled entirely, allow them for your user:
#     Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
#   or run it a single time without the policy check:
#     powershell -ExecutionPolicy Bypass -File .\dnsperftest.ps1

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('ipv4', 'ipv6', 'all')]
    [string]$Mode = 'ipv4',

    [Parameter(Position = 1)]
    [ValidateSet('table', 'csv', 'tsv', 'json')]
    [string]$Format = 'table',

    [ValidateSet('fastest', 'slowest')]
    [string]$Sort = 'fastest',

    [ValidateRange(1, [int]::MaxValue)]
    [int]$Repeat = 1,

    [ValidateRange(1, [int]::MaxValue)]
    [int]$Timeout = 1,

    [Alias('h')]
    [switch]$Help
)

$ErrorActionPreference = 'Stop'

# Per-query timeout in milliseconds, from -Timeout (seconds).
$TimeoutMs = $Timeout * 1000

# Latency color thresholds in ms. A value below a threshold gets that
# color; the defaults follow the rating scale in the HaGeZi DNS README
# (< 20 excellent, < 50 very good, < 100 OK, < 200 average/slow).
$ThresholdGreen  = 20
$ThresholdYellow = 50
$ThresholdOrange = 100
$ThresholdRed    = 200

# Writes an error message to stderr without raising a terminating error
# (see IMPLEMENTATION NOTES above), so the explicit `exit N` right after
# it always runs.
function Write-ErrorMessage {
    param([string]$Message)
    [Console]::Error.WriteLine($Message)
}

function Show-Usage {
    @"
Usage:
  dnsperftest.ps1 [-Mode ipv4|ipv6|all] [-Format table|csv|tsv|json] [-Sort fastest|slowest] [-Repeat N] [-Timeout SEC]
  dnsperftest.ps1 -Help

Examples:
  .\dnsperftest.ps1
  .\dnsperftest.ps1 ipv4 table
  .\dnsperftest.ps1 all csv
  .\dnsperftest.ps1 all csv -Sort slowest
  .\dnsperftest.ps1 ipv6 json -Sort fastest
  .\dnsperftest.ps1 ipv4 table -Repeat 3
  .\dnsperftest.ps1 ipv4 table -Repeat 3 -Timeout 2
  .\dnsperftest.ps1 -Help

Defaults:
  Mode    = ipv4
  Format  = table
  Sort    = fastest
  Repeat  = 1
  Timeout = 1 (seconds, per single query)

Query order:
  Queries are interleaved: domain1/provider1, domain1/provider2, ...,
  domain1/providerN, domain2/provider1, ... All providers are measured
  for the same domain at nearly the same time, and no provider gets all
  domains in a row before the next one starts.

  With -Repeat N, the full domain x provider matrix runs N times in a
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
  good), orange < 100 ms (OK), red < 200 ms (average to slow), dark
  red >= 200 ms (very slow). "error" and "timeout" are shown in red.
  Column widths follow the content, and domain headers omit the TLD to
  keep the columns narrow. CSV, TSV, and JSON always use full domain
  names.

Implementation note:
  DNS queries are sent as raw UDP packets instead of through
  Resolve-DnsName, to keep the overhead in the measurement low. A reply
  only counts if it comes from the queried server, matches the
  transaction ID, and reports RCODE NOERROR.

Exit codes:
  0 = at least one provider answered successfully
  1 = invalid usage / missing dependency
  2 = all tested providers failed (error or timeout)

Running the script:
  Windows blocks downloaded scripts that are not signed ("not digitally
  signed" error). Remove the download mark once with:
    Unblock-File .\dnsperftest.ps1
  If the error says that running scripts is disabled on this system,
  allow scripts for your user once:
    Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
  or run it a single time without the policy check:
    powershell -ExecutionPolicy Bypass -File .\dnsperftest.ps1
"@ | Write-Output
}

if ($Help) {
    Show-Usage
    exit 0
}

# ---------------------------------------------------------------------------
# Providers and test domains
# ---------------------------------------------------------------------------
$ProvidersV4 = @(
    [PSCustomObject]@{ Ip = '1.1.1.1';         Name = 'Cloudflare' }
    [PSCustomObject]@{ Ip = '8.8.8.8';         Name = 'Google' }
    [PSCustomObject]@{ Ip = '9.9.9.9';         Name = 'Quad9' }
    [PSCustomObject]@{ Ip = '9.9.9.11';        Name = 'Quad9-ECS' }
    [PSCustomObject]@{ Ip = '208.67.222.222';  Name = 'OpenDNS' }
    [PSCustomObject]@{ Ip = '86.54.11.1';      Name = 'DNS4EU' }
    [PSCustomObject]@{ Ip = '94.140.14.140';   Name = 'AdGuard-DNS' }
    [PSCustomObject]@{ Ip = '76.76.2.0';       Name = 'ControlD' }
    [PSCustomObject]@{ Ip = '176.9.93.198';    Name = 'DNSForge' }
    [PSCustomObject]@{ Ip = '188.34.161.210';  Name = 'HaGeZi-Root' }
    [PSCustomObject]@{ Ip = '159.69.155.94';   Name = 'HaGeZi-Wurzn' }
    [PSCustomObject]@{ Ip = '162.55.58.40';    Name = 'HaGeZi-CTIF' }
    [PSCustomObject]@{ Ip = '95.217.163.17';   Name = 'HaGeZi-Juuri' }
)

$ProvidersV6 = @(
    [PSCustomObject]@{ Ip = '2606:4700:4700::1111';        Name = 'Cloudflare-v6' }
    [PSCustomObject]@{ Ip = '2001:4860:4860::8888';        Name = 'Google-v6' }
    [PSCustomObject]@{ Ip = '2620:fe::fe';                 Name = 'Quad9-v6' }
    [PSCustomObject]@{ Ip = '2620:fe::11';                 Name = 'Quad9-ECS-v6' }
    [PSCustomObject]@{ Ip = '2620:119:35::35';             Name = 'OpenDNS-v6' }
    [PSCustomObject]@{ Ip = '2a13:1001::86:54:11:1';       Name = 'DNS4EU-v6' }
    [PSCustomObject]@{ Ip = '2a10:50c0::1:ff';             Name = 'AdGuard-DNS-v6' }
    [PSCustomObject]@{ Ip = '2606:1a40::';                 Name = 'ControlD-v6' }
    [PSCustomObject]@{ Ip = '2a01:4f8:151:34aa::198';      Name = 'DNSForge-v6' }
    [PSCustomObject]@{ Ip = '2a01:4f8:c17:1c66::1';        Name = 'HaGeZi-Root-v6' }
    [PSCustomObject]@{ Ip = '2a01:4f8:1c1c:d363::1';       Name = 'HaGeZi-Wurzn-v6' }
    [PSCustomObject]@{ Ip = '2a01:4f8:1c19:6c19::1';       Name = 'HaGeZi-CTIF-v6' }
    [PSCustomObject]@{ Ip = '2a01:4f9:c013:dc4e::1';       Name = 'HaGeZi-Juuri-v6' }
)

$Domains = @(
    'google.com', 'youtube.com', 'facebook.com', 'instagram.com', 'x.com',
    'whatsapp.com', 'reddit.com', 'wikipedia.org', 'amazon.com', 'tiktok.com'
)

# Short labels without the TLD, used only for the table header.
# CSV, TSV, and JSON always use the full domain names in $Domains.
$DomainLabels = $Domains | ForEach-Object {
    $idx = $_.LastIndexOf('.')
    if ($idx -gt 0) { $_.Substring(0, $idx) } else { $_ }
}

# Reject names containing '|', since it separates provider and domain in
# the internal hashtable key.
foreach ($p in ($ProvidersV4 + $ProvidersV6)) {
    if ($p.Name.Contains('|')) {
        Write-ErrorMessage "error: provider name '$($p.Name)' contains the reserved '|' character."
        exit 1
    }
}
foreach ($d in $Domains) {
    if ($d.Contains('|')) {
        Write-ErrorMessage "error: domain '$d' contains the reserved '|' character."
        exit 1
    }
}

# ---------------------------------------------------------------------------
# DNS query helpers
# ---------------------------------------------------------------------------

# Fixed transaction ID for every query. Safe because the queries run
# strictly one after another (one UDP socket per query, closed before the
# next one opens), and each reply is checked against this ID below.
$DnsTransactionId = [byte[]]@(0x12, 0x34)

function Build-DnsQueryPacket {
    param([string]$Domain)

    $bytes = New-Object System.Collections.Generic.List[byte]

    $bytes.AddRange($DnsTransactionId)
    # Flags: standard recursive query
    $bytes.AddRange([byte[]]@(0x01, 0x00))
    # Questions: 1
    $bytes.AddRange([byte[]]@(0x00, 0x01))
    # Answer / Authority / Additional RRs: 0
    $bytes.AddRange([byte[]]@(0x00, 0x00))
    $bytes.AddRange([byte[]]@(0x00, 0x00))
    $bytes.AddRange([byte[]]@(0x00, 0x00))

    foreach ($label in $Domain.Split('.')) {
        $labelBytes = [System.Text.Encoding]::ASCII.GetBytes($label)
        $bytes.Add([byte]$labelBytes.Length)
        $bytes.AddRange($labelBytes)
    }
    $bytes.Add(0x00)

    # Type A, Class IN
    $bytes.AddRange([byte[]]@(0x00, 0x01))
    $bytes.AddRange([byte[]]@(0x00, 0x01))

    return $bytes.ToArray()
}

function Test-DnsQuery {
    param(
        [string]$ServerIp,
        [string]$Domain,
        [int]$TimeoutMs
    )

    $udpClient = $null
    try {
        $ipAddr = [System.Net.IPAddress]::Parse($ServerIp)
        $udpClient = New-Object System.Net.Sockets.UdpClient($ipAddr.AddressFamily)
        $udpClient.Client.ReceiveTimeout = $TimeoutMs

        $endpoint = New-Object System.Net.IPEndPoint ($ipAddr, 53)
        $queryBytes = Build-DnsQueryPacket -Domain $Domain

        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $udpClient.Send($queryBytes, $queryBytes.Length, $endpoint) | Out-Null

        $remoteEndpoint = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Any, 0)
        $response = $udpClient.Receive([ref]$remoteEndpoint)
        $sw.Stop()

        # A usable reply must come from the queried server, carry our
        # transaction ID, be a response (QR bit, byte 2), and report RCODE
        # NOERROR (low 4 bits of byte 3). A full DNS header is 12 bytes.
        $isValidResponse = $response.Length -ge 12 -and
            $remoteEndpoint.Address.Equals($ipAddr) -and
            $response[0] -eq $DnsTransactionId[0] -and
            $response[1] -eq $DnsTransactionId[1] -and
            ($response[2] -band 0x80) -ne 0 -and
            ($response[3] -band 0x0F) -eq 0

        if ($isValidResponse) {
            return [PSCustomObject]@{ Status = 'ok'; Ms = $sw.Elapsed.TotalMilliseconds }
        } else {
            return [PSCustomObject]@{ Status = 'error'; Ms = $null }
        }
    } catch [System.Net.Sockets.SocketException] {
        if ($_.Exception.SocketErrorCode -eq [System.Net.Sockets.SocketError]::TimedOut) {
            return [PSCustomObject]@{ Status = 'timeout'; Ms = $null }
        } else {
            return [PSCustomObject]@{ Status = 'error'; Ms = $null }
        }
    } catch {
        return [PSCustomObject]@{ Status = 'error'; Ms = $null }
    } finally {
        if ($udpClient) { $udpClient.Dispose() }
    }
}

function Get-LatencyColor {
    param([double]$Value)
    if ($Value -lt $ThresholdGreen)  { return 'Green' }
    if ($Value -lt $ThresholdYellow) { return 'Yellow' }
    if ($Value -lt $ThresholdOrange) { return 'DarkYellow' }
    if ($Value -lt $ThresholdRed)    { return 'Red' }
    return 'DarkRed'
}

# ---------------------------------------------------------------------------
# IPv6 support detection
#   Connecting a UDP socket makes the OS look up the outgoing route and
#   interface without sending a packet, similar to "ip -6 route get".
#   The check therefore does not depend on any external resolver being
#   reachable.
# ---------------------------------------------------------------------------
function Test-Ipv6Support {
    $udp = $null
    try {
        $udp = New-Object System.Net.Sockets.UdpClient([System.Net.Sockets.AddressFamily]::InterNetworkV6)
        $udp.Connect([System.Net.IPAddress]::Parse('2606:4700:4700::1111'), 53)
        return $true
    } catch {
        return $false
    } finally {
        if ($udp) { $udp.Dispose() }
    }
}

$hasIpv6 = Test-Ipv6Support

switch ($Mode) {
    'ipv4' { $providersToTest = $ProvidersV4 }
    'ipv6' {
        if (-not $hasIpv6) {
            Write-ErrorMessage "error: IPv6 support not found. Unable to do the ipv6 test."
            exit 1
        }
        $providersToTest = $ProvidersV6
    }
    'all' {
        $providersToTest = if ($hasIpv6) { $ProvidersV4 + $ProvidersV6 } else { $ProvidersV4 }
    }
}

$totalDomains   = $Domains.Count
$totalProviders = $providersToTest.Count

if ($totalProviders -eq 0) {
    Write-ErrorMessage "error: no providers configured for mode '$Mode'."
    exit 1
}

$totalQueries = $Repeat * $totalDomains * $totalProviders

# Width of the provider column. The data columns are sized later in
# Print-Table, from the rendered content.
$providerColWidth = [Math]::Max(($providersToTest | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum + 2, 10)

# ---------------------------------------------------------------------------
# Main measurement loop
#   Order: pass -> domain -> provider (interleaved, see header comment).
#   Results are collected in hashtables keyed by "provider|domain", so
#   printing them per provider afterwards is a simple lookup.
# ---------------------------------------------------------------------------
$sumTime      = @{}   # summed query time (ms) of successful queries per "provider|domain"
$countSuccess = @{}   # number of successful queries per "provider|domain"
$countTimeout = @{}   # number of timeouts per "provider|domain"

$queryNum = 0
for ($pass = 1; $pass -le $Repeat; $pass++) {
    foreach ($domain in $Domains) {
        foreach ($provider in $providersToTest) {
            $queryNum++
            Write-Host -NoNewline ("`rTesting DNS servers... [{0}/{1}] pass {2}/{3}  {4,-20} -> {5,-20}" -f `
                $queryNum, $totalQueries, $pass, $Repeat, $domain, $provider.Name)

            $key = "$($provider.Name)|$domain"
            $res = Test-DnsQuery -ServerIp $provider.Ip -Domain $domain -TimeoutMs $TimeoutMs

            if ($res.Status -eq 'ok') {
                if (-not $sumTime.ContainsKey($key)) {
                    $sumTime[$key] = 0.0
                    $countSuccess[$key] = 0
                }
                $sumTime[$key] += $res.Ms
                $countSuccess[$key]++
            } elseif ($res.Status -eq 'timeout') {
                if (-not $countTimeout.ContainsKey($key)) { $countTimeout[$key] = 0 }
                $countTimeout[$key]++
            }
        }
    }
}

Write-Host ("`r" + (' ' * 100) + "`r") -NoNewline

# ---------------------------------------------------------------------------
# Build one result row per provider (one value per domain plus the overall
# Average) from the collected hashtables.
# ---------------------------------------------------------------------------
$results = @()
$successfulProviders = 0

foreach ($provider in $providersToTest) {
    $testValues = @()
    $ftime = 0.0
    $successCount = 0
    $anyTimeout = $false

    foreach ($domain in $Domains) {
        $key = "$($provider.Name)|$domain"
        $dsuccess = if ($countSuccess.ContainsKey($key)) { $countSuccess[$key] } else { 0 }
        $dtimeout = if ($countTimeout.ContainsKey($key)) { $countTimeout[$key] } else { 0 }
        $dtime    = if ($sumTime.ContainsKey($key)) { $sumTime[$key] } else { 0.0 }

        if ($dsuccess -gt 0) {
            $value = [math]::Round($dtime / $dsuccess, 2)
            $testValues += $value
            $ftime += $value
            $successCount++
        } elseif ($dtimeout -gt 0) {
            $testValues += 'timeout'
            $anyTimeout = $true
        } else {
            $testValues += 'error'
        }
    }

    if ($successCount -gt 0) {
        $avg = [math]::Round($ftime / $successCount, 2)
        $sortKey = $avg
        $successfulProviders++
    } else {
        $avg = if ($anyTimeout) { 'timeout' } else { 'error' }
        $sortKey = 999999
    }

    $results += [PSCustomObject]@{
        Provider = $provider.Name
        Tests    = $testValues
        Average  = $avg
        SortKey  = $sortKey
    }
}

$sortedResults = if ($Sort -eq 'fastest') {
    $results | Sort-Object SortKey
} else {
    $results | Sort-Object SortKey -Descending
}

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
# Formats a latency with exactly two decimals and '.' as decimal separator,
# whatever the system locale (as in dnsperftest.sh, e.g. "12.50").
# Non-numeric values ("error"/"timeout") are returned unchanged.
function Format-Latency {
    param($Value)
    if ($Value -is [double] -or $Value -is [int]) {
        return $Value.ToString('0.00', [System.Globalization.CultureInfo]::InvariantCulture)
    }
    return "$Value"
}

function Write-ColoredValue {
    param($Value, [string]$Unit = '')

    if ($Value -is [double] -or $Value -is [int]) {
        $color = Get-LatencyColor -Value $Value
        Write-Host -NoNewline "$(Format-Latency $Value)$Unit" -ForegroundColor $color
    } elseif ($Value -eq 'error' -or $Value -eq 'timeout') {
        Write-Host -NoNewline "$Value" -ForegroundColor Red
    } else {
        Write-Host -NoNewline "$Value"
    }
}

function Format-CellDisplay {
    param($Value)
    if ($Value -is [double] -or $Value -is [int]) { return "$(Format-Latency $Value)ms" }
    return "$Value"
}

# Print-Table: prints the sorted results as an aligned, colored table.
# Each domain column is as wide as its widest rendered cell: the short
# header label or the widest "NN.NNms"/"error"/"timeout" value in that
# column. Full domain names such as "instagram.com" would make the
# columns much wider than the values below them.
function Print-Table {
    $colWidth = New-Object int[] $totalDomains
    for ($i = 0; $i -lt $totalDomains; $i++) {
        $colWidth[$i] = $DomainLabels[$i].Length
    }
    $avgWidth = 7 # length of "Average"

    foreach ($row in $sortedResults) {
        for ($i = 0; $i -lt $totalDomains; $i++) {
            $display = Format-CellDisplay -Value $row.Tests[$i]
            if ($display.Length -gt $colWidth[$i]) { $colWidth[$i] = $display.Length }
        }
        $avgDisplay = Format-CellDisplay -Value $row.Average
        if ($avgDisplay.Length -gt $avgWidth) { $avgWidth = $avgDisplay.Length }
    }

    $header = "{0,-$providerColWidth}" -f ""
    for ($i = 0; $i -lt $totalDomains; $i++) {
        $header += "{0,-$($colWidth[$i] + 2)}" -f $DomainLabels[$i]
    }
    $header += "{0,-$avgWidth}" -f "Average"
    Write-Host $header

    foreach ($row in $sortedResults) {
        Write-Host -NoNewline ("{0,-$providerColWidth}" -f $row.Provider)

        for ($i = 0; $i -lt $totalDomains; $i++) {
            $val = $row.Tests[$i]
            $display = Format-CellDisplay -Value $val
            Write-ColoredValue -Value $val -Unit 'ms'
            $padLen = $colWidth[$i] + 2 - $display.Length
            if ($padLen -lt 0) { $padLen = 0 }
            Write-Host -NoNewline (' ' * $padLen)
        }

        Write-ColoredValue -Value $row.Average -Unit 'ms'
        Write-Host ""
    }
}

function Print-Csv {
    $header = "provider"
    foreach ($domain in $Domains) { $header += ",$domain" }
    $header += ",average"
    Write-Output $header

    foreach ($row in $sortedResults) {
        $cells = @($row.Tests | ForEach-Object { Format-Latency $_ })
        $line = $row.Provider + "," + ($cells -join ",") + "," + (Format-Latency $row.Average)
        Write-Output $line
    }
}

function Print-Tsv {
    $header = "provider"
    foreach ($domain in $Domains) { $header += "`t$domain" }
    $header += "`taverage"
    Write-Output $header

    foreach ($row in $sortedResults) {
        $cells = @($row.Tests | ForEach-Object { Format-Latency $_ })
        $line = $row.Provider + "`t" + ($cells -join "`t") + "`t" + (Format-Latency $row.Average)
        Write-Output $line
    }
}

function Print-Json {
    $jsonObjects = foreach ($row in $sortedResults) {
        $resultsMap = [ordered]@{}
        for ($i = 0; $i -lt $Domains.Count; $i++) {
            $resultsMap[$Domains[$i]] = $row.Tests[$i]
        }
        [PSCustomObject]@{
            provider = $row.Provider
            results  = [PSCustomObject]$resultsMap
            # Number when measured, otherwise the string "error"/"timeout".
            average  = $row.Average
        }
    }
    $jsonObjects | ConvertTo-Json -Depth 4
}

switch ($Format) {
    'table' { Print-Table }
    'csv'   { Print-Csv }
    'tsv'   { Print-Tsv }
    'json'  { Print-Json }
}

if ($successfulProviders -eq 0) {
    Write-ErrorMessage "error: all tested providers failed (error or timeout)."
    exit 2
}

exit 0
