#Requires -Version 5.1
#
# dnsperftest.ps1 - DNS resolver latency benchmark (PowerShell port)
# ====================================================================
#
# PURPOSE
#   Measures DNS query latency of a configurable list of DNS resolvers
#   (IPv4 and/or IPv6) against a configurable list of test domains, and
#   reports the results as a sorted table / CSV / TSV / JSON.
#   Functionally equivalent to dnsperftest.sh.
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
#   With -Repeat N, this entire domain x provider matrix is executed as
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
#   Average column).
#
# IMPLEMENTATION NOTES / KNOWN LIMITATIONS
#   - DNS queries are sent as raw UDP packets (bypassing Resolve-DnsName)
#     for accurate, low-overhead latency measurement. Every query uses a
#     fixed transaction ID (0x1234); this is safe because queries run
#     strictly sequentially on a single UDP socket per query, but the
#     response is validated to actually start with that same transaction
#     ID before its timing is accepted, to reject stray/malformed UDP
#     packets. If this script were ever parallelized, transaction IDs
#     would need to be randomized/unique per in-flight query.
#   - IPv6 support detection uses a connected UDP socket purely to force
#     a local routing-table lookup (Connect() on a UDP socket does not
#     put any packet on the wire) instead of sending a live DNS query to
#     one specific external resolver. This is fast and does not depend
#     on that resolver being reachable, but it is a heuristic: it only
#     confirms that an IPv6 route exists, not that the path is actually
#     usable end-to-end.
#   - Provider names and domain names are used as parts of an internal
#     "provider|domain" hashtable key and must therefore not contain the
#     '|' character; this is validated at startup.
#   - Table column widths are computed dynamically from the actually
#     rendered content (domain header labels and measured values), not
#     from the raw domain name length. Table headers show a shortened
#     domain label (TLD stripped, e.g. "wikipedia.org" -> "wikipedia")
#     so columns stay compact even though domain names are usually
#     longer than the "NN.NNms" values printed underneath them. CSV/TSV/
#     JSON output always use the full, untruncated domain name.
#   - Error reporting uses a dedicated Write-ErrorMessage helper instead
#     of PowerShell's Write-Error. Write-Error becomes a *terminating*
#     error under $ErrorActionPreference = 'Stop' (set below), which
#     would abort the script before it reaches the intended `exit 1` /
#     `exit 2` statements and make the documented exit-code contract
#     unreliable. Write-ErrorMessage writes directly to stderr and lets
#     the subsequent explicit `exit N` run as intended.
#
# EXIT CODES
#   0 = at least one provider answered successfully
#   1 = invalid usage / missing dependency
#   2 = all tested providers failed (error or timeout)

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

# Per-query timeout in milliseconds, derived from -Timeout (seconds).
$TimeoutMs = $Timeout * 1000

# Latency color thresholds in ms (configurable)
$ThresholdGreen  = 25
$ThresholdYellow = 50
$ThresholdOrange = 100

# Writes an error message to stderr without triggering PowerShell's
# terminating-error behavior (see IMPLEMENTATION NOTES above), so the
# explicit `exit N` right after it always executes.
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
  domain1/providerN, domain2/provider1, ... This gives every provider a
  fair, time-aligned comparison instead of hammering one provider with
  all domains before moving to the next.

  With -Repeat N, the full domain x provider matrix is run N times in
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
  based on ThresholdGreen / ThresholdYellow / ThresholdOrange (ms).
  "error"/"timeout" are highlighted in red. Column widths adapt to the
  actual rendered content; domain headers show a shortened label (TLD
  stripped) so columns stay compact. CSV/TSV/JSON always use full domain
  names.

Implementation note:
  DNS queries are sent as raw UDP packets (bypassing Resolve-DnsName) for
  accurate, low-overhead latency measurement; the response's transaction
  ID is validated before its timing is accepted.

Exit codes:
  0 = at least one provider answered successfully
  1 = invalid usage / missing dependency
  2 = all tested providers failed (error or timeout)
"@ | Write-Output
}

if ($Help) {
    Show-Usage
    exit 0
}

# ---------------------------------------------------------------------------
# Provider / domain configuration
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

# Shortened labels (TLD stripped) used only for compact table headers.
# CSV/TSV/JSON output always use the full domain names in $Domains.
$DomainLabels = $Domains | ForEach-Object {
    $idx = $_.LastIndexOf('.')
    if ($idx -gt 0) { $_.Substring(0, $idx) } else { $_ }
}

# Validate that no configured name contains '|', since it is used both as
# the internal hashtable-key separator and (implicitly) must not collide
# with itself across providers.
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

# Fixed transaction ID used for every query. Safe here because queries run
# strictly sequentially (one UDP socket per query, closed before the next
# one opens) and the response is validated against this same ID below.
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

        $isValidResponse = $response.Length -ge 2 -and
            $response[0] -eq $DnsTransactionId[0] -and
            $response[1] -eq $DnsTransactionId[1]

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
    if ($Value -le $ThresholdGreen)  { return 'Green' }
    if ($Value -le $ThresholdYellow) { return 'Yellow' }
    if ($Value -le $ThresholdOrange) { return 'DarkYellow' }
    return 'Red'
}

# ---------------------------------------------------------------------------
# IPv6 support detection
#   Uses a connected UDP socket to trigger a local routing-table lookup
#   without sending any packet on the wire (System.Net UDP "Connect" only
#   resolves the outbound route/interface, same idea as "ip -6 route get").
#   This makes the detection independent of any single external resolver
#   actually being reachable.
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

# Provider-name column width (data columns are sized dynamically later,
# from actually rendered content, inside Print-Table).
$providerColWidth = [Math]::Max(($providersToTest | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum + 2, 10)

# ---------------------------------------------------------------------------
# Main measurement loop
#   Order: pass -> domain -> provider (interleaved, see header comment).
#   Results are accumulated in hashtables keyed by "provider|domain" so
#   that grouping/printing per provider afterwards is a simple lookup.
# ---------------------------------------------------------------------------
$sumTime      = @{}   # accumulated successful query time (ms) per "provider|domain"
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
# Aggregate results per provider (one row per provider, one value per
# domain, plus an overall Average) from the accumulated hashtables.
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
function Write-ColoredValue {
    param($Value, [string]$Unit = '')

    if ($Value -is [double] -or $Value -is [int]) {
        $color = Get-LatencyColor -Value $Value
        Write-Host -NoNewline "$Value$Unit" -ForegroundColor $color
    } elseif ($Value -eq 'error' -or $Value -eq 'timeout') {
        Write-Host -NoNewline "$Value" -ForegroundColor Red
    } else {
        Write-Host -NoNewline "$Value"
    }
}

function Format-CellDisplay {
    param($Value)
    if ($Value -is [double] -or $Value -is [int]) { return "${Value}ms" }
    return "$Value"
}

# Print-Table: renders the sorted results as an aligned, color-coded
# table. Column width per domain is computed from the actually rendered
# content (the shortened domain label in the header, and the widest
# "NN.NNms"/"error"/"timeout" value in that column across all providers)
# rather than from the raw (often much longer) domain name. This keeps
# columns compact instead of being stretched out to fit full domain
# names like "wikipedia.org" or "instagram.com".
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
        $line = $row.Provider + "," + (($row.Tests) -join ",") + "," + $row.Average
        Write-Output $line
    }
}

function Print-Tsv {
    $header = "provider"
    foreach ($domain in $Domains) { $header += "`t$domain" }
    $header += "`taverage"
    Write-Output $header

    foreach ($row in $sortedResults) {
        $line = $row.Provider + "`t" + (($row.Tests) -join "`t") + "`t" + $row.Average
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
            average  = "$($row.Average)"
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
