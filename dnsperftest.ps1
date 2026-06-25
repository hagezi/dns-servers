#Requires -Version 5.1
<#
===============================================================================

  dnsperftest.ps1  -  DNS performance test
  PowerShell port of dnsperftest.sh (hagezi/dns-servers)

-------------------------------------------------------------------------------
  DESCRIPTION
-------------------------------------------------------------------------------

  Measures DNS resolution time for several domains against a set of public
  DNS servers, computes the average per server and prints the result sorted.

  Unlike the original (dig/drill), this port uses 'Resolve-DnsName' and
  measures the response time via a Stopwatch (wall-clock time of the call).
  This is functionally equivalent to dig's "Query time" but is an
  approximation.

-------------------------------------------------------------------------------
  HOW TO RUN
-------------------------------------------------------------------------------

  Requires Windows PowerShell 5.1+ (uses the built-in Resolve-DnsName).

  Run it once without changing your system's execution policy:

      powershell -ExecutionPolicy Bypass -File .\dnsperftest.ps1 all table

  Replace the arguments as needed, e.g.:

      powershell -ExecutionPolicy Bypass -File .\dnsperftest.ps1 ipv4 csv -Sort slowest

  Note: -ExecutionPolicy Bypass applies only to this single invocation;
        it does not change any machine- or user-wide setting.

-------------------------------------------------------------------------------
  ARGUMENTS                                  (all optional, any order)
-------------------------------------------------------------------------------

  mode      ipv4 | ipv6 | all                default: ipv4
  format    table | csv | tsv | json         default: table
  -Sort     fastest | slowest                default: fastest
              fastest = lowest  average latency first
              slowest = highest average latency first

-------------------------------------------------------------------------------
  EXAMPLES
-------------------------------------------------------------------------------

  .\dnsperftest.ps1
  .\dnsperftest.ps1 ipv4 table
  .\dnsperftest.ps1 all csv
  .\dnsperftest.ps1 all csv -Sort slowest
  .\dnsperftest.ps1 ipv6 json -Sort fastest

===============================================================================
#>

# --- Manual argument handling (allows positional args like the original) ---
$mode     = 'ipv4'
$format   = 'table'
$sortMode = 'fastest'

$argList = @($args)
for ($i = 0; $i -lt $argList.Count; $i++) {
    $a = [string]$argList[$i]
    switch -Regex ($a) {
        '^(ipv4|ipv6|all)$'          { $mode   = $a.ToLower(); continue }
        '^(table|csv|tsv|json)$'     { $format = $a.ToLower(); continue }
        '^(-{1,2}sort)$' {
            $i++
            if ($i -ge $argList.Count) { Write-Error 'error: -Sort requires a value'; exit 1 }
            $v = ([string]$argList[$i]).ToLower()
            if ($v -ne 'fastest' -and $v -ne 'slowest') {
                Write-Error "error: unsupported sort mode: $v"; exit 1
            }
            $sortMode = $v
            continue
        }
        default { Write-Error "error: unknown argument: $a"; exit 1 }
    }
}

# --- DNS servers (IP#Name) ---
$providersV4 = @(
    '1.1.1.1#Cloudflare'
    '8.8.8.8#Google'
    '9.9.9.9#Quad9'
    '208.67.222.222#OpenDNS'
    '94.140.14.140#AdGuard-DNS'
    '76.76.2.0#ControlD'
    '188.34.161.210#HaGeZi-Root'
    '159.69.155.94#HaGeZi-Wurzn'
    '162.55.58.40#HaGeZi-CTIF'
    '95.217.163.17#HaGeZi-Juuri'
)

$providersV6 = @(
    '2606:4700:4700::1111#Cloudflare-v6'
    '2001:4860:4860::8888#Google-v6'
    '2620:fe::fe#Quad9-v6'
    '2620:119:35::35#OpenDNS-v6'
    '2a10:50c0::1:ff#AdGuard-DNS-v6'
    '2606:1a40::#ControlD-v6'
    '2a01:4f8:c17:1c66::1#HaGeZi-Root-v6'
    '2a01:4f8:1c1c:d363::1#HaGeZi-Wurzn-v6'
    '2a01:4f8:1c19:6c19::1#HaGeZi-CTIF-v6'
    '2a01:4f9:c013:dc4e::1#HaGeZi-Juuri-v6'
)

$domains2Test = @(
    'google.com'
    'youtube.com'
    'facebook.com'
    'instagram.com'
    'x.com'
    'whatsapp.com'
    'reddit.com'
    'wikipedia.org'
    'amazon.com'
    'tiktok.com'
)

# --- Single DNS query against one server, returns ms (int) ---
function Measure-Query {
    param([string]$Server, [string]$Domain)

    $elapsed = $null
    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $res = Resolve-DnsName -Name $Domain -Server $Server -Type A `
                   -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop
        $sw.Stop()
        if ($res) { $elapsed = $sw.Elapsed.TotalMilliseconds }
    } catch {
        $elapsed = $null
    }

    if ($null -eq $elapsed)      { return 1000 }   # error/timeout -> same as original
    $ms = [int][math]::Round($elapsed)
    if ($ms -eq 0)               { return 1 }      # 0 ms -> 1 (original behavior)
    return $ms
}

# --- Check IPv6 availability (analogous to the original) ---
$hasIPv6 = $false
try {
    $probe = Resolve-DnsName -Name 'www.google.com' -Server '2001:4860:4860::8888' `
                 -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop
    if ($probe) { $hasIPv6 = $true }
} catch { $hasIPv6 = $false }

# --- Select the providers to test ---
switch ($mode) {
    'ipv4' { $providersToTest = $providersV4 }
    'ipv6' {
        if (-not $hasIPv6) { Write-Error 'error: IPv6 support not found. Unable to do the ipv6 test.'; exit 1 }
        $providersToTest = $providersV6
    }
    'all'  {
        if ($hasIPv6) { $providersToTest = $providersV4 + $providersV6 }
        else          { $providersToTest = $providersV4 }
    }
}

$totalDomains = $domains2Test.Count

# --- Run the measurements ---
$results = New-Object System.Collections.Generic.List[object]
foreach ($p in $providersToTest) {
    if ([string]::IsNullOrWhiteSpace($p)) { continue }

    $pip   = ($p -split '#', 2)[0]
    $pname = ($p -split '#', 2)[1]
    if ([string]::IsNullOrWhiteSpace($pname)) { $pname = $pip }

    $times = New-Object System.Collections.Generic.List[int]
    $sum = 0
    foreach ($d in $domains2Test) {
        $t = Measure-Query -Server $pip -Domain $d
        [void]$times.Add($t)
        $sum += $t
    }

    $avg = [math]::Round($sum / [double]$totalDomains, 2)
    # Always display with a dot as the decimal separator (like bc in the original),
    # regardless of the system locale (e.g. sv-SE would otherwise use a comma!).
    $avgStr = $avg.ToString('F2', [System.Globalization.CultureInfo]::InvariantCulture)

    $results.Add([pscustomobject]@{
        Provider   = $pname
        Times      = $times
        Average    = $avg      # numeric -> used for sorting
        AverageStr = $avgStr   # formatted -> used for output
    })
}

# --- Sort ---
if ($sortMode -eq 'fastest') {
    $sorted = $results | Sort-Object Average
} else {
    $sorted = $results | Sort-Object Average -Descending
}

# --- Output functions ---
function Write-AsTable {
    $line = ('{0,-21}' -f '')
    for ($i = 1; $i -le $totalDomains; $i++) { $line += ('{0,-10}' -f "Test$i") }
    $line += ('{0,-10}' -f 'Average')
    Write-Output $line

    foreach ($r in $sorted) {
        $line = ('{0,-21}' -f $r.Provider)
        for ($i = 0; $i -lt $totalDomains; $i++) {
            $line += ('{0,-10}' -f ("$($r.Times[$i])ms"))
        }
        $line += ('{0}' -f $r.AverageStr)
        Write-Output $line
    }
}

function Write-AsCsv {
    $header = 'provider'
    for ($i = 1; $i -le $totalDomains; $i++) { $header += ",test$i" }
    $header += ',average'
    Write-Output $header

    foreach ($r in $sorted) {
        $cells = @($r.Provider) + ($r.Times | ForEach-Object { "$_" }) + @($r.AverageStr)
        Write-Output ($cells -join ',')
    }
}

function Write-AsTsv {
    $header = 'provider'
    for ($i = 1; $i -le $totalDomains; $i++) { $header += "`ttest$i" }
    $header += "`taverage"
    Write-Output $header

    foreach ($r in $sorted) {
        $cells = @($r.Provider) + ($r.Times | ForEach-Object { "$_" }) + @($r.AverageStr)
        Write-Output ($cells -join "`t")
    }
}

function Write-AsJson {
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('[')
    $first = $true
    foreach ($r in $sorted) {
        if (-not $first) { [void]$sb.AppendLine(',') }
        $first = $false
        $resultsCsv = ($r.Times -join ',')
        [void]$sb.Append(('  {{"provider":"{0}","results":[{1}],"average":"{2}"}}' -f `
            $r.Provider, $resultsCsv, $r.AverageStr))
    }
    [void]$sb.AppendLine('')
    [void]$sb.Append(']')
    Write-Output $sb.ToString()
}

switch ($format) {
    'table' { Write-AsTable }
    'csv'   { Write-AsCsv }
    'tsv'   { Write-AsTsv }
    'json'  { Write-AsJson }
}

exit 0
