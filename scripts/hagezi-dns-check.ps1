# SPDX-License-Identifier: GPL-3.0-or-later

<#
.SYNOPSIS
    Connectivity and function test for HaGeZi DNS.

.DESCRIPTION
    Tests every HaGeZi DNS server over Do53, DoT, DoH and DoQ (IPv4 and IPv6):
    resolution, DNSSEC validation, blocking behaviour and ping latency.

    Runs natively in Windows PowerShell 5.1 and PowerShell 7, no extra tools
    needed. DoQ requires PowerShell 7.4 or newer on Windows 11 / Server 2022
    (or Linux/macOS with libmsquic); otherwise the DoQ test is skipped.

.PARAMETER Server
    One or more of: root wurzn juuri ctif (default: all).

.PARAMETER IPv4
    Test IPv4 only.

.PARAMETER IPv6
    Test IPv6 only.

.PARAMETER Version
    Show version and license.

.PARAMETER Help
    Show usage.

.EXAMPLE
    .\hagezi-dns-check.ps1

.EXAMPLE
    .\hagezi-dns-check.ps1 root ctif -IPv4 -Verbose

.NOTES
    Exit codes: 0 all passed, 1 at least one check failed, 2 invalid arguments

    Windows blocks downloaded scripts that are not signed. Remove the
    download mark once with:
      Unblock-File .\hagezi-dns-check.ps1
    or run it a single time without the policy check:
      powershell -ExecutionPolicy Bypass -File .\hagezi-dns-check.ps1

    Copyright (C) 2026 HaGeZi

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program. If not, see <https://www.gnu.org/licenses/>.
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
    [string[]]$Server,
    [switch]$IPv4,
    [switch]$IPv6,
    [switch]$Version,
    [switch]$Help
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

$ScriptVersion = '1.0.0'

$Servers = @(
    [pscustomobject]@{ Name = 'root';  V4 = '188.34.161.210'; V6 = '2a01:4f8:c17:1c66::1' }
    [pscustomobject]@{ Name = 'wurzn'; V4 = '159.69.155.94';  V6 = '2a01:4f8:1c1c:d363::1' }
    [pscustomobject]@{ Name = 'juuri'; V4 = '95.217.163.17';  V6 = '2a01:4f9:c013:dc4e::1' }
    [pscustomobject]@{ Name = 'ctif';  V4 = '162.55.58.40';   V6 = '2a01:4f8:1c19:6c19::1' }
)

$Protocols      = @('Do53', 'DoT', 'DoH', 'DoQ')
$ResolveDomains = @('example.com', 'wikipedia.org')
# DNSSEC: the AD flag is not passed on (Technitium -> Unbound),
# so validation is tested via the result for signed and deliberately broken zones
$DnssecOk    = 'isc.org'                                          # correctly signed -> NOERROR expected
$DnssecBogus = @('dnssec-failed.org', 'sigfail.verteiltesysteme.net') # broken signature -> SERVFAIL expected
$BlockDomain = 'app-measurement.com'  # 0.0.0.0 expected on full-protection servers, not on ctif
$TimeoutMs   = 5000
$PingCount   = 10

$EXIT_OK = 0; $EXIT_FAIL = 1; $EXIT_USAGE = 2

# --- output ----------------------------------------------------------------

$UseColor = -not $env:NO_COLOR
$Unicode  = ($PSVersionTable.PSVersion.Major -ge 7) -or [bool]$env:WT_SESSION
if ($Unicode) { try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { } }
$SymOk   = if ($Unicode) { [string][char]0x2713 } else { '+' }
$SymFail = if ($Unicode) { [string][char]0x2717 } else { 'x' }
$IsVerbose = $PSBoundParameters.ContainsKey('Verbose')

function Out-Part([string]$Text, [string]$Color = '') {
    if ($UseColor -and $Color) { Write-Host $Text -NoNewline -ForegroundColor $Color }
    else { Write-Host $Text -NoNewline }
}
function Out-Line([string]$Text = '', [string]$Color = '') { Out-Part $Text $Color; Write-Host '' }

function Out-Mark([int]$State) {
    switch ($State) {
        1       { Out-Part $SymOk 'Green' }
        2       { Out-Part '?' 'Yellow' }
        default { Out-Part $SymFail 'Red' }
    }
}

function Show-Usage {
@"
hagezi-dns-check.ps1 $ScriptVersion - test script for HaGeZi DNS

Tests every HaGeZi DNS server over Do53, DoT, DoH and DoQ (IPv4 and IPv6):
resolution, DNSSEC validation, blocking behaviour and ping latency.

Usage: .\hagezi-dns-check.ps1 [server ...] [options]

Options:
  -IPv4      test IPv4 only
  -IPv6      test IPv6 only
  -Verbose   show the result of every single query
  -Help      show this help
  -Version   show version and license

Servers: root wurzn juuri ctif (default: all)

Exit codes: 0 all passed, 1 at least one check failed, 2 invalid arguments

No extra tools needed. DoQ requires PowerShell 7.4 or newer on Windows 11 /
Server 2022 (install: winget install Microsoft.PowerShell), otherwise the
DoQ test is skipped. Set NO_COLOR=1 to disable colored output.

Windows blocks downloaded scripts that are not signed ("not digitally
signed" error). Remove the download mark once with:
  Unblock-File .\hagezi-dns-check.ps1
or run it a single time without the policy check:
  powershell -ExecutionPolicy Bypass -File .\hagezi-dns-check.ps1
"@
}

function Show-Version {
@"
hagezi-dns-check.ps1 $ScriptVersion
Copyright (C) 2026 HaGeZi
License GPLv3+: GNU GPL version 3 or later <https://www.gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
"@
}

# --- arguments -------------------------------------------------------------

if ($Help)    { Show-Usage;   exit $EXIT_OK }
if ($Version) { Show-Version; exit $EXIT_OK }
if ($IPv4 -and $IPv6) { $IPv4 = $false; $IPv6 = $false }   # both = default

$Select = @()
if ($Server) {
    foreach ($s in $Server) {
        $n = ($s -replace '\.hagezi\.org$', '').ToLowerInvariant()
        if ($Servers.Name -notcontains $n) {
            Write-Host "Unknown argument: $s"; Write-Host ''; Show-Usage; exit $EXIT_USAGE
        }
        $Select += $n
    }
}

$Families = @()
if (-not $IPv6) { $Families += 4 }
if (-not $IPv4) { $Families += 6 }

# --- helpers ---------------------------------------------------------------

function Get-RootMessage($Exception) {
    $e = $Exception
    while ($e.InnerException) { $e = $e.InnerException }
    $e.Message
}

$RCodes = @{ 0 = 'NOERROR'; 1 = 'FORMERR'; 2 = 'SERVFAIL'; 3 = 'NXDOMAIN'; 4 = 'NOTIMP'; 5 = 'REFUSED' }
$EdeNames = @{
    0 = 'Other'; 1 = 'Unsupported DNSKEY Algorithm'; 2 = 'Unsupported DS Digest Type'
    3 = 'Stale Answer'; 4 = 'Forged Answer'; 5 = 'DNSSEC Indeterminate'; 6 = 'DNSSEC Bogus'
    7 = 'Signature Expired'; 8 = 'Signature Not Yet Valid'; 9 = 'DNSKEY Missing'
    10 = 'RRSIGs Missing'; 11 = 'No Zone Key Bit Set'; 12 = 'NSEC Missing'
    13 = 'Cached Error'; 14 = 'Not Ready'; 15 = 'Blocked'; 16 = 'Censored'; 17 = 'Filtered'
    18 = 'Prohibited'; 19 = 'Stale NXDOMAIN Answer'; 20 = 'Not Authoritative'
    21 = 'Not Supported'; 22 = 'No Reachable Authority'; 23 = 'Network Error'; 24 = 'Invalid Data'
}

# TLS protocol choice: PowerShell 7 uses the OS default, Windows PowerShell 5.1
# (.NET Framework) would otherwise fall back to old protocol versions
$SslProtocols = [Security.Authentication.SslProtocols]::None
if ($PSVersionTable.PSVersion.Major -lt 7) {
    $SslProtocols = [Security.Authentication.SslProtocols]::Tls12
    if ([Environment]::OSVersion.Version.Build -ge 20348 -and
        [enum]::GetNames([Security.Authentication.SslProtocols]) -contains 'Tls13') {
        $SslProtocols = $SslProtocols -bor [Security.Authentication.SslProtocols]::Tls13
    }
}

function Format-TlsVersion($Protocol) { ([string]$Protocol) -replace '^Tls(\d)(\d)$', 'TLS$1.$2' }

# DNS query in wire format: RD set, one question (type A), EDNS(0) OPT, UDP size 1232
function New-DnsQuery([string]$Name, [int]$Id) {
    $b = New-Object 'System.Collections.Generic.List[byte]'
    $b.AddRange([byte[]](((($Id -shr 8) -band 0xFF), ($Id -band 0xFF), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1)))   # comma binds tighter than -band
    foreach ($label in $Name.TrimEnd('.').Split('.')) {
        $lb = [Text.Encoding]::ASCII.GetBytes($label)
        $b.Add([byte]$lb.Length); $b.AddRange($lb)
    }
    $b.AddRange([byte[]](0, 0, 1, 0, 1))                          # root label, QTYPE A, QCLASS IN
    $b.AddRange([byte[]](0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0)) # OPT RR
    , $b.ToArray()
}

function Read-U16([byte[]]$M, [int]$O) { ([int]$M[$O] -shl 8) -bor [int]$M[$O + 1] }

function Skip-Name([byte[]]$M, [int]$O) {
    while ($true) {
        $len = [int]$M[$O]
        if ($len -eq 0) { return $O + 1 }
        if (($len -band 0xC0) -eq 0xC0) { return $O + 2 }
        $O += $len + 1
    }
}

function ConvertFrom-DnsMessage([byte[]]$M) {
    if ($M.Length -lt 12) { throw 'truncated DNS response' }
    $flags = Read-U16 $M 2
    $rcode = $flags -band 0x0F
    $qd = Read-U16 $M 4; $an = Read-U16 $M 6; $ns = Read-U16 $M 8; $ar = Read-U16 $M 10
    $o = 12
    for ($i = 0; $i -lt $qd; $i++) { $o = (Skip-Name $M $o) + 4 }
    $a = @(); $ede = $null
    for ($i = 0; $i -lt ($an + $ns + $ar); $i++) {
        $o = Skip-Name $M $o
        $type = Read-U16 $M $o; $rdlen = Read-U16 $M ($o + 8); $rd = $o + 10
        if ($i -lt $an -and $type -eq 1 -and $rdlen -eq 4) {
            $a += ('{0}.{1}.{2}.{3}' -f $M[$rd], $M[$rd + 1], $M[$rd + 2], $M[$rd + 3])
        }
        if ($type -eq 41) {                                       # OPT: look for EDE (option 15)
            $p = $rd
            while ($p + 4 -le $rd + $rdlen) {
                $code = Read-U16 $M $p; $olen = Read-U16 $M ($p + 2)
                if ($code -eq 15 -and $olen -ge 2) {
                    $info = Read-U16 $M ($p + 4)
                    $name = if ($EdeNames.ContainsKey($info)) { $EdeNames[$info] } else { 'Unknown' }
                    $ede = "EDE: $info ($name)"
                }
                $p += 4 + $olen
            }
        }
        $o = $rd + $rdlen
    }
    $status = if ($RCodes.ContainsKey($rcode)) { $RCodes[$rcode] } else { "RCODE$rcode" }
    [pscustomobject]@{
        Id = (Read-U16 $M 0); Tc = [bool]($flags -band 0x0200); Status = $status
        A = $a; Ede = $ede; Session = $null; Error = $null
    }
}

function Read-Exact($Stream, [int]$Count) {
    $buf = New-Object byte[] $Count; $got = 0
    while ($got -lt $Count) {
        $r = $Stream.Read($buf, $got, $Count - $got)
        if ($r -le 0) { throw 'connection closed by server' }
        $got += $r
    }
    , $buf
}

function Add-LengthPrefix([byte[]]$Q) {
    [byte[]]$msg = [byte[]]((($Q.Length -shr 8) -band 0xFF), ($Q.Length -band 0xFF)) + $Q
    , $msg
}

function Invoke-Udp([string]$Ip, [byte[]]$Q) {
    $addr = [Net.IPAddress]::Parse($Ip)
    $udp = New-Object Net.Sockets.UdpClient($addr.AddressFamily)
    try {
        $udp.Client.ReceiveTimeout = $TimeoutMs
        $udp.Connect($addr, 53)
        [void]$udp.Send($Q, $Q.Length)
        $any = if ($addr.AddressFamily -eq 'InterNetworkV6') { [Net.IPAddress]::IPv6Any } else { [Net.IPAddress]::Any }
        $ep = New-Object Net.IPEndPoint($any, 0)
        , $udp.Receive([ref]$ep)
    } finally { $udp.Close() }
}

# TCP connection, optionally with TLS; certificate is validated against the
# system store and the server hostname
function Open-Stream([string]$Ip, [int]$Port, [string]$TlsHost) {
    $addr = [Net.IPAddress]::Parse($Ip)
    $tcp = New-Object Net.Sockets.TcpClient($addr.AddressFamily)
    $ar = $tcp.BeginConnect($addr, $Port, $null, $null)
    if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs)) { $tcp.Close(); throw "connection to port $Port timed out" }
    $tcp.EndConnect($ar)
    $tcp.ReceiveTimeout = $TimeoutMs; $tcp.SendTimeout = $TimeoutMs
    $stream = $tcp.GetStream(); $tls = $null
    if ($TlsHost) {
        $ssl = New-Object Net.Security.SslStream($stream, $false)
        try { $ssl.AuthenticateAsClient($TlsHost, $null, $SslProtocols, $false) }
        catch { $tcp.Close(); throw "TLS/certificate error: $(Get-RootMessage $_.Exception)" }
        $stream = $ssl; $tls = Format-TlsVersion $ssl.SslProtocol
    }
    [pscustomobject]@{ Tcp = $tcp; Stream = $stream; Tls = $tls }
}

function Invoke-StreamDns($Stream, [byte[]]$Q) {
    $msg = Add-LengthPrefix $Q
    $Stream.Write($msg, 0, $msg.Length); $Stream.Flush()
    $lb = Read-Exact $Stream 2
    , (Read-Exact $Stream ((([int]$lb[0]) -shl 8) -bor [int]$lb[1]))
}

# DoH (RFC 8484) via plain HTTP/1.1 POST over the TLS stream
function Invoke-DohRaw($Stream, [string]$HostName, [byte[]]$Q) {
    $hdr = "POST /dns-query HTTP/1.1`r`nHost: $HostName`r`nContent-Type: application/dns-message`r`n" +
           "Accept: application/dns-message`r`nContent-Length: $($Q.Length)`r`nConnection: close`r`n`r`n"
    $hb = [Text.Encoding]::ASCII.GetBytes($hdr)
    $Stream.Write($hb, 0, $hb.Length); $Stream.Write($Q, 0, $Q.Length); $Stream.Flush()

    $latin1 = [Text.Encoding]::GetEncoding(28591)   # 1:1 byte <-> char, keeps offsets
    $data = New-Object IO.MemoryStream
    $buf = New-Object byte[] 4096
    $hdrEnd = -1; $bodyLen = -1; $chunked = $false
    while ($true) {
        if ($hdrEnd -ge 0) {
            $have = $data.Length - $hdrEnd
            if ($bodyLen -ge 0 -and $have -ge $bodyLen) { break }
            if ($chunked -and $latin1.GetString($data.ToArray(), $hdrEnd, $have).Contains("`r`n0`r`n")) { break }
        }
        try { $r = $Stream.Read($buf, 0, $buf.Length) } catch { $r = 0 }
        if ($r -le 0) { break }
        $data.Write($buf, 0, $r)
        if ($hdrEnd -lt 0) {
            $txt = $latin1.GetString($data.ToArray())
            $i = $txt.IndexOf("`r`n`r`n")
            if ($i -ge 0) {
                $hdrEnd = $i + 4
                $head = $txt.Substring(0, $i)
                if ($head -notmatch '^HTTP/1\.[01] (\d{3})') { throw 'invalid HTTP response' }
                if ($Matches[1] -ne '200') { throw "HTTP status $($Matches[1])" }
                if ($head -match '(?im)^Content-Length:\s*(\d+)') { $bodyLen = [int]$Matches[1] }
                elseif ($head -match '(?im)^Transfer-Encoding:\s*chunked') { $chunked = $true }
            }
        }
    }
    if ($hdrEnd -lt 0) { throw 'no HTTP response' }
    $all = $data.ToArray()
    if ($hdrEnd -ge $all.Length) { throw 'empty HTTP response body' }
    $body = [byte[]]$all[$hdrEnd..($all.Length - 1)]
    if ($chunked) {                                     # decode chunked transfer encoding
        $out = New-Object IO.MemoryStream; $p = 0
        while ($p -lt $body.Length) {
            $s = $latin1.GetString($body, $p, [Math]::Min(16, $body.Length - $p))
            $e = $s.IndexOf("`r`n"); if ($e -lt 1) { break }
            $size = [Convert]::ToInt32(($s.Substring(0, $e) -split ';')[0], 16)
            if ($size -eq 0) { break }
            $out.Write($body, $p + $e + 2, $size); $p += $e + 2 + $size + 2
        }
        $body = $out.ToArray()
    } elseif ($bodyLen -gt 0 -and $bodyLen -lt $body.Length) {
        $body = [byte[]]$body[0..($bodyLen - 1)]
    }
    , $body
}

# DoQ (RFC 9250): needs System.Net.Quic (.NET 7+) and OS support (msquic)
function Get-QuicProblem {
    $v = $PSVersionTable.PSVersion
    if ($v.Major -lt 7 -or ($v.Major -eq 7 -and $v.Minor -lt 4)) { return 'needs PowerShell 7.4 or newer' }
    try { Add-Type -AssemblyName System.Net.Quic } catch { return 'System.Net.Quic not available' }
    try {
        if (-not [System.Net.Quic.QuicConnection]::IsSupported) {
            return 'QUIC not supported by this OS (Windows 11 / Server 2022 or libmsquic needed)'
        }
    } catch { return 'QUIC not available' }
    return $null
}

function Invoke-Doq([string]$Ip, [string]$HostName, [byte[]]$Q) {
    $opt = New-Object System.Net.Quic.QuicClientConnectionOptions
    $opt.RemoteEndPoint = New-Object Net.IPEndPoint([Net.IPAddress]::Parse($Ip), 853)
    $opt.DefaultStreamErrorCode = 0
    $opt.DefaultCloseErrorCode = 0
    $ssl = New-Object Net.Security.SslClientAuthenticationOptions
    $ssl.TargetHost = $HostName
    $alpn = New-Object 'System.Collections.Generic.List[System.Net.Security.SslApplicationProtocol]'
    $alpn.Add((New-Object Net.Security.SslApplicationProtocol('doq')))
    $ssl.ApplicationProtocols = $alpn
    $opt.ClientAuthenticationOptions = $ssl
    $cts = New-Object Threading.CancellationTokenSource($TimeoutMs)
    $conn = [System.Net.Quic.QuicConnection]::ConnectAsync($opt, $cts.Token).AsTask().GetAwaiter().GetResult()
    try {
        $stream = $conn.OpenOutboundStreamAsync([System.Net.Quic.QuicStreamType]::Bidirectional, $cts.Token).AsTask().GetAwaiter().GetResult()
        try {
            $msg = Add-LengthPrefix $Q
            # [void]: GetResult() returns a VoidTaskResult object in PowerShell that would end up in the output
            [void]$stream.WriteAsync([ReadOnlyMemory[byte]]$msg, $true, $cts.Token).AsTask().GetAwaiter().GetResult()
            try { $stream.ReadTimeout = $TimeoutMs } catch { }
            $lb = Read-Exact $stream 2
            , (Read-Exact $stream ((([int]$lb[0]) -shl 8) -bor [int]$lb[1]))
        } finally { $stream.Dispose() }
    } finally { try { [void]$conn.DisposeAsync().AsTask().GetAwaiter().GetResult() } catch { } }
}

function Invoke-DnsQuery([string]$Proto, [string]$Ip, [string]$HostName, [string]$Domain) {
    try {
        $id = if ($Proto -eq 'DoQ') { 0 } else { Get-Random -Minimum 1 -Maximum 65536 }  # DoQ requires ID 0
        $q = New-DnsQuery $Domain $id
        $session = $null
        switch ($Proto) {
            'Do53' {
                $resp = Invoke-Udp $Ip $q
                if ((ConvertFrom-DnsMessage $resp).Tc) {             # truncated -> retry over TCP
                    $c = Open-Stream $Ip 53 $null
                    try { $resp = Invoke-StreamDns $c.Stream $q } finally { $c.Tcp.Close() }
                }
            }
            'DoT' {
                $c = Open-Stream $Ip 853 $HostName
                try { $resp = Invoke-StreamDns $c.Stream $q } finally { $c.Tcp.Close() }
                $session = $c.Tls
            }
            'DoH' {
                $c = Open-Stream $Ip 443 $HostName
                try { $resp = Invoke-DohRaw $c.Stream $HostName $q } finally { $c.Tcp.Close() }
                $session = "HTTP/1.1, $($c.Tls)"
            }
            'DoQ' {
                $resp = Invoke-Doq $Ip $HostName $q
                $session = 'QUICv1, TLS1.3'
            }
        }
        $r = ConvertFrom-DnsMessage $resp
        if ($r.Id -ne $id) { throw 'DNS response ID mismatch' }
        $r.Session = $session
        $r
    } catch {
        [pscustomobject]@{ Id = 0; Tc = $false; Status = 'no response'; A = @(); Ede = $null
                           Session = $null; Error = (Get-RootMessage $_.Exception) }
    }
}

function Write-Trace([string]$Label, $R) {
    if (-not $IsVerbose) { return }
    $line = '        {0,-42} {1}' -f $Label, $R.Status
    if (@($R.A).Count -gt 0) { $line += " $(@($R.A)[0])" }
    if ($R.Ede)   { $line += " [$($R.Ede)]" }
    if ($R.Error) { $line += " ($($R.Error))" }
    Out-Line $line
}

function Get-PingAverage([string]$Ip) {
    $times = @()
    $ping = New-Object Net.NetworkInformation.Ping
    try {
        for ($i = 0; $i -lt $PingCount; $i++) {
            try {
                $r = $ping.Send($Ip, 2000)
                if ($r.Status -eq 'Success') { $times += [double]$r.RoundtripTime }
            } catch { }
            Start-Sleep -Milliseconds 200
        }
    } finally { $ping.Dispose() }
    if ($times.Count -eq 0) { return $null }
    $avg = ($times | Measure-Object -Average).Average
    [int][Math]::Round($avg, [MidpointRounding]::AwayFromZero)   # commercial rounding
}

function Test-IPv6Route {
    try {
        $s = New-Object Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetworkV6,
                                           [Net.Sockets.SocketType]::Dgram, [Net.Sockets.ProtocolType]::Udp)
        try { $s.Connect([Net.IPAddress]::Parse('2a01:4f8:c17:1c66::1'), 53); $true } finally { $s.Close() }
    } catch { $false }
}

# --- checks ----------------------------------------------------------------

$script:Pass = 0; $script:Fail = 0; $script:Skip = 0; $script:Warn = 0
$Rank = New-Object 'System.Collections.Generic.List[object]'
$QuicProblem = Get-QuicProblem

function Test-Protocol([string]$Proto, [string]$Ip, [string]$Name) {
    $fqdn = "$Name.hagezi.org"
    $details = New-Object 'System.Collections.Generic.List[string]'
    $rok = 1; $dok = 1; $bok = 1

    if ($Proto -eq 'DoQ' -and $QuicProblem) {
        Out-Part ('  {0,-5} ' -f $Proto); Out-Part 'SKIP' 'Yellow'; Out-Line "  $QuicProblem"
        $script:Skip++; return
    }

    # first query doubles as connection/TLS test and as first resolution test
    $first = Invoke-DnsQuery $Proto $Ip $fqdn $ResolveDomains[0]
    if ($first.Error) {
        Out-Part ('  {0,-5} ' -f $Proto); Out-Part 'FAIL' 'Red'
        Out-Line '  no response (connection failed, timeout or certificate error)'
        Out-Line "        $($first.Error)"
        if ($Proto -eq 'DoQ') { Out-Line '        (DoQ uses UDP port 853, which some networks block)' }
        $script:Fail++; return
    }

    # resolution
    for ($i = 0; $i -lt $ResolveDomains.Count; $i++) {
        $d = $ResolveDomains[$i]
        $r = if ($i -eq 0) { $first } else { Invoke-DnsQuery $Proto $Ip $fqdn $d }
        Write-Trace "resolve $d" $r
        if ($r.Status -ne 'NOERROR' -or @($r.A).Count -eq 0) { $rok = 0; $details.Add("resolve ${d}: $($r.Status)") }
    }

    # DNSSEC: signed zone must resolve, bogus zones must be rejected
    $r = Invoke-DnsQuery $Proto $Ip $fqdn $DnssecOk
    Write-Trace "dnssec valid $DnssecOk" $r
    if ($r.Status -ne 'NOERROR') { $dok = 0; $details.Add("dnssec $DnssecOk (valid): $($r.Status), expected NOERROR") }
    $bogusServfail = 0; $bogusOpen = 0
    foreach ($d in $DnssecBogus) {
        $r = Invoke-DnsQuery $Proto $Ip $fqdn $d
        Write-Trace "dnssec bogus $d" $r
        switch ($r.Status) {
            'SERVFAIL' { $bogusServfail++ }
            'NOERROR'  { $bogusOpen++; $details.Add("dnssec $d (bogus): NOERROR, signature not validated") }
            default    { $details.Add("dnssec $d (bogus): $($r.Status), test domain may no longer exist") }
        }
    }
    if ($bogusOpen -gt 0) { $dok = 0 }
    elseif ($dok -eq 1 -and $bogusServfail -eq 0) { $dok = 2 }   # inconclusive

    # blocking
    $r = Invoke-DnsQuery $Proto $Ip $fqdn $BlockDomain
    Write-Trace "block $BlockDomain" $r
    $blocked = @($r.A) -contains '0.0.0.0'
    if ($Name -eq 'ctif') {
        if ($blocked) { $bok = 0; $details.Add("block ${BlockDomain}: blocked, but ctif is threat-only") }
    } elseif (-not $blocked) {
        $bok = 0; $details.Add("block ${BlockDomain}: not blocked")
    }

    Out-Part ('  {0,-5} ' -f $Proto)
    if ($rok -eq 0 -or $dok -eq 0 -or $bok -eq 0) { Out-Part 'FAIL' 'Red';    $script:Fail++ }
    elseif ($dok -eq 2)                           { Out-Part 'WARN' 'Yellow'; $script:Warn++ }
    else                                          { Out-Part 'OK  ' 'Green';  $script:Pass++ }
    Out-Part '  resolve '; Out-Mark $rok
    Out-Part '  dnssec ';  Out-Mark $dok
    Out-Part '  block ';   Out-Mark $bok
    if ($first.Session) { Out-Part "   [$($first.Session)]" }
    Out-Line
    foreach ($l in $details) { Out-Line "        $l" }
}

# --- main ------------------------------------------------------------------

if ($Families -contains 6 -and -not (Test-IPv6Route)) {
    if ($IPv6) { Out-Line 'IPv6 is not available on this connection.' 'Red'; exit $EXIT_FAIL }
    Out-Line 'IPv6 is not available on this connection, skipping IPv6 tests.' 'Yellow'
    $Families = @(4)
}

$psv = $PSVersionTable.PSVersion.ToString()
Out-Part "HaGeZi DNS check $ScriptVersion" 'White'
Out-Line "  (PowerShell $psv)"
Out-Line

foreach ($srv in $Servers) {
    if ($Select.Count -gt 0 -and $Select -notcontains $srv.Name) { continue }
    $fqdn = "$($srv.Name).hagezi.org"
    foreach ($fam in $Families) {
        $ip = if ($fam -eq 4) { $srv.V4 } else { $srv.V6 }
        $avg = Get-PingAverage $ip
        if ($null -ne $avg) {
            $pingTxt = "ping avg $avg ms"
            $Rank.Add([pscustomobject]@{ Ms = $avg; Host = $fqdn; Family = "IPv$fam" })
        } else { $pingTxt = 'ping n/a' }
        Out-Part "== $fqdn" 'White'
        Out-Line "  IPv$fam $ip  ($pingTxt)"
        foreach ($p in $Protocols) { Test-Protocol $p $ip $srv.Name }
        Out-Line
    }
}

if ($Rank.Count -gt 0) {
    Out-Line "Latency (average of $PingCount pings, lowest first):" 'White'
    foreach ($e in ($Rank | Sort-Object Ms)) { Out-Line ('  {0,4} ms  {1} {2}' -f $e.Ms, $e.Host, $e.Family) }
    Out-Line
}

Out-Part 'Result: ' 'White'
Out-Part "$($script:Pass) passed" 'Green'; Out-Part ', '
Out-Part "$($script:Fail) failed" 'Red';   Out-Part ', '
Out-Part "$($script:Warn) warning(s)" 'Yellow'; Out-Part ', '
Out-Line "$($script:Skip) skipped" 'Yellow'
if ($script:Fail -gt 0) {
    Out-Line 'A VPN or a router intercepting DNS can cause failures. Need help? support@hagezi.org'
    exit $EXIT_FAIL
}
exit $EXIT_OK
