# HaGeZi DNS: Cheat Sheet

> [!TIP]
> Just want to get connected? Pick a server below, set it up, and you're done. Full background, security details, and legal/privacy info are in [README](README.md) and [PRIVACY](PRIVACY.md).

## 1. Pick a server by country and protection level <a id="pick-server"></a>

**Full protection (ads, trackers, and threats blocked), recommended for most users:**

| Server | Location | Best for (country) |
|---|---|---|
| `root.hagezi.org` | Germany, Falkenstein | AT, BA, BE, BG, CH, CZ, DE, DK, FR, GB, HU, IE, IT, LU, NL, PL, RO, SI, SK |
| `wurzn.hagezi.org` | Germany, Nuremberg | AT, BA, BE, BG, CH, CZ, DE, DK, ES, FR, GB, GR, HR, HU, IE, IT, LU, MD, MK, MT, NL, PL, PT, RO, RS, SI, SK, TR, UA |
| `juuri.hagezi.org` | Finland, Helsinki | DK, EE, FI, LT, LV, NO, SE |

**Threats only (phishing, malware, scam), no ad/tracker blocking:**

| Server | Location | Best for (country) |
|---|---|---|
| `ctif.hagezi.org` | Germany, Nuremberg | AT, BA, BE, BG, CH, CZ, DE, DK, ES, FR, GB, GR, HR, HU, IE, IT, LU, MD, MK, MT, NL, PL, PT, RO, RS, SI, SK, TR, UA |

Limited coverage from current locations: AD, CY, GE, IS, LI, MC, ME, SM. Any server still works, just with higher latency.

> [!NOTE]
> The three full-protection servers are all named "root", once per location: `root` in English, `wurzn` in the Franconian dialect spoken around Nuremberg, and `juuri` in Finnish. `ctif` is the odd one out, short for Cyber Threat Intelligence Feed, after the list it runs on.

## 2. Connect (recommended: encrypted) <a id="connect"></a>

| Protocol | Format | Example |
|---|---|---|
| DoH/DoH3 | `https://<server>/dns-query` | `https://root.hagezi.org/dns-query` |
| DoT | `<server>`, port 853 | `root.hagezi.org` |
| DoQ | `<server>`, port 853 | `root.hagezi.org` |

Use the [DNS Stamps](README.md#dns-stamps) for compatible apps (auto-configuration), or set it up per platform below.

> [!WARNING]
> Don't enable DoH, DoT, and DoQ against the same server at the same time. It doesn't add protection, only wastes your rate-limit allowance and can slow things down.

## 3. Platform setup <a id="platform-setup"></a>

> [!IMPORTANT]
> An active VPN normally takes over DNS for the whole device and overrides everything below: Android's Private DNS, an installed Apple profile, and the Windows settings alike. If you use a VPN, set this DNS inside the VPN app itself (most support a custom resolver), or accept that your VPN provider's resolver is in use whenever the tunnel is up. The [leak test](#verify) shows you which one actually applies.

**Apple (iOS, iPadOS, macOS):** manual DoH/DoT entry isn't supported in system settings. Use the official mobileconfig profile instead:

| Server | Apple Config |
|---|---|
| `root.hagezi.org` | [Profile](mobileconfig/root-hagezi-org.mobileconfig) · [QR](mobileconfig/root-hagezi-org.mobileconfig.png) |
| `wurzn.hagezi.org` | [Profile](mobileconfig/wurzn-hagezi-org.mobileconfig) · [QR](mobileconfig/wurzn-hagezi-org.mobileconfig.png) |
| `juuri.hagezi.org` | [Profile](mobileconfig/juuri-hagezi-org.mobileconfig) · [QR](mobileconfig/juuri-hagezi-org.mobileconfig.png) |
| `ctif.hagezi.org` | [Profile](mobileconfig/ctif-hagezi-org.mobileconfig) · [QR](mobileconfig/ctif-hagezi-org.mobileconfig.png) |

Install the profile via Settings, or scan the QR code with your camera.

**Android (9+):** Settings → Network & internet → Private DNS → Private DNS provider hostname → enter the server, e.g. `root.hagezi.org`. This uses DoT.

**Windows (11):**

1. Go to **Settings → Network & internet → [your Wi-Fi/Ethernet connection] → Hardware properties → DNS server assignment → Edit**.
2. Change the dropdown to **Manual**, and turn on **IPv4** (and/or IPv6).
3. Under **Preferred DNS**, enter the server's IPv4 address, e.g. `188.34.161.210` for `root.hagezi.org`. If you turned on IPv6 in the previous step, enter the matching IPv6 address in the IPv6 section as well, e.g. `2a01:4f8:c17:1c66::1`. See the [Do53 table](#do53-fallback) for the other servers.
4. Under **DNS over HTTPS**, select **On (manual template)**.
5. In the **DNS over HTTPS template** field that appears, enter the matching DoH URL, e.g. `https://root.hagezi.org/dns-query`.
6. Leave **Fallback to plaintext** off, so queries always stay encrypted.
7. Optionally repeat steps 3 to 6 under **Alternate DNS** with a second server, or leave it empty.
8. Select **Save**.

> [!NOTE]
> On some Windows 11 builds, the manual template field may stay greyed out for servers not in Windows' built-in list (Cloudflare, Google, Quad9). If that happens, register the server first via an elevated PowerShell prompt: `Add-DnsClientDohServerAddress -ServerAddress '188.34.161.210' -DohTemplate 'https://root.hagezi.org/dns-query' -AllowFallbackToUdp $False -AutoUpgrade $True`, then repeat the steps above. If you also use IPv6, register the matching IPv6 address the same way: `Add-DnsClientDohServerAddress -ServerAddress '2a01:4f8:c17:1c66::1' -DohTemplate 'https://root.hagezi.org/dns-query' -AllowFallbackToUdp $False -AutoUpgrade $True`.

> [!NOTE]
> Windows 10 has no interface for encrypted DNS. Use the Do53 IP addresses from the [table below](#do53-fallback), set up encrypted DNS on your router, or use a local DNS client that supports DoH/DoT.

**Router or other OS/app:** most consumer routers only support classic, unencrypted DNS (Do53). In that case, enter the IPv4/IPv6 addresses from the table below directly as your router's DNS servers, so every device on your network is protected automatically, no per-device setup needed.

If your router or firmware supports encrypted DNS, use the DoH URL or DoT hostname instead of the Do53 IPs:

- **OpenWrt:** configure via `https-dns-proxy` (DoH) or `stubby` (DoT) in LuCI.
- **pfSense / OPNsense:** set up as a DoT forwarder in the Unbound DNS Resolver settings.
- **FRITZ!Box, ASUS, and other consumer routers with encrypted DNS support:** look for a "DNS-over-HTTPS", "DNS-over-TLS", or "Encrypted DNS" field in the router's DNS or internet settings and enter the DoH URL or DoT hostname there.
- **Not sure your router supports it?** Stick with the Do53 IPs below, they work everywhere and protect the whole network with zero per-device configuration.

## 4. Unencrypted fallback (Do53), only if nothing else works <a id="do53-fallback"></a>

| Server | IPv4 | IPv6 |
|---|---|---|
| `root.hagezi.org` | `188.34.161.210` | `2a01:4f8:c17:1c66::1` |
| `wurzn.hagezi.org` | `159.69.155.94` | `2a01:4f8:1c1c:d363::1` |
| `juuri.hagezi.org` | `95.217.163.17` | `2a01:4f9:c013:dc4e::1` |
| `ctif.hagezi.org` | `162.55.58.40` | `2a01:4f8:1c19:6c19::1` |

## 5. Verify it's working <a id="verify"></a>

Run a [DNS leak test](https://dnscheck.tools). If it shows an IP address other than the ones above, your device or network is bypassing this DNS setup.

## 6. Something not working? <a id="troubleshooting"></a>

**One site fails, everything else is fine.** This is almost always a blocked domain rather than a fault. Blocked domains are answered with `0.0.0.0`, so the connection fails instantly and the browser shows a generic "can't reach this site" page that says nothing about DNS or blocking. To confirm, look the domain up through a different resolver, or switch to `ctif.hagezi.org` for a moment: if the site loads there, an ad or tracker rule was the cause, since that server filters threats only. Report anything blocked in error via the channels in [Good to know](#things-to-know).

**Nothing resolves at all.** First check whether a VPN is active, since it will normally override your DNS settings entirely. Then check the server status pages, which are regenerated every 5 minutes: [`root.hagezi.org`](https://root.hagezi.org/stats.txt) · [`wurzn.hagezi.org`](https://wurzn.hagezi.org/stats.txt) · [`juuri.hagezi.org`](https://juuri.hagezi.org/stats.txt) · [`ctif.hagezi.org`](https://ctif.hagezi.org/stats.txt). Opening those links needs working name resolution, so if DNS is dead on this device, check from a phone on mobile data or point the device at another resolver first.

**The status pages won't load either.** If all four time out from a device whose DNS otherwise works, the likely cause is your IP address being blocked at the firewall rather than an outage, since four servers rarely fail at once. Two things cause that:

- **Tor.** Exit nodes are blocked on every server and every protocol, including Do53. Queries arriving from that network go unanswered.
- **A threat-intelligence match.** Addresses listed as malicious or abusive are blocked automatically. This can catch you through no fault of your own, most commonly when your provider puts many customers behind one shared address (CGNAT) and someone else on it misbehaved.

To get an incorrect block lifted, contact the operator privately: [support@hagezi.org](mailto:support@hagezi.org), [Matrix](https://matrix.to/#/@hagezi:tchncs.de), or [Signal](https://signal.me/#eu/WlBfKuiT1S1GAGwDRpvIJErjM-C3IcjQUQ9HWLzeJKGKTfwlOGhEe7GQRSx05uX0). Please don't use the public support chat for this, since sorting it out means sharing your IP address with whoever is in the room.

**Still stuck?** If the server looks healthy and none of the above applies, reach out via [support@hagezi.org](mailto:support@hagezi.org) or the [Matrix chat](https://matrix.to/#/#hagezi-support:tchncs.de?via=tchncs.de).

## 7. Good to know <a id="things-to-know"></a>

1. Free, non-commercial, no account, no data sold, EU-hosted servers only.
2. No logging of individual queries; only short-lived stats, held in memory for max. 1 hour and published as aggregate totals on the status pages. Domains that fail to resolve are kept for 24 hours for troubleshooting, without any client IP address.
3. Tor exit nodes are blocked on every server and protocol due to persistent attack traffic from that network. Queries routed through Tor will not be answered.
4. A domain wrongly blocked or missed? Report it via [support@hagezi.org](mailto:support@hagezi.org) or the [Matrix chat](https://matrix.to/#/#hagezi-support:tchncs.de?via=tchncs.de).
5. This is one layer of protection, not a replacement for antivirus, a firewall, or your own judgment.
6. Full legal disclaimer, privacy policy, and DSA compliance info live in [PRIVACY](PRIVACY.md), not required reading to just use the service.
