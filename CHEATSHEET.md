# HaGeZi DNS: Cheat Sheet

> [!TIP]
> Just want to get going? Pick a server below, set it up, done. All the background, security details, and legal stuff are in [README](README.md) and [PRIVACY](PRIVACY.md).

## 1. Pick a server by country and protection level <a id="pick-server"></a>

**Full protection (blocks ads, trackers, and threats), the right pick for most people:**

| Server | Location | Best for (country) |
|---|---|---|
| `root.hagezi.org` | Germany, Falkenstein | AT, BA, BE, BG, CH, CZ, DE, DK, FR, GB, HU, IE, IT, LU, NL, PL, RO, SI, SK |
| `wurzn.hagezi.org` | Germany, Nuremberg | AT, BA, BE, BG, CH, CZ, DE, DK, ES, FR, GB, GR, HR, HU, IE, IT, LU, MD, MK, MT, NL, PL, PT, RO, RS, SI, SK, TR, UA |
| `juuri.hagezi.org` | Finland, Helsinki | DK, EE, FI, LT, LV, NO, SE |

**Threats only (phishing, malware, scam, fake, cryptojacking), ads and trackers are left alone:**

| Server | Location | Best for (country) |
|---|---|---|
| `ctif.hagezi.org` | Germany, Nuremberg | AT, BA, BE, BG, CH, CZ, DE, DK, ES, FR, GB, GR, HR, HU, IE, IT, LU, MD, MK, MT, NL, PL, PT, RO, RS, SI, SK, TR, UA |

A bit far from the current locations: AD, CY, GE, IS, LI, MC, ME, SM. Any server works from there too, you'll just see more latency.

> [!NOTE]
> The three full-protection servers are all called "root", just in different languages: `root` in English, `wurzn` in the Franconian dialect around Nuremberg, and `juuri` in Finnish. `ctif` is the odd one out. It stands for Cyber Threat Intelligence Feed, after the threat-intelligence list it runs on.

## 2. Connect (recommended: encrypted) <a id="connect"></a>

| Protocol | Format | Example |
|---|---|---|
| DoH/DoH3 | `https://<server>/dns-query` | `https://root.hagezi.org/dns-query` |
| DoT | `<server>`, port 853 | `root.hagezi.org` |
| DoQ | `<server>`, port 853 | `root.hagezi.org` |

If your app supports [DNS stamps](README.md#dns-stamps), one string is all you need. Otherwise, follow the steps for your platform below.

> [!WARNING]
> Don't turn on DoH, DoT, and DoQ for the same server at the same time. It doesn't make you any safer, it just eats your rate limit and can slow things down.

## 3. Platform setup <a id="platform-setup"></a>

> [!IMPORTANT]
> Using a VPN? Then it almost certainly handles DNS for your whole device and overrides everything below: Android's Private DNS, an installed Apple profile, and the Windows settings. Either set this DNS inside your VPN app (most let you pick a custom resolver), or live with your VPN provider's resolver while the tunnel is up. The [leak test](#verify) shows you which one is actually in use.

**Apple (iOS, iPadOS, macOS):** there's no field for DoH or DoT in the system settings, so use a configuration profile:

| Server | Apple config |
|---|---|
| `root.hagezi.org` | [Profile](mobileconfig/root-hagezi-org.mobileconfig) · [QR](mobileconfig/root-hagezi-org.mobileconfig.png) |
| `wurzn.hagezi.org` | [Profile](mobileconfig/wurzn-hagezi-org.mobileconfig) · [QR](mobileconfig/wurzn-hagezi-org.mobileconfig.png) |
| `juuri.hagezi.org` | [Profile](mobileconfig/juuri-hagezi-org.mobileconfig) · [QR](mobileconfig/juuri-hagezi-org.mobileconfig.png) |
| `ctif.hagezi.org` | [Profile](mobileconfig/ctif-hagezi-org.mobileconfig) · [QR](mobileconfig/ctif-hagezi-org.mobileconfig.png) |

Download the profile and install it in Settings, or just scan the QR code with your camera.

**Android (9+):** Settings → Network & internet → Private DNS → Private DNS provider hostname → enter the server, e.g. `root.hagezi.org`. That's DoT.

**Windows (11):**

1. Go to **Settings → Network & internet → [your Wi-Fi/Ethernet connection] → Hardware properties → DNS server assignment → Edit**.
2. Switch the dropdown to **Manual** and turn on **IPv4** (and/or IPv6).
3. Under **Preferred DNS**, enter the server's IPv4 address, e.g. `188.34.161.210` for `root.hagezi.org`. If you turned on IPv6, put the matching IPv6 address in the IPv6 section too, e.g. `2a01:4f8:c17:1c66::1`. The other servers' addresses are in the [Do53 table](#do53-fallback).
4. Under **DNS over HTTPS**, pick **On (manual template)**.
5. In the **DNS over HTTPS template** field, enter the matching DoH URL, e.g. `https://root.hagezi.org/dns-query`.
6. Leave **Fallback to plaintext** off, so your queries always stay encrypted.
7. If you like, repeat steps 3 to 6 under **Alternate DNS** with a second server. Leaving it empty is fine too.
8. Hit **Save**.

> [!NOTE]
> On some Windows 11 builds the template field stays greyed out for servers that aren't on Windows' built-in list (Cloudflare, Google, Quad9). No problem: register the server first in an elevated PowerShell prompt with `Add-DnsClientDohServerAddress -ServerAddress '188.34.161.210' -DohTemplate 'https://root.hagezi.org/dns-query' -AllowFallbackToUdp $False -AutoUpgrade $True`, then do the steps above again. Using IPv6 as well? Register the IPv6 address the same way: `Add-DnsClientDohServerAddress -ServerAddress '2a01:4f8:c17:1c66::1' -DohTemplate 'https://root.hagezi.org/dns-query' -AllowFallbackToUdp $False -AutoUpgrade $True`.

> [!NOTE]
> Windows 10 has no settings for encrypted DNS. Use the Do53 addresses from the [table below](#do53-fallback), set up encrypted DNS on your router, or install a local DNS client that does DoH or DoT.

**Router or other OS/app:** most home routers only do classic, unencrypted DNS (Do53). Just enter the IPv4/IPv6 addresses from the table below as your router's DNS servers, and every device on your network is covered without setting up each one.

If your router or firmware can do encrypted DNS, use the DoH URL or DoT hostname instead of the Do53 addresses:

- **OpenWrt:** set up `https-dns-proxy` (DoH) or `stubby` (DoT) in LuCI.
- **pfSense / OPNsense:** add the server as a DoT forwarder in the Unbound DNS Resolver settings.
- **FRITZ!Box, ASUS, and other routers with encrypted DNS:** look for a "DNS-over-HTTPS", "DNS-over-TLS", or "Encrypted DNS" field in the DNS or internet settings and put the DoH URL or DoT hostname there.
- **Not sure your router can do it?** Then go with the Do53 addresses below. They work on any router and cover your whole network.

## 4. Unencrypted fallback (Do53), only if nothing else works <a id="do53-fallback"></a>

| Server | IPv4 | IPv6 |
|---|---|---|
| `root.hagezi.org` | `188.34.161.210` | `2a01:4f8:c17:1c66::1` |
| `wurzn.hagezi.org` | `159.69.155.94` | `2a01:4f8:1c1c:d363::1` |
| `juuri.hagezi.org` | `95.217.163.17` | `2a01:4f9:c013:dc4e::1` |
| `ctif.hagezi.org` | `162.55.58.40` | `2a01:4f8:1c19:6c19::1` |

## 5. Verify it's working <a id="verify"></a>

Run a [DNS leak test](https://dnscheck.tools). If it shows an IP address that isn't in the table above, something on your device or network is going around this DNS setup.

Want to check that every server and protocol works from your network? Run [hagezi-dns-check.sh](scripts/hagezi-dns-check.sh) (Linux, macOS) or [hagezi-dns-check.ps1](scripts/hagezi-dns-check.ps1) (Windows). It tests Do53, DoT, DoH, and DoQ on IPv4 and IPv6, including DNSSEC validation and blocking, and tells you which server answers fastest. The script talks to the servers directly, so it doesn't replace the leak test. Only the leak test shows which resolver your device really uses. How to run it: [scripts/README](scripts/README.md).

## 6. Something not working? <a id="troubleshooting"></a>

**One site fails, everything else is fine.** That's almost always a blocked domain, not a bug. Blocked domains get `0.0.0.0` back, so the connection fails right away and the browser shows a generic "can't reach this site" page that says nothing about DNS or blocking. To check, look the domain up with another resolver, or switch to `ctif.hagezi.org` for a moment. If the site loads there, an ad or tracker rule blocked it, because `ctif` only filters threats. Wrong blocks can be reported through the channels in [Good to know](#things-to-know).

**Nothing resolves at all.** First check if a VPN is running, because it usually overrides your DNS settings completely. Then have a look at the server status pages, which are rebuilt every 5 minutes: [`root.hagezi.org`](https://root.hagezi.org/stats.txt) · [`wurzn.hagezi.org`](https://wurzn.hagezi.org/stats.txt) · [`juuri.hagezi.org`](https://juuri.hagezi.org/stats.txt) · [`ctif.hagezi.org`](https://ctif.hagezi.org/stats.txt). Catch: opening them needs working DNS. If DNS is down on this device, check from your phone on mobile data, or point the device at another resolver first.

**The status pages won't load either.** If all four time out on a device where DNS otherwise works, your IP address is probably blocked at the firewall. An outage is unlikely, since four servers rarely go down at the same time. There are two usual reasons for a block like that:

- **Tor.** Exit nodes are blocked on every server and protocol, Do53 included. Queries from that network go unanswered.
- **A threat-intelligence match.** Addresses listed as malicious or abusive are blocked automatically. That can hit you even if you did nothing wrong, most often when your provider puts lots of customers behind one shared address (CGNAT) and someone else on it misbehaved.

To get a wrong block lifted, get in touch privately: [support@hagezi.org](mailto:support@hagezi.org), [Matrix](https://matrix.to/#/@hagezi:tchncs.de), or [Signal](https://signal.me/#eu/WlBfKuiT1S1GAGwDRpvIJErjM-C3IcjQUQ9HWLzeJKGKTfwlOGhEe7GQRSx05uX0). Please don't use the public support chat for this, because sorting it out means sharing your IP address with everyone in the room.

**Only one protocol or IP version fails.** Say DoT works but DoH doesn't, or only IPv6 is broken. Run [hagezi-dns-check](#verify). It tests every server, protocol, and IP version on its own and shows you exactly which combination fails. It connects to the servers by IP address, so it even works while DNS on your device is broken. If only DoQ fails, your network is probably blocking UDP port 853.

**Still stuck?** If the server looks fine and none of the above fits, write to [support@hagezi.org](mailto:support@hagezi.org) or ask in the [Matrix chat](https://matrix.to/#/#hagezi-support:tchncs.de?via=tchncs.de). Sending the output of [hagezi-dns-check](#verify) along helps a lot. It only contains the servers' addresses and the test results, not your own IP address.

## 7. Good to know <a id="things-to-know"></a>

1. Free and non-commercial. No account, no data sold, servers in the EU only.
2. Individual queries aren't logged. Stats live in memory for 1 hour max and are only published as totals on the status pages. Domains that fail to resolve are kept for 24 hours for troubleshooting, without any client IP address.
3. Tor exit nodes are blocked on every server and protocol, because a constant stream of attacks comes from that network. Queries over Tor won't get an answer.
4. Something blocked that shouldn't be, or something missing that should be blocked? Report it via [support@hagezi.org](mailto:support@hagezi.org) or the [Matrix chat](https://matrix.to/#/#hagezi-support:tchncs.de?via=tchncs.de).
5. DNS filtering is one layer of protection. It doesn't replace antivirus, a firewall, or common sense.
6. The legal disclaimer, privacy policy, and DSA info are in [PRIVACY](PRIVACY.md). You don't have to read them to use the service.
