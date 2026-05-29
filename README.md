# HaGeZi DNS: Free, Non-Commercial EU Public DNS Servers

HaGeZi DNS offers free, non-commercial public DNS resolvers designed and operated by a private individual for the European community. It provides robust DNS-based blocking of ads, trackers, scam, phishing, fake, and malware domains - helping users achieve greater privacy and security online with zero cost.

## Features

- EU-only hosting (Hetzner: Falkenstein, Nuremberg, Helsinki) and jurisdiction, with full GDPR and ENISA recommendations.
- Fully open-source DNS infrastructure combining Technitium DNS v15.2 Server with Unbound DNS v1.25.1 as an upstream recursive resolver, featuring a local root zone for enhanced privacy, security, and performance.

### Security & Privacy

- No recursion via third-party resolvers.
- Strict DNSSEC validation to prevent tampering.
- QNAME minimization is enforced for better privacy.
- DNS leak/rebind protection
- No EDNS Client Subnet, user location is not exposed to upstreams.
- Drop ANY requests for improving server performance and enhancing privacy.
- Strict rate limiting for response and clients.
- Encrypted transport: DNS-over-HTTPS/3 (DoH/DoH3), DNS-over-TLS (DoT) and DNS-over-QUIC (DoQ)
- ECH support: Encrypted Client Hello works alongside DoH/DoT to encrypt the TLS handshake, hiding the website name and making it far harder for observers to see which domains you visit.
- EDE (Extended DNS Errors) support, makes DNS errors more descriptive.
- Hidden version and identity: CHAOS version.bind and id.server queries are refused for security hardening.
- Firewall: restricted to ports strictly necessary for operation.
- Widely known internet scanners are restricted by the firewall.
- OS & DNS software are regularly updated for latest security.
- No logging or storage of individual queries per client.
- No sharing of any data with third parties. If you don't log anything sharable, you can't share anything.
  
### Filtering/Blocking

HaGeZi DNS employs a balanced blocking strategy to deliver robust privacy and security while minimizing unnecessary restrictions. This approach provides effective protection without excessive blocking, making it ideal for most users. The balance is achieved through the use of the following blocklists:

| Blocklist | Link | Blocks |
|------|------|-------------|
| HaGeZi Multi Pro | [Link](https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/pro.txt) | Ads, Tracking, Analytics, Metrics, Telemetry |
| HaGeZi TIF (Threat Intelligence Feeds) | [Link](https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/tif.txt) | Phishing, Malware, Scam, Fake, Cryptojacking |
| xRuffKez CTI (Cyber Threat Intelligence) | [Link](https://codeberg.org/xRuffKez/tif/raw/branch/main/domains.txt) | Phishing, Malware, other dangerous harmful (live-updated) |

No additional censorship, only security and privacy-oriented filtering.

> [!NOTE]
> Alternatively, a DNS server is available that blocks only Phishing, Malware, Scam, Fake, Cryptojacking and other harmful domains.

#### Block TTL (Time to Live) and Response

- **Block TTL: 3600**<br>Setting DNS block TTL to 3600 seconds (1 hour) reduces the frequency of repeated DNS requests for blocked domains. This lowers CPU and network activity on mobile devices, helping save battery life. The 3600 TTL balances caching efficiency and responsiveness, improving battery performance without sacrificing block update speed.
- **Block response: 0.0.0.0**<br>Blocked domains are answered with `0.0.0.0` instead of `REFUSED/NXDOMAIN` or `127.0.0.1`. This makes connections fail immediately without local timeouts or retries in many apps, reducing unnecessary traffic.

#### Special domain handling:

- **Blocked Mozilla Firefox canary domain**, answered with `NXDOMAIN` - prevents Mozilla Firefox from automatically switching to DNS-over-HTTPS in its settings.
- **Blocked Google Chrome preflight mode for prefetching**, answered with `NXDOMAIN` - applies DNS filtering to resources preloaded via Chrome’s private prefetch proxy.
- **Allowed access to Apple iCloud Private Relay** - supports macOS and iOS Mail Privacy Protection and Safari Tracking Prevention.

## Logging and Data Handling

- Hourly DNS statistics (processed and block domain rankings, per-client query counts) stored only in RAM, never written to disk and auto-deleted each hour or on service/server restart.<br>(Query counts per client are solely for rate limiting, no linkage to resolved/blocked domains or other details)
- Error logging: Only domains that fail to resolve (e.g., DNSSEC validation failure, upstream/server error, timeout - resulting in SERVFAIL) are logged, and those entries are retained for 24 hours for troubleshooting; no client IP addresses are stored.
- Uses an in-memory DNS cache for enhanced privacy. No query data is ever written to disk, and all entries are automatically cleared when they expire or the server restarts.
  
### Hourly statistics

A simplified version of the hourly statistics (number of queries, number of blocked queries, and number of clients) can be viewed via the following links: [root.hagezi.org](https://root.hagezi.org/stats.txt) | [wurzn.hagezi.org](https://wurzn.hagezi.org/stats.txt) | [juuri.hagezi.org](https://juuri.hagezi.org/stats.txt)

## Server Locations & Access

The servers are accessible via encrypted DNS protocols, including DNS-over-HTTPS/3 (DoH/DoH3), DNS-over-TLS (DoT), and DNS-over-QUIC (DoQ), as well as unencrypted DNS-over-53 (Do53). Whenever possible, I recommend using DoH or DoH3.

> [!WARNING]
> Clients that use multiple encrypted DNS protocols at the same time, such as DoH, DoT, and DoQ, against the same DNS server may resolve the same domain in parallel multiple times, which can unnecessarily exhaust rate limits. There is no practical benefit to using all encrypted protocols simultaneously; it only wastes resources.

#### Blocks Ads, Tracking, Analytics, Metrics, Telemetry, Phishing, Malware, Scam, Fake, Cryptojacking and other harmful domains:
                  
| Location           | Protocols     | Endpoint/URL                          | Apple<br>Config        | Recommended for    |
|--------------------|---------------|-------------------------------------|-----------------------|-------------------------|
| Germany, Falkenstein| DoH/DoH3      | `https://root.hagezi.org/dns-query`   | [Link](https://raw.githubusercontent.com/hagezi/dns-servers/refs/heads/main/mobileconfig/root-hagezi-org.mobileconfig) [QR](/mobileconfig/root-hagezi-org.mobileconfig.png)    | AT, BA, BE, BG, CH, CZ, DE, DK, FR, GB, HU, IE, IT, LU, NL, PL, RO, SI, SK | 
|                    | DoT/QUIC      | `root.hagezi.org`                     |                       |                         |
|                    | Do53      | `188.34.161.210`<br>`2a01:4f8:c17:1c66::1` |                       |                         |
| Germany, Nuremberg| DoH/DoH3      | `https://wurzn.hagezi.org/dns-query`   | [Link](https://raw.githubusercontent.com/hagezi/dns-servers/refs/heads/main/mobileconfig/wurzn-hagezi-org.mobileconfig) [QR](/mobileconfig/wurzn-hagezi-org.mobileconfig.png)    | AT, BA, BE, BG, CH, CZ, DE, DK, ES, FR, GB, GR, HR, HU, IE, IT, LU, MD, MK, MT, NL, PL, PT, RO, RS, SI, SK, TR, UA | 
|                    | DoT/QUIC      | `wurzn.hagezi.org`                     |                       |                         |
|                    | Do53      | `159.69.155.94`<br>`2a01:4f8:1c1c:d363::1` |                       |                         |
| Finland, Helsinki   | DoH/DoH3      | `https://juuri.hagezi.org/dns-query`  | [Link](https://raw.githubusercontent.com/hagezi/dns-servers/refs/heads/main/mobileconfig/juuri-hagezi-org.mobileconfig) [QR](/mobileconfig/juuri-hagezi-org.mobileconfig.png)    | DK, EE, FI, LT, LV, NO, SE | 
|                    | DoT/QUIC      | `juuri.hagezi.org`                    |                       |                         |
|                    | Do53      | `95.217.163.17`<br>`2a01:4f9:c013:dc4e::1` |                       |                         |

#### Blocks ONLY Phishing, Malware, Scam, Fake, Cryptojacking and other harmful domains:

| Location           | Protocols     | Endpoint/URL                          | Apple<br>Config        | Recommended for    |
|--------------------|---------------|-------------------------------------|-----------------------|-------------------------|
| Germany, Nuremberg| DoH/DoH3      | `https://ctif.hagezi.org/dns-query`  |  | AT, BA, BE, BG, CH, CZ, DE, DK, ES, FR, GB, GR, HR, HU, IE, IT, LU, MD, MK, MT, NL, PL, PT, RO, RS, SI, SK, TR, UA | 
|                    | DoT/QUIC      | `ctif.hagezi.org`                     |                       |                         |
|                    | Do53      | `162.55.58.40`<br>`2a01:4f8:1c19:6c19::1` |                       |                         |
                      
EU and neighboring countries with limited coverage from current server locations: AD, CY, GE, IS, LI, MC, ME, PT, SM, TR

### DNS Stamps

> [!NOTE]
> These encrypted DNS Stamps let compatible tools connect to HaGeZi DNS automatically, with all the needed details built in.

#### Blocks Ads, Tracking, Analytics, Metrics, Telemetry, Phishing, Malware, Scam, Fake, Cryptojacking and other harmful domains:
                  
| Endpoint | Protocol : DNS Stamp |
| -------- | ----- | 
| root.hagezi.org  | DoH: `sdns://AgMAAAAAAAAADjE4OC4zNC4xNjEuMjEwAA9yb290LmhhZ2V6aS5vcmcKL2Rucy1xdWVyeQ` |
|                  | DoT: `sdns://AwMAAAAAAAAADjE4OC4zNC4xNjEuMjEwAA9yb290LmhhZ2V6aS5vcmc` |
|                  | DoQ: `sdns://BAMAAAAAAAAADjE4OC4zNC4xNjEuMjEwAA9yb290LmhhZ2V6aS5vcmc` |
| wurzn.hagezi.org | DoH: `sdns://AgMAAAAAAAAADTE1OS42OS4xNTUuOTQAEHd1cnpuLmhhZ2V6aS5vcmcKL2Rucy1xdWVyeQ` |
|                  | DoT: `sdns://AwMAAAAAAAAADTE1OS42OS4xNTUuOTQAEHd1cnpuLmhhZ2V6aS5vcmc` |
|                  | DoQ: `sdns://BAMAAAAAAAAADTE1OS42OS4xNTUuOTQAEHd1cnpuLmhhZ2V6aS5vcmc` |
| juuri.hagezi.org | DoH: `sdns://AgMAAAAAAAAADTk1LjIxNy4xNjMuMTcAEGp1dXJpLmhhZ2V6aS5vcmcKL2Rucy1xdWVyeQ` |
|                  | DoT: `sdns://AwMAAAAAAAAADTk1LjIxNy4xNjMuMTcAEGp1dXJpLmhhZ2V6aS5vcmc` |
|                  | DoQ: `sdns://BAMAAAAAAAAADTk1LjIxNy4xNjMuMTcAEGp1dXJpLmhhZ2V6aS5vcmc` |

#### Blocks ONLY Phishing, Malware, Scam, Fake, Cryptojacking and other harmful domains:
                      
| Endpoint | Protocol : DNS Stamp |
| -------- | ----- | 
| ctif.hagezi.org  | DoH: `sdns://AgMAAAAAAAAADDE2Mi41NS41OC40MAAPY3RpZi5oYWdlemkub3JnCi9kbnMtcXVlcnk` |
|                  | DoT: `sdns://AwMAAAAAAAAADDE2Mi41NS41OC40MAAPY3RpZi5oYWdlemkub3Jn` |
|                  | DoQ: `sdns://BAMAAAAAAAAADDE2Mi41NS41OC40MAAPY3RpZi5oYWdlemkub3Jn` |

### Latency

> [!TIP]
> For a general idea of the latency between your location and our server locations, we recommend using [WonderNetwork’s Global Ping Statistics](https://wondernetwork.com/pings). 
> <br><br>
> Example of a [WonderNetwork](https://wondernetwork.com/pings) compilation configured for Germany:
> <br><br>
> <img width="792" height="241" alt="Screenshot 2025-11-26 123938" src="https://github.com/user-attachments/assets/224dcd94-8801-48ca-97b1-8b22b16396ff" />
> <br><br>
> To optimize latency when choosing DNS servers, you can personally measure the response times by pinging each DNS server from your own connection. This approach factors in your specific network conditions, such as geographic location, ISP routing, and local congestion, giving you a practical, real-world latency measurement. By selecting the DNS server with the lowest ping time, you maximize responsiveness and reduce DNS query delays for your devices or infrastructure.
> <br><br>
> [Latency cheat sheet](latency.pdf) - This PDF summarizes measured network latency in milliseconds from six European PoPs (Amsterdam, Falkenstein, Frankfurt, Helsinki, Nürnberg, Vienna) to cities across European countries, highlighting the fastest location per city and EU membership status based on WonderNetwork ping data.
> <br><br>
> **DNS resolution reference values (ms):**
> | DNS resolve / lookup time (ms) | Rating | What it usually means |
> |---:|---|---|
> | < 20 | Excellent | Very fast response, often due to a nearby resolver and/or a warm cache. |
>| 20–50 | Very good | Common target range for good user experience. |
>| 50–100 | OK | Usually fine, but can add noticeable delay if a page triggers many lookups. |
>| 100–120 | Average | Often cited as the upper end of “average” DNS lookup time. |
>| 120–200 | Slow | Suggests distance, routing/latency, resolver load, or extra resolution steps. |
>| > 200 | Very slow / problematic | Frequently indicates a real performance or reachability issue (retries/timeouts/overload). |

### Expected IP addresses

- `188.34.161.210` - `2a01:4f8:c17:1c66::1` (ptr:  `root.hagezi.org`) - Hetzner Online GmbH - Falkenstein, Saxony, DE
- `159.69.155.94` - `2a01:4f8:1c1c:d363::1` (ptr:  `wurzn.hagezi.org`) - Hetzner Online GmbH - Nürnberg, Bavaria, DE
- `95.217.163.17` - `2a01:4f9:c013:dc4e::1` (ptr:  `juuri.hagezi.org`) - Hetzner Online GmbH/HOS-GUN - Helsinki, Uusimaa, FI
- `162.55.58.40` - `2a01:4f8:1c19:6c19::1` (ptr:  `ctif.hagezi.org`) - Hetzner Online GmbH - Nürnberg, Bavaria, DE

If you see any IP addresses in your [DNS leak test](https://dnscheck.tools) results other than those expected, it indicates that your device or network might be leaking DNS queries through fallback resolvers or directly to your ISP. This means DNS requests are bypassing your intended DNS protection, potentially exposing your browsing activity to external parties. 

## Web-based DNS testing services

- **DNS Leak Test:** [dnscheck.tools](https://dnscheck.tools) - [dnsleaktest.com](https://www.dnsleaktest.com/) - [browserleaks.com](https://browserleaks.com/dns)
- **DNS Nameserver Spoofability Test:** [GRC](https://www.grc.com/dns/dns.htm)
- **DNS Rebind Test:** [ControlD](https://controld.com/tools/dns-rebind-test)
- **Domain Lookup Service:** [DNSclient](https://dnsclient.net)
- **DNS Zone/DNSSEC Status:** [DNSViz](https://dnsviz.net/)
  
## Getting Help

- Open a GitHub Issue or contact [support@hagezi.org](mailto:support@hagezi.org) for support and questions.

## Disclaimer / Privacy Policy (EU Compliance)

HaGeZi DNS is a non-commercial, publicly accessible DNS resolver service operated privately
for the public benefit in the EU.

- All servers are operated from data centers in the EU and fall under EU data protection laws,
  including the EU General Data Protection Regulation (GDPR). User DNS traffic remains within EU
  jurisdiction. Encrypted protocols are supported and recommended wherever possible to maximize
  privacy.
- No personal data is retained, persisted, or shared beyond what is technically necessary to
  operate the service. For operational integrity, temporary and anonymized query statistics are
  maintained for a maximum of one hour exclusively in memory, not on permanent storage. IP
  addresses are only ever processed for technical purposes such as query rate limiting and abuse
  prevention, on the legal basis of Article 6(1)(f) GDPR (legitimate interest), and are not
  stored in conjunction with or linked to any resolved or blocked domain data.
- No data is transferred to or processed in countries outside the European Economic Area (EEA).
  All data remains exclusively within EU-hosted infrastructure.
- This service is not directed at children under the age of 16. No data of minors is knowingly
  collected or processed.
- Error logs contain only metadata about DNS failures (domain, timestamp, error type); no client
  IP addresses are stored in those logs.
- No client data is ever sold or shared.
- This is a best-effort, volunteer-provided service with no warranty, availability, or liability
  for interruptions or malfunctions. It is intended for private, lawful use only. Misuse,
  automated abuse, or attempts to circumvent restrictions may result in access being blocked.
- The operator does not guarantee the accuracy or completeness of the blocklists used. False
  positives (legitimate domains being blocked) may occur. The operator accepts no liability for
  any issues resulting from incorrect blocking decisions.
- This service is not affiliated with any commercial provider, government body, or the DNS4EU
  consortium.
- Use of the service constitutes acceptance of these terms.

### Data Subject Rights (Art. 15–22 GDPR)

As virtually no personal data is retained by this service, the practical scope of data subject
rights under Articles 15–22 GDPR (including access, erasure, restriction, objection, and
portability) is limited by the privacy-preserving technical design of the service. For any privacy
inquiries or requests regarding data processing, contact
[privacy@hagezi.org](mailto:privacy@hagezi.org).

### Service Operator

HaGeZi [mail@hagezi.org](mailto:mail@hagezi.org) – private individual operating this
non-commercial volunteer service within the EU. Where applicable, information duties are provided
in accordance with Articles 13 and 14 GDPR.

*Last updated: 2026-03-22*



---
