# Built-in DNS

The optional built-in DNS component replaces the need for a separate Pi-hole for restricted-domain routing. It is a small forwarding DNS service using Ubuntu's python3-dnspython package, not a full Pi-hole or recursive DNSSEC validator. Existing external Pi-hole installations remain supported.

## Install and use

Choose built-in DNS in the installer, or set dns_mode to builtin and provide one to three dns_upstreams IPv4 addresses in the unattended deployment profile. Upstreams must not be this server or loopback; avoid an upstream that forwards back to Access Gate through another resolver. The installer detects TCP/UDP port conflicts and does not disable systemd-resolved or another DNS service automatically.

Set DHCP, VPN or individual client DNS to the chosen Access Gate server address. Permit selected clients to reach UDP and TCP 53, as well as TCP 80/443 for the website gateway. Client queries are allowed only from configured client_networks using the real socket peer address. Do not expose this DNS listener through a public port forward. Installing the component does not change your router/DHCP or prevent alternate client DNS/DoH.

Use the portal's Restricted domains screen normally. A dedicated unprivileged publisher updates an atomic snapshot every two seconds. The DNS service reloads changed snapshots on queries and keeps the last known-good rules if a snapshot is invalid. Publisher failure/staleness is reported under System status. There is no cron job to install on another host.

Exact-only rules affect only the named host. Whole-domain rules affect the apex and all subdomain levels. Restricted names return the configured gateway IPv4 for A queries and local NOERROR/NODATA for AAAA, HTTPS/SVCB and other types, without querying upstream. The canonical portal and aliases are also resolved locally. Unrelated queries preserve upstream responses, including IPv6 records and TTLs. UDP responses are bounded to 1232 bytes (or the client's smaller supported size); clients may retry via TCP. Upstream truncation uses dnspython's TCP fallback.

## Service isolation and limits

- access-gate-dns.service runs as accessgate-dns, with only the port-binding capability. It receives public network settings and a read-only rules snapshot, not portal secrets, the database or CA private keys.
- access-gate-dns-rules.service runs as accessgate, reads the existing domain database and writes only the DNS snapshot/status directory and normal application data.
- Both transports share a 32-request concurrency limit. TCP input has bounded sizes/deadlines and at most 16 queries per connection; each upstream has a two-second timeout. No additional DNS cache or query-history database is maintained.
- Query source authorization is an application CIDR check, not protection against source spoofing on an untrusted network. Keep normal network anti-spoofing/firewall controls in place.
- Client caches remain outside our control. A removed rule may remain cached briefly; existing public answers cached before restriction may continue until expiry. DNS redirection is only one part of website enforcement.
- This optional service is IPv4-bound; it can forward AAAA records for unrelated sites. There is no DHCP server, DNS-over-HTTPS endpoint or public DNS service.

## Verify

Substitute the installed server and a configured restricted name:

```bash
dig @192.168.10.20 restricted.example A
dig @192.168.10.20 child.restricted.example A
dig @192.168.10.20 restricted.example AAAA
dig @192.168.10.20 restricted.example HTTPS
dig +tcp @192.168.10.20 restricted.example A
dig @192.168.10.20 unrelated.example AAAA
systemctl status access-gate-dns access-gate-dns-rules
```

Test exact-only versus child behavior, domain disable/delete, an unauthorized client source and an unavailable upstream. Restart both services and repeat. Then verify code activation/expiry/revoke in an actual browser. Automated transport tests do not replace fresh-host package/systemd checks.

Updates preserve the selected component. Reconfigure updates its public identity settings; restore requires matching installed DNS components and regenerates snapshots from restored domains. Reset removes only Access Gate's DNS units/state; installed dependency packages and unrelated DNS configuration remain.

## Implementation references

The forwarder uses [dnspython UDP/TCP query support](https://dnspython.readthedocs.io/en/stable/query.html) and [message construction](https://dnspython.readthedocs.io/en/stable/message-make.html). A forwarding boundary is intentional: ordinary dnsmasq host records can forward other query types, while local-domain directives also affect child names. See the [dnsmasq maintainer discussion of local host query types](https://lists.thekelleys.org.uk/pipermail/dnsmasq-discuss/2026q4/018576.html). The built-in component therefore applies its exact/suffix decision before sending any record type upstream.
