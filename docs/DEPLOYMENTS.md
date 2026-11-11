# Deployment and service combinations

## Supported first-release combinations

| Deployment | Support | Ownership and routing |
| --- | --- | --- |
| Dedicated Ubuntu 24.04 VM with built-in DNS | Implemented | Access Gate owns its DNS/portal/gateway services; clients use this VM for DNS. |
| Dedicated Access Gate VM and Pi-hole on a separate host | Implemented | Pi-hole owns DNS; use the managed export and configurable sync helper. |
| Dedicated Access Gate VM and another external DNS server | Implemented with manual integration | Operator applies equivalent exact/subdomain mappings and prevents upstream AAAA/HTTPS bypass. |
| CloudPanel on another VM alongside a dedicated Access Gate VM | Independent services | CloudPanel keeps its web ports/configuration; restricted names point directly to the Access Gate VM. |
| Access Gate and CloudPanel/existing virtual hosts on one OS | Unsupported | Both need web listeners; fresh installer refuses existing CloudPanel/enabled nginx sites. Use separate VMs. |
| Access Gate with bundled full Pi-hole on one OS | Deferred | Pi-hole adds separate lifecycle, UI/web-port and DNS ownership concerns. Built-in DNS is the supported bundled option. |
| Public portal with a remote private gateway | Design milestone #26 | Not enabled by changing a URL; see PUBLIC_PORTAL.md when available. |

This matrix distinguishes implemented topology from target-system acceptance: local DNS UDP/TCP and Pi-hole-helper flows have automated tests; a fresh Ubuntu/CloudPanel combination has not been deployed in this workspace. Verify the documented install/network flows on target hosts before release.

## Addresses, ports and ownership

The current single-host application uses the selected IPv4 on TCP 80 for feeds/CA/HTTP forwarding and TCP 443 for the gateway and canonical HTTPS portal. Gunicorn and the gateway's HTTP handler use loopback TCP 8088/8089. Optional built-in DNS binds UDP/TCP 53 only on the configured address and enforces client CIDRs. Different services on separate VMs may use the same ports normally.

The installer does not automatically remove another DNS daemon, change host addresses, install CloudPanel/Pi-hole, edit their configuration, or install a public reverse-proxy arrangement. It detects listeners before package installation. Fresh installation refuses existing enabled nginx sites and recognized CloudPanel hosts, including inactive installations whose configuration would otherwise be overwritten. Source profiles do not override these checks.

Access Gate owns only its named systemd units, /etc/access-gate, /var/lib/access-gate, /opt/access-gate and its nginx site. Updates preserve the chosen DNS mode. Reset removes Access Gate units/site/state and reloads validated nginx configuration; it does not disable the global nginx service or an independent Squid service. Dependency packages remain installed. Recognized legacy Access Gate Squid integration follows its dedicated backup/retirement path.

Use a separate VM rather than assuming a second IP makes CloudPanel coexistence supported: listener ownership, package hooks and lifecycle need their own integration first. Shared-host support can be added through an explicit supported adapter, not by silently skipping port checks.

## Existing Pi-hole

The sync helper accepts ACCESS_GATE_FEED_URL and ACCESS_GATE_TARGET_IP through /etc/default/access-gate-pihole-sync. Use the actual configured values, not example addresses. See PIHOLE.md for installation, syntax validation, locking, rollback and cron setup. This is local dnsmasq configuration, not a Gravity adlist. Changing Access Gate's address requires updating both settings on Pi-hole.

For an external DNS product, verify exact-only and whole-domain behavior and all applicable record types. A hosts-style feed cannot represent wildcard scope; an A record alone may leave other types forwarded. Avoid forwarding loops when one DNS service uses the other as its upstream.

## Proxy trust boundary

HTTPS clients currently connect directly to the Access Gate gateway. It derives source identity from the peer. The loopback nginx HTTP path supplies the client header; the portal accepts forwarding headers only from its loopback boundary. Arbitrary proxies/CDNs in front of the gateway are unsupported. Do not grant a proxy subnet as an IP exclusion or trust client-provided X-Forwarded-For/X-Real-IP: that could grant every proxied user a bypass or management access. A future adapter must prove client identity, authorization and certificate handling before being advertised as supported.

## Target-system release checks

Install each advertised preset on a clean VM. Check selected-only service installation, absence of unexpected listeners, reboot, update, partial-install resume and reset. For external Pi-hole, verify fetch/apply, an empty list, wildcard/exact rules and rollback without touching Gravity or unrelated rules. For CloudPanel on another VM, verify its sites remain untouched and clients reach the dedicated Access Gate VM directly. Complete browser code/expiry/revoke and CA checks through the actual LAN/VPN routes.
