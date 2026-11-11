# Deployment and service combinations

## Supported first-release combinations

| Deployment | Support | Ownership and routing |
| --- | --- | --- |
| Dedicated Ubuntu 24.04 VM with built-in DNS | Implemented | Access Gate owns its DNS/portal/gateway services; clients use this VM for DNS. |
| Dedicated Access Gate VM and Pi-hole on a separate host | Implemented | Pi-hole owns DNS; use the managed export and configurable sync helper. |
| Dedicated Access Gate VM and another external DNS server | Implemented with manual integration | Operator applies equivalent exact/subdomain mappings and prevents upstream AAAA/HTTPS bypass. |
| CloudPanel on another VM alongside a dedicated Access Gate VM | Independent services | CloudPanel keeps its web ports/configuration; restricted names point directly to the Access Gate VM. |
| Access Gate and CloudPanel/existing nginx on one OS | Implemented with address separation | Choose shared-nginx; existing listeners must leave the gateway IPv4 free on 80/443. |
| Full Pi-hole installation/lifecycle | Independent by design | Existing Pi-hole can coexist on the same host; built-in DNS is the self-contained installer option. |
| Public portal with a remote private gateway | Explicit opt-in from 0.21.0 | Verified public TLS, enrolled mTLS control and gateway-bound proofs; see PUBLIC_PORTAL.md. |

This matrix distinguishes implemented topology from target-system acceptance: local DNS UDP/TCP and Pi-hole-helper flows have automated tests; a fresh Ubuntu/CloudPanel combination has not been deployed in this workspace. Verify the documented install/network flows on target hosts before release.

## Addresses, ports and ownership

The current single-host application uses the selected IPv4 on TCP 80 for feeds/CA/HTTP forwarding and TCP 443 for the gateway and canonical HTTPS portal. Gunicorn and the gateway's HTTP handler use loopback TCP 8088/8089. Optional built-in DNS binds UDP/TCP 53 only on the configured address and enforces client CIDRs. Different services on separate VMs may use the same ports normally.

The installer does not automatically remove another DNS daemon, change host addresses, install CloudPanel/Pi-hole, edit their configuration, or install a public reverse-proxy arrangement. It detects listeners before package installation. Dedicated mode refuses existing enabled nginx sites/CloudPanel. Shared-nginx mode explicitly preserves them and requires a validated active nginx service. Source profiles do not override these checks.

Access Gate owns only its named systemd units, /etc/access-gate, /var/lib/access-gate, /opt/access-gate and its nginx site. Updates preserve the chosen DNS mode. Reset removes Access Gate units/site/state and reloads validated nginx configuration; it does not disable the global nginx service or an independent Squid service. Dependency packages remain installed. Recognized legacy Access Gate Squid integration follows its dedicated backup/retirement path.

Use a separate VM rather than assuming a second IP makes CloudPanel coexistence supported: listener ownership, package hooks and lifecycle need their own integration first. Shared-nginx uses address-aware conflict checks and explicit service ownership; wildcard conflicts must be resolved by the operator.

## Existing Pi-hole

The sync helper accepts ACCESS_GATE_FEED_URL and ACCESS_GATE_TARGET_IP through /etc/default/access-gate-pihole-sync. Use the actual configured values, not example addresses. See PIHOLE.md for installation, syntax validation, locking, rollback and cron setup. This is local dnsmasq configuration, not a Gravity adlist. Changing Access Gate's address requires updating both settings on Pi-hole.

For an external DNS product, verify exact-only and whole-domain behavior and all applicable record types. A hosts-style feed cannot represent wildcard scope; an A record alone may leave other types forwarded. Avoid forwarding loops when one DNS service uses the other as its upstream.

## Proxy trust boundary

HTTPS clients currently connect directly to the Access Gate gateway. It derives source identity from the peer. The loopback nginx HTTP path supplies the client header; the portal accepts forwarding headers only from its loopback boundary. Arbitrary proxies/CDNs in front of the gateway are unsupported. Do not grant a proxy subnet as an IP exclusion or trust client-provided X-Forwarded-For/X-Real-IP: that could grant every proxied user a bypass or management access. A future adapter must prove client identity, authorization and certificate handling before being advertised as supported.

## Target-system release checks

Install each advertised preset on a clean VM. Check selected-only service installation, absence of unexpected listeners, reboot, update, partial-install resume and reset. For external Pi-hole, verify fetch/apply, an empty list, wildcard/exact rules and rollback without touching Gravity or unrelated rules. For CloudPanel on another VM, verify its sites remain untouched and clients reach the dedicated Access Gate VM directly. Complete browser code/expiry/revoke and CA checks through the actual LAN/VPN routes.

## Shared nginx / CloudPanel host (implemented in 0.20.0)

Set `web_mode` to `shared-nginx` in the installation profile or select it in the wizard. The host must have an active, valid nginx service that includes /etc/nginx/sites-enabled/*. Access Gate reuses that service without installing/upgrading its nginx package, enabling it at boot, replacing nginx.conf, deleting default/other virtual hosts or restarting nginx. Only its own site is installed and validated; nginx is reloaded after changes.

Reserve a separate address for the Access Gate gateway. For example, existing CloudPanel/Pi-hole web sites can listen on 192.168.10.10, while Access Gate uses 192.168.10.20 on the same Ubuntu host. Both addresses must already exist. Configure other services to bind their own address before installing Access Gate. Wildcard 0.0.0.0/[::] web listeners overlap the gateway and are rejected. Access Gate never rewrites CloudPanel-managed virtual hosts to resolve that conflict. Point restricted DNS names and the canonical portal at the gateway address. No external HTTPS proxy or new forwarded-identity trust is introduced by this mode.

An existing Pi-hole can run on the same OS, provided web listeners do not occupy the gateway address/ports. Select external-pihole and install the normal sync helper locally, with the feed URL/target from Access Gate. Pi-hole may own DNS 53 while Access Gate does not install a DNS listener. Alternatively use built-in DNS on the gateway address; any existing DNS socket must bind another address. Do not configure both DNS services to forward back to each other.

Full Pi-hole auto-installation is deliberately not another preset: an existing installation keeps its own lifecycle and data, while built-in DNS supplies the self-contained preset. Shared CloudPanel support is address-separated coexistence using its existing nginx service, not a CloudPanel installer or an arbitrary CDN/proxy adapter. This resolves the current bundled-Pi-hole feasibility decision without downloading another mutable installer as root.

Automation tests cover accepted/rejected address bindings, preserved CloudPanel/other-site configuration, nginx reload ownership and existing DNS export/sync/browser identity boundaries. Actual CloudPanel/Pi-hole package versions still require the target-system checks above; no fresh multi-service host was provisioned in this workspace.
