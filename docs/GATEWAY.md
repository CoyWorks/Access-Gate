# Restricted-domain HTTPS gateway

Version 0.5 installs the HTTPS gateway on the existing portal VM. It provides the missing client-facing TLS/certificate generation, portal return flow, verified origin forwarding and live access enforcement. The same setup works for permitted Wi-Fi and VPN client networks; it does not need VPN user enrollment or FortiGate credentials.

## Install or update

```bash
bash /root/Access-Gate/update.sh
```

Use the ordinary install/resume entry points for fresh/interrupted deployments. No reset is needed. The installer preserves codes, credentials, the database, the existing portal certificate and the root CA already trusted on the devices. It creates a separate issuing intermediate signed by that root; the intermediate key belongs only to the dedicated gateway account. The portal account cannot read it, and neither service receives the root CA private key.

The installed roles are:

| Component | Listener | Role |
| --- | --- | --- |
| `access-gate-gateway` | `192.168.10.20:443` | Portal HTTPS and dynamic restricted-site HTTPS |
| `access-gate-gateway` | `127.0.0.1:8089` | HTTP hostname handling behind Nginx |
| `nginx` | `192.168.10.20:80` | Hosts/config feeds, public CA download and forwarding to the gateway's HTTP handler |
| `access-gate` | `127.0.0.1:8088` | Existing Flask portal and authenticated private gateway API |

The updater releases Nginx's old 443 listener before starting the gateway. It installs Ubuntu's `python3-aiohttp` and `python3-cryptography` packages and a dedicated `accessgate-gateway` service user. Only the port-binding capability is granted; the gateway runs without root, has a read-only application/configuration filesystem and can write only its private runtime directory. Known reset cleanup includes the gateway service.

Version 0.5.1 also gives that account group-read access to **both** retained portal TLS files. A legacy portal.crt can be root:root 0640 under the original installer umask, even though its public certificate is safe to serve to clients. Before changing listeners the installer runs a real `runuser -u accessgate-gateway -- /usr/bin/python3 -m access_gate.gateway --check` probe from the application directory. This loads its configuration, issuing credentials and portal TLS pair without starting a listener. It detects missing/denied files immediately and preserves their contents and the existing root trust.

An unrelated/custom 443 listener must not occupy this VM's address. Do not install the earlier optional Nginx site example alongside the built-in gateway; remove that reviewed example's site if you previously enabled it. The installer does not delete unrelated Nginx sites or firewall settings. Legacy 0.3 interception still needs its matching rollback before updating, as described in the README.

## DNS and device prerequisites

- Keep the selected hostname's DNS answer pointed at `192.168.10.20` for the whole session. Apply the managed [Pi-hole config](PIHOLE.md); a normal adlist does not preserve the destination IP.
- Permit the actual client subnet to reach this VM on TCP 80/443. The default `192.168.0.0/16` includes `192.168.40.0/24` and `192.168.50.0/24`.
- Trust the retained public Access Gate root CA in the intended browser/device. A device that already trusts the correct retained CA does not need a different CA installed after this update.
- The VM needs outbound verified HTTPS to public origins and the public DNS-over-HTTPS providers. The gateway bootstraps Cloudflare (`1.1.1.1`/`1.0.0.1`) and Google (`8.8.8.8`/`8.8.4.4`) independently of Pi-hole, retaining provider hostname/certificate validation. This avoids resolving the real website back to the gateway itself. Upstream IPv4 addresses must be public; local, private, loopback, link-local and reserved answers are refused.

Keep the normal device VPN/DNS enforcement in place. This release does not change FortiGate policies, client VPN profiles, Pi-hole configuration, or alternative DNS/VPN settings remotely.

## Browser flow

1. The client requests a selected HTTPS hostname whose DNS points at this VM.
2. The gateway checks the current enabled domain policy before issuing an exact-host certificate. It generates certificates on demand, including deep subdomains; there is no need to pre-generate every imported domain. The in-memory TLS-context cache is bounded to 256 entries, leaves are short-lived and temporary private-key files are removed immediately after OpenSSL loads them.
3. With no active site token, the gateway gets a private entry challenge and returns the browser to the canonical code portal. The original host receives its own Secure/HttpOnly challenge cookie.
4. After a valid code, the portal returns a one-use origin-bound ticket. The gateway exchanges it through the private API and installs the host-only site cookie.
5. The browser returns to the site's root. Every subsequent protected request checks the current grant and domain policy, then forwards to the verified real HTTPS origin using independent public DNS.

The existing session deadline is retained across Wi-Fi/VPN changes and portal restarts. A second selected host can reuse the active browser grant through another origin-bound handoff. Code values and raw portal browser tokens are never sent to the website. Reserved Access Gate cookies and private integration headers are removed from origin traffic. The gateway's upstream cookie jar is disabled, so different client browsers do not share website cookies.

Requests resume at the website root after login; original POST bodies and private paths/queries are not replayed through the handoff. Normal authorized requests, bodies, redirects, compressed responses, cookies, HTTP streaming and WebSockets are forwarded. Website `Alt-Svc`/alternate-protocol hints are removed because this gateway handles TCP HTTPS, not HTTP3.

## Expiry, revocation and failures

Every new protected request is authorized against the live persisted deadline. An independent watcher checks active HTTP streams and WebSockets every 0.5 seconds. Expiry, code/batch revocation, policy removal or a failed authorization check aborts the associated client transport and cancels its upstream work. Extensions are read on each check, so a fresh valid extension prevents closure based on an old deadline. Only the affected restricted connection is closed; other devices and the portal are not disconnected by IP-wide socket cleanup.

The 0.5-second interval is a polling target, not a real-time guarantee. Local API requests have a two-second timeout; CPU/event-loop load and network/kernel buffering add latency. Already delivered/downloaded/cached content cannot be withdrawn. An unavailable authorization backend denies new access and closes active protected flows on the next failed check. Restarting the gateway closes its active connections; surviving persisted grants are checked again on reconnect.

The gateway does not follow an origin's HTTP redirects internally. The browser processes them normally, so a new host is evaluated according to that host's own DNS/policy. Unknown or disabled TLS hostnames fail closed; HTTP Host/SNI mismatches are rejected. Private API routes are hidden from browser requests, even on the portal hostname. Source-IP headers are trusted only from the loopback HTTP proxy; HTTPS uses the actual client peer address.

## Supported scope and limits

This is a browser-oriented HTTPS/TCP gateway with HTTP/1.1 on its client listener. It handles selected hostname SNI, HTTP requests/streams and basic WebSocket relay. It does not provide UDP/QUIC/HTTP3 service, upstream IPv6-only access, arbitrary TCP protocols, upstream client-certificate authentication or support for apps that reject user CAs or use certificate pinning. It does not disable upstream certificate validation.

The Pi-hole wildcard config's `local=` rule suppresses fresh upstream AAAA/HTTPS/ECH records for that scope. Previously cached public addresses, HTTPS/ECH records or alternate transport routes may still need to expire or be cleared on test clients. ECH hiding the requested hostname and missing/unknown SNI cannot be decrypted by this gateway. Test the real devices' TCP fallback and prevent undesired alternate routes in the external network configuration before claiming full bypass prevention.

## Verify on srvaccess01

```bash
systemctl is-active nginx access-gate access-gate-gateway
ss -lntp
curl --noproxy '*' --cacert /etc/access-gate/ca/root.crt https://192.168.10.20/__access_gate/health
curl --noproxy '*' --cacert /etc/access-gate/ca/root.crt -I https://192.168.10.20/
```

Expect three active services, the listeners listed above, gateway health JSON and a trusted HTTP 200 for the portal.

Choose an enabled restricted hostname and substitute it in both places below:

```bash
curl --noproxy '*' \
  --resolve 'restricted.example:443:192.168.10.20' \
  --cacert /etc/access-gate/ca/root.crt \
  -I https://restricted.example/
```

Without a browser site cookie, expect a trusted TLS connection and HTTP 302 to the canonical portal with an opaque `entry` value. A certificate-name mismatch should no longer occur for the selected hostname. Unknown hosts should fail TLS or policy checks. Do not use `-k` to hide a certificate failure.

Then verify on Android over the actual VPN:

1. Open the restricted hostname and confirm the automatic portal navigation.
2. Activate a short-lived test code and verify the real site opens.
3. Confirm another browser does not inherit access.
4. Start a long-lived download/stream, test an administrator extension, then revoke the grant and verify the connection stops. Test natural expiry separately.
5. Confirm unrelated browsing and the direct portal stay reachable. Repeat over Wi-Fi and on other intended devices.

For errors:

```bash
journalctl -u access-gate-gateway -n 80 --no-pager
journalctl -u access-gate -n 60 --no-pager
nginx -t
```

Unknown-name TLS rejection can mean a disabled/missing rule, an unreachable policy API or an expiring issuer. HTTP 502 means authorization/origin connectivity or verified upstream TLS failed; inspect the actual path rather than disabling verification. Gateway access/body logging is disabled; do not add logs containing codes, cookies, ticket query strings or request bodies.

If 0.5.0 failed with `PermissionError` in `load_cert_chain()` and port 443 is refused, run the normal update to 0.5.1 or later. It repairs the retained portal TLS ownership/modes and clears the owned gateway unit's failed state. No reset, CA replacement or new code database is needed. To check credential access manually after updating:

```bash
cd /opt/access-gate
runuser -u accessgate-gateway -- /usr/bin/python3 -m access_gate.gateway --check
```

## State, renewal and rollback

The root CA remains under `/etc/access-gate/ca/`, inaccessible to either application service. Root-owned `gateway/issuer.crt`, `issuer.key` and `gateway.json` are readable only by the dedicated gateway group; the private integration key is in that configuration. The existing portal private key also becomes readable by that group. No administrator hash, Flask signing secret or code pepper is copied to the gateway configuration.

Ordinary updates reuse a matching valid intermediate and renew it when it has fewer than 30 days left, preserving the trusted root. Do not manually replace one half of an issuer key/certificate pair. An incomplete/mismatched pair stops setup with existing state/backups retained. A root CA that cannot sign an intermediate or is near expiry also stops setup; renewing device trust is a separate explicit maintenance task.

The normal updater backs up the entire configuration/database and keeps the prior application. To roll back, stop/disable `access-gate-gateway`, remove only its known `/etc/systemd/system/access-gate-gateway.service` unit and run `systemctl daemon-reload` before restarting the old portal. This removes its PartOf restart linkage. Restore the matching prior code and Nginx configuration, then restart the prior portal/Nginx services so Nginx owns 443 again. Preserve the current database when compatible; do not restore an older code database blindly, because it can restore consumed codes. Preserve the issuing/root CA state for a future forward update; do not reset FortiGate/Pi-hole or delete the root CA to troubleshoot.

## Validation evidence

The source test suite uses real local TLS listeners, a trusted root/intermediate chain, the actual Flask private API and an independently certified HTTPS origin. It verifies certificate names/deep subdomains, origin-bound code/cookie return, request bodies, cookie/header isolation, refused upstream certificates, bounded TLS state and issuer reuse. Real streaming HTTP and WebSocket tests verify expiry/revocation/policy/API failure, extensions and continued portal reachability. Public-DNS validation and bootstrap behavior are tested without relying on the machine's Pi-hole resolver.

These tests prove the implemented source behavior on local sockets. The updater has not been run remotely on srvaccess01 by this release, and Android/FortiGate/Pi-hole packet paths and transport caches still require the target checks above.

### Returning after code activation

Code submission redirects to a portal continuation page that returns HTTP 200. Its external script starts a new GET navigation to the existing entry handoff; a Continue to website link works without JavaScript. This ends the form redirect chain before leaving the portal, so Chrome can retain the strict `form-action 'self'` policy. The entry and live browser grant are rechecked before the usual one-time ticket is issued. Actual Android browser behavior still needs verification after updating.
