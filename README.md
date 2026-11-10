# Access Gate

**Version 0.7.0.** A code portal and HTTPS gateway for temporary browser access. Users enter a single-use code; administrators manage codes, batches and access extensions. No VPN users or devices need to be registered. **DNS domains** manages your restricted list, imports public blocklist URLs and serves stable hosts/config feeds.

Keep selected DNS names pointed at `10.40.22.5` through Pi-hole. The installed gateway generates matching site certificates under the retained device-trusted CA, sends unauthorized browsers to the code portal and forwards authorized requests to the verified real HTTPS origin. It checks current deadlines and stops affected streams/WebSockets on expiry or revocation. See [Gateway setup and verification](docs/GATEWAY.md).

## Current deployment

Ubuntu Server 24.04 on `10.40.22.5/24`, gateway `10.40.22.1`. The portal is available at `https://10.40.22.5/`; administration is at `/admin`. The default client range `10.40.0.0/16` covers the existing local and VPN networks without registering individual addresses. The same browser keeps its access deadline when switching between Wi-Fi and VPN.

Different browsers have independent sessions, even on the same IP address. Deleting cookies or changing browsers requires a new unused code. An IP address alone never proves browser access.

## Clone and install

```bash
git clone https://github.com/CoyWorks/Access-Gate.git /root/Access-Gate
cd /root/Access-Gate
bash install.sh
```

Use a dedicated server. The installer creates the portal certificate/CA, admin password and database, configures Nginx for HTTP, and installs separate unprivileged portal and HTTPS gateway services. A dedicated intermediate CA signs on-demand site certificates; neither service receives the root CA private key. Current deployment addresses remain explicit in the installer; it is not a general-purpose installer for arbitrary networks.

The initial admin URL/password is saved locally:

```bash
cat /root/access-gate-initial-login.txt
```

New access codes use 8 characters in two groups, such as `K7MP-4RX9`. Input is case-insensitive and accepts codes with or without the separator. Previously generated 12-character codes remain valid.

To change the admin password, run on the installed server as root in an interactive terminal:

```bash
/usr/bin/python3 /opt/access-gate/configure.py --set-admin-password
systemctl restart access-gate.service
```

Enter and confirm the new password (at least 8 characters); input is hidden and the password is not saved in plaintext. Existing admin sessions are signed out after restart. Access codes, browser grants and certificates are preserved. The initial-login file is marked obsolete if present. Cancelling or mismatched input leaves the configuration unchanged.

## Access exclusions

Signed-in administrators bypass the code requirement in their browser. The normal portal includes Sign in/Sign out; logins last seven idle days and renew with portal/website use. In **Settings → Access exclusions**, add individual addresses (`10.40.32.20/32`) or networks (`10.40.32.0/24`) that should bypass the code requirement without gaining administrator permissions. Leave empty to disable IP exclusions. See [Exclusions, rolling login and enforcement](docs/EXCLUSIONS.md) for trusted-address/VPN/NAT behavior, cookie scope, logout and recovery.

## Administration

Signed-in navigation now includes **Settings** (password and separate management networks), **Sessions** (live remaining time, extension and confirmed per-browser termination) and **System status** (installed version, services, clock and verified gateway/certificate health). Runtime admin policy is stored in the database and checked across workers. See [Administration and local recovery](docs/ADMINISTRATION.md).

## Update or resume

```bash
bash /root/Access-Gate/update.sh
```

In a Git checkout, this fetches and fast-forwards clean `main`, then executes the downloaded updater/installer. Dirty, detached or diverged checkouts and fetch failures stop before deployment. It never discards local changes. Keep generated exports and local files outside the checkout.

For an extracted source archive or offline deployment:

```bash
bash update.sh --local
```

To resume an interrupted installation:

```bash
bash /root/Access-Gate/resume.sh
```

Updates back up configuration and the database under `/root/access-gate-resume.*`, retain previous application files under `/opt/.access-gate-previous-*`, and replace the whole portal including templates/static assets. Existing admin credentials, certificates, HMAC pepper, code digests and consumed/revoked flags are retained. A reset is unnecessary.

The final check waits up to 30 seconds for an actual verified HTTPS HTTP 200 response through the gateway. Persistent failures print portal/gateway/Nginx diagnostics and leave the backup available. This avoids reporting success merely because processes are `active`.

### Upgrading from 0.4.x

The normal update installs the gateway and its isolated issuing CA while migrating to schema version 6 and preserving existing browser grants, codes, credentials and the trusted root CA. Nginx releases its old 443 listener, and `access-gate-gateway` owns HTTPS on the same address. HTTP feeds and the CA download remain available. The existing root CA already installed on devices remains the trust anchor; keep selected DNS records pointed at this VM and perform the [restricted-host TLS/browser checks](docs/GATEWAY.md). No new VPN account mapping or remote firewall change is installed.

### Upgrading from 0.3.x or earlier

Schema version 4 retains existing batches, code validity, extension history and archived settings, and adds the optional DNS export list. The browser migration introduced in schema 3 invalidates old IP-only/VPN-bound grants because they cannot safely be assigned to an anonymous browser. Unused codes remain usable; consumed codes stay consumed. New browser grants keep their original deadline across ordinary restarts and subsequent updates.

The upgrade retires only the known Access Gate Squid/keeper integration: it restores the saved original Squid configuration, removes its known AppArmor addition and removes the obsolete worker/network units. Existing packages, historical domain/device records and root-only reader files are retained; the new application does not use them. Unrelated Squid settings are not rewritten. The new runtime has no privileged keeper, live FortiGate connector, proxy ACL files or mandatory user/domain registration.

If the former transparent interception was explicitly enabled, the installer stops **before migration**. Apply the matching FortiGate rollback and disable its local interception first, while the old `/opt/access-gate` toolkit is still installed. See the [previous activation/rollback guide](https://github.com/CoyWorks/Access-Gate/blob/254699ee14322aa20cd7d1641d51b84ead453a0a/docs/ACTIVATION.md). The updater cannot remove remote policy routes safely by guessing. Do not delete `network.json` to bypass this guard.

Application/database rollback requires the matching previous database backup and code. Restoring old data can restore consumed codes, so revoke affected codes before reopening access.

## Download launcher alternative

```bash
curl -fL https://raw.githubusercontent.com/CoyWorks/Access-Gate/main/access-gate.sh -o /root/access-gate.sh
bash /root/access-gate.sh install
```

The launcher downloads a fresh `main` archive into a new directory under `/root` on each run. Use `resume` or `update` instead of `install` for those operations. Never use `/opt/access-gate` as the source checkout; it is replaced during deployment.

## Code management

- Generate named batches of 1–1,000 codes, with 10 as the default.
- Set unused-code validity in whole hours/days, starting at generation, up to 365 days. A day means 24 hours.
- Set access per activation in whole minutes/hours, up to 7 days. An activation just before the code deadline receives the full configured access duration.
- Each code is permanently single-use. An active browser cannot stack another code or accidentally consume it.
- The timer continues when the page/browser closes. Expired/revoked browser access can use a new unused code immediately, without waiting for a worker.
- View batch counts, filter/paginate code lists, revoke individual codes or whole batches, and **Clear revoked** without making codes reusable.
- Extend active browser access from administration. Added time is measured from the current deadline, duplicate submissions are idempotent and expired/revoked sessions cannot be reopened.
- Download full codes once immediately after generation. Only keyed digests and partial hints are retained; full codes cannot be retrieved later.

Times are displayed in Europe/Amsterdam. The server's persisted deadline is authoritative; `/status` reconciles the visible countdown every five seconds. Keep the server clock synchronized.

## External redirects and website access

Version 0.5 installs the enforcement gateway alongside the portal. An enabled domain rule plus the matching Pi-hole DNS mapping sends that site's browser traffic to the gateway. The device must trust the retained root CA. Public DNS-over-HTTPS is resolved independently of Pi-hole, actual origin certificates remain verified and browser grant deadlines apply to both new requests and live streams. See [GATEWAY.md](docs/GATEWAY.md) for supported transports and practical limits; [INTEGRATION.md](docs/INTEGRATION.md) remains the private API reference.

### Build your Pi-hole domain list

In administration, open **DNS domains** and paste one domain per line. **Domain + all subdomains** is selected by default: `example.com` or `*.example.com` covers the base domain, `www.example.com` and deeper names such as `a.b.example.com`. Choose **Exact hostname only** when needed. Every enabled record points to the fixed target `10.40.22.5`.

You can enable/disable, delete or change the match scope of each entry. Adding duplicates keeps their current state/scope. Up to 500,000 entries are stored in SQLite and survive updates/restarts; historical 0.3 rules are not silently reactivated. Search and 100-row pages keep large lists manageable. The preview shows the first 50 enabled rules; feeds/downloads always contain every enabled rule. Code management and browser grants remain independent of this list.

### Import an existing blocklist URL

Under **DNS domains → Import a blocklist URL**, paste a public HTTPS raw-text URL, select the match scope for new domains and click **Import from URL**. For example:

```text
https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
```

The server downloads and parses the list only when submitted by an administrator. It supports hosts rows (`0.0.0.0 example.com`, including multiple aliases), one-domain-per-line lists and simple `||example.com^` rules. Comments, source IPs and local host boilerplate are ignored. Unsupported filters/options/exceptions are skipped and counted. The chosen scope applies to new domains, with **Domain + all subdomains** as the default; existing rows retain their state and scope. Every enabled imported domain uses our fixed target `10.40.22.5`, regardless of the original file's addresses.

The result reports new domains, existing entries, source duplicates and skipped entries. Imports are additive and atomic: fetching/parsing/limit failures do not modify the saved list. Reimport a URL to add newly listed domains; source removals do not delete saved entries. No list is preloaded, and no source subscription or periodic synchronization is installed.

Downloads are limited to 32 MiB and use verified HTTPS with bounded socket timeouts and a download time budget. Each redirect is validated, the resolved destination must be public, and the connection is pinned to that checked IP while preserving TLS hostname/SNI validation. Private/local/metadata targets, custom ports and URL credentials are refused. The source must be reachable directly from the portal server. Internationalized URL hosts are normalized; non-ASCII URL paths must be percent-encoded.

### Fetch the managed feeds

Two read-only feeds are available without login from the configured local/VPN client networks. Edits appear in their next response automatically:

| URL | Content |
| --- | --- |
| `http://10.40.22.5/domains.txt` | Hosts-format feed: `10.40.22.5 example.com`. Includes each enabled base/exact hostname. A hosts file cannot express the configured wildcard scopes. |
| `http://10.40.22.5/pihole.conf` | dnsmasq configuration preserving the target IP and every configured subdomain scope. Use this for whole-domain DNS redirection. |

These paths serve plain text over HTTP without an HTTPS/login redirect, even when the portal uses a canonical hostname. The administration pages still require HTTPS and administrator sign-in. Both feeds are also served through the gateway's portal HTTPS listener. They expose only enabled domain rules, not credentials, codes or sessions.

**Download Pi-hole config** still produces a file snapshot. The strict hosts-file download is available only when all enabled entries are exact matches, while `/domains.txt` always publishes the explicitly listed base/exact names with a comment explaining the wildcard limitation.

Pi-hole's ordinary adlist import extracts domain names for blocking; it does not keep the IP mapping from a hosts list. Its DNS answer follows Pi-hole's blocking mode. For the requested `10.40.22.5` destination and whole-domain coverage, fetch `/pihole.conf` and apply it as local DNS configuration. The feeds update automatically in Access Gate, but Pi-hole still needs to fetch and apply a new copy; this release does not install a poller or change Pi-hole's global blocking mode.

Follow [Pi-hole import, verification and rollback](docs/PIHOLE.md), including the Pi-hole 6 setting that enables `/etc/dnsmasq.d/`.

Pi-hole changes DNS answers. The browser still requests the original HTTPS hostname. The gateway now provides a short-lived matching site certificate signed by its intermediate under the retained root CA; the portal certificate itself still covers only the portal. Browser CA trust, actual DNS/routing and alternate-transport bypass controls remain target-network responsibilities.

For DNS-assisted proxying, leave selected domains pointing to the gateway throughout the access session. The gateway resolves the real upstream independently of those Pi-hole rewrites. Do not toggle DNS records every time a code activates/expires; DNS caches are not an authorization timer.

The updater installs certificate generation, forwarding and live gateway enforcement locally. It does not remotely change FortiGate policies, Pi-hole configuration or device trust. Real local-socket tests cover the TLS/code/forwarding flow and stream expiry; run the [target-device acceptance checks](docs/GATEWAY.md) before claiming the same result on the user's actual network.

## Server checks and startup errors

```bash
systemctl is-active access-gate nginx access-gate-gateway
curl --noproxy '*' --cacert /etc/access-gate/ca/root.crt -I https://10.40.22.5/
```

Expected: three `active` results and HTTP 200. For a persistent 502:

```bash
curl --noproxy '*' -sS -H 'X-Real-IP: 10.40.22.5' -o /dev/null -w 'Backend HTTP: %{http_code}\n' http://127.0.0.1:8088/
journalctl -u access-gate.service -n 60 --no-pager
journalctl -u access-gate-gateway.service -n 60 --no-pager
tail -n 20 /var/log/nginx/error.log
```

A 502 is not necessarily a startup race. Use the actual upstream/backend error. Do not reset or regenerate credentials to troubleshoot it.

## HTTPS and settings

The existing public CA is available at `http://10.40.22.5/ca.crt`. Verify its fingerprint on the server before trusting it on a device:

```bash
openssl x509 -in /etc/access-gate/ca/root.crt -noout -fingerprint -sha256
```

The portal uses secure host-only browser cookies, HTTPS, CSRF protection, attempt limits and a separate administrator session. Signing in/out of administration does not reset active code access. Use the configured canonical portal address consistently; alternate hostnames redirect there so browser identity is not split between aliases.

`/etc/access-gate/config.json` holds `portal_url`, `client_networks`, `database`, `secret`, `pepper`, `admin_hash` and `acl_token`. The first two are general portal settings, not user registrations. Root can validate/migrate settings with:

```bash
cd /opt/access-gate
python3 configure.py --check
```

The configured portal URL must have matching DNS and certificate coverage. Apply settings through the normal updater so gateway settings are regenerated and all services restart consistently. Gunicorn binds only to loopback. The gateway uses the actual HTTPS client peer address, trusts forwarded addresses only from the loopback HTTP proxy, strips private headers and hides `/internal/` from browsers. Do not expose the private API or upload config secrets, code exports, private keys or the runtime database to GitHub.

## Runtime paths

| Path | Purpose |
| --- | --- |
| `/opt/access-gate` | Managed application, templates and static assets |
| `/etc/access-gate/config.json` | Portal settings and secrets |
| `/etc/access-gate/acl-token` | Root-only gateway integration key |
| `/etc/access-gate/ca/` | Retained portal CA; private key remains root-only |
| `/etc/access-gate/gateway/` | Dedicated issuing CA and private gateway settings |
| `/run/access-gate-gateway/` | Private ephemeral certificate-loading files, removed immediately after loading |
| `/var/lib/access-gate/data/` | SQLite database and WAL files |
| `/root/access-gate-initial-login.txt` | Initial administrator credentials |

For a consistent manual backup, stop `access-gate`, copy the complete configuration/data directories, then restart it. No keeper service is required.

## Full reset

Only for this dedicated portal VM:

```bash
bash /root/Access-Gate/reset.sh --dry-run
bash /root/Access-Gate/reset.sh --purge
```

Purge permanently removes application state, credentials, certificates and saved Access Gate backups. It keeps the source checkout, system account and installed packages. Legacy interception must already be rolled back. FortiGate and Pi-hole are never reset by this command. A fresh install creates a new admin password and CA; device trust must then be updated.

## Tests

```bash
python3 -m unittest discover -s tests -v
bash -n install.sh
bash -n reset.sh
node --check static/gate.js
```

Node is only needed for the optional JavaScript syntax check.

Tests cover DNS export/import, large lists, migration, code/batch behavior, independent browsers, CSRF/admin controls, private API/handoff integrity, legacy retirement, readiness, deployment, reset and Git updates. Gateway tests use real local TLS with a root/intermediate chain, the actual Flask API and an independently certified HTTPS origin. They exercise automatic code return, bodies, header/cookie isolation, failed upstream TLS, stream/WebSocket revocation and expiry, extensions, private DNS rejection and continued portal access. Real systemd/Nginx configuration, external firewall/DNS rules and Android/iOS/Windows behavior still need target-network verification.
