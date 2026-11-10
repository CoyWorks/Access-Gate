# Access Gate

A local pilot for temporary access to selected websites using configurable single-use codes. The interface, installer messages and documentation are in English.

**Version:** 0.3.1. **Current deployment:** Ubuntu Server 24.04, `10.40.22.5/24`, gateway `10.40.22.1`, portal `toegang.coyseinri.nl`.

## Enable the working VPN path

Version 0.3.0 adds domain administration, a live FortiGate identity connector, targeted restricted-connection expiry, strict visible-SNI checks and a scoped Linux/FortiGate interception toolkit. Follow **[docs/ACTIVATION.md](docs/ACTIVATION.md)** after updating. It includes reader-key setup, exact prerequisites, additive firewall plan generation, Android acceptance tests and matching rollback.

An update installs these components but does not activate traffic interception or remotely change the FortiGate. Real firewall output/permissions, Squid/kernel behavior and the Android browser path still need target-network verification. ECH/GREASE, pinned apps, external IPv6 and alternative website ports have explicit support boundaries in the guide. Start with one Android device and a unique VPN account.

## Download and run from /root

Download the launcher once:

```bash
curl -fL https://raw.githubusercontent.com/CoyWorks/Access-Gate/main/access-gate.sh -o /root/access-gate.sh
```

Choose the operation:

| Situation | Command |
| --- | --- |
| Fresh installation | `bash /root/access-gate.sh install` |
| Resume the interrupted installation | `bash /root/access-gate.sh resume` |
| Update the complete portal | `bash /root/access-gate.sh update` |

Each run downloads the latest `main` archive into a **new directory under `/root`**, extracts it and executes that snapshot's installer. It never overlays a new download onto an old source directory. This prevents deleted source files from returning during an update. The launcher does not depend on your current working directory or a Git checkout. Downloads are kept in `/root/access-gate-download.*` for inspection if something fails.

**For the installation that stopped at the missing `/var/lib/squid` directory, use `resume`.** The updated installer creates the directory with the correct owner and reuses your existing database, credentials and certificates. Do not delete `/etc/access-gate/config.json` to bypass the guard.

The launcher requires `curl`, `tar` and `mktemp`. The target must be Ubuntu 24.04 with the configured server address. Deployment-specific addresses are currently explicit in the pilot; this is not yet a general-purpose installer for arbitrary networks.

## Full installation reset

For the dedicated Access Gate VM, update your local checkout and run the explicit purge command:

```bash
cd /root/Access-Gate
git pull --ff-only
bash reset.sh --purge
```

This permanently deletes the portal installation, configuration, code database, generated CA/certificates, initial admin credentials and saved Access Gate installation backups. It stops and disables the portal, keeper, Squid and Nginx services on this dedicated VM. The original Squid configuration is restored, and only Access Gate's known AppArmor block is removed. The source checkout, system account and installed dependency packages remain. FortiGate and Pi-hole configurations are not changed.

The script validates that restoration is possible before removing data. You can inspect its file plan first with `bash reset.sh --dry-run`.

Start a clean installation after a successful purge:

```bash
bash install.sh
```

The new installation generates a new admin password and CA. If you installed the previous CA on devices, remove that old CA and install the new one. Do not use this purge procedure on a VM hosting unrelated Nginx/Squid workloads.

## What install, resume and update do

- **Install** creates the initial CA, portal certificate, admin password and code database. It refuses to overwrite an existing configuration.
- **Resume** verifies the existing state and completes an interrupted setup without regenerating credentials or keys.
- **Update** uses the existing state and replaces the entire installed portal, including Python code, HTML templates, stylesheets and JavaScript. Obsolete application files disappear from the active installation.

Before replacing application code, existing portal/keeper services are stopped and configuration plus the database are backed up in a private `/root/access-gate-resume.*` directory. Previous application code is retained under `/opt/.access-gate-previous-*`. Source files are staged and Python syntax is checked before swapping application directories. If the directory activation itself fails, the previous directory is restored.

Deployment settings, restricted domains, code records, the admin password, HMAC pepper and certificates are retained in their separate runtime directories. Managed Squid/Nginx configurations and service definitions are reapplied from the package. Back up manual changes to those managed files before updating.

Services restart during update. In this pilot, restarting the keeper invalidates active grants; used codes remain used and unused codes retain their original validity window. Previously loaded browser content cannot be removed remotely. If a later configuration or service check fails, the installer stops and shows the error; backups remain available, but a complete automatic service/configuration rollback is not implemented.

## Updating existing data

Run the normal updater; a reset is unnecessary. Installation/resume/update automatically run transactional, versioned SQLite migrations before starting services. Schema version 2 preserves all code batches, HMAC digests, consumption/revocation flags and extension events, adds VPN account/session bindings, and imports the legacy domain list once. Older weekly batches retain their original window and 15-minute access duration.

After migration, use **Restricted domains** for rule changes. The worker validates and applies them atomically, shows requested/applied revisions and errors, and rolls back to the previous policy on failure. It runs outside the unprivileged web process. Applying rules reconnects proxy sockets, including already-spliced tunnels, without silently revoking other grant deadlines.

Existing installations default to live VPN identity enforcement after this upgrade. Until the reader and a distinct VPN account are registered, restricted VPN access stays locked; the local portal remains available. Interception remains an explicit, separate activation. The installer retains existing network activation state if you already enabled it through the toolkit.

The installer makes its normal pre-update database/configuration backup. Keeper startup invalidates active grants, so plan updates between access sessions. Rollback requires the matching previous application **and its database backup**; old code against an upgraded schema is unsupported. Restoring data may restore consumed codes: revoke affected codes before allowing use again.

## Direct source and Git workflows

The repository root contains `install.sh`, `resume.sh`, `update.sh` and `access-gate.sh`.

From any complete source download:

```bash
bash install.sh install
bash install.sh resume
bash install.sh update
```

Run only the operation you need. `resume.sh` is a shortcut for resume. `install.sh` and `resume.sh` use the downloaded files directly. In a Git clone, `update.sh` first fetches the latest `origin/main`, fast-forwards the clean local main branch and starts the newly downloaded updater and installer. It then selects update when server state exists and a fresh install otherwise.

For an extracted archive or an explicit offline deployment, use `bash update.sh --local`; this skips Git synchronization and applies only the source already present. The separate `access-gate.sh` launcher still downloads a fresh archive on every run.

For a Git checkout:

```bash
git clone https://github.com/CoyWorks/Access-Gate.git /root/Access-Gate
cd /root/Access-Gate
bash update.sh
```

Subsequent updates need only:

```bash
cd /root/Access-Gate
bash update.sh
```

The updater refuses to install when Git fetch fails, files have local changes, untracked files exist, HEAD is detached, the checkout is not on main, or local history has diverged/unpublished commits. It does not discard, stash or force-reset local changes. If main is already current, it reapplies that version normally.

When upgrading from version 0.1.3 or earlier, run `git pull --ff-only` once to obtain this automatic updater. After that, `bash update.sh` is sufficient. Never use `/opt/access-gate` as the source checkout: it is the managed runtime directory and is fully replaced during deployment.

## Current feature scope

- Create named batches of 1–1,000 codes (10 by default).
- Choose unused-code validity in whole hours or days, starting at generation, up to 365 days. A day is exactly 24 hours; absolute dates use **Europe/Amsterdam**.
- Choose access per single activation in whole minutes or hours, up to 7 days. Activating just before the code deadline grants the full configured access duration.
- Each code is permanently single-use. The timer continues when the browser closes, and another code cannot be stacked onto active access.
- Download full codes as text immediately after generation, including the batch name and validity/access details. Full codes cannot be retrieved later; only keyed HMAC digests are stored.
- Browse paginated batches and code lists with unused, redeemed, revoked, expired and future status filters. Batch totals include archived revoked records. All batches currently use the Default global domain list; configurable profiles remain planned.
- Revoke individual codes or a whole batch, including its active grants. Whole-batch revocation shows an impact preview and result counts.
- **Clear revoked** hides revoked code rows while preserving their consumption/revocation records and references. From Overview it affects all batches; from a batch detail page it affects only that batch, across all status filters/pages. It never deletes unused or merely expired codes.
- **Extend access** adds whole minutes or hours to the current deadline of still-active, non-revoked access. Expired access cannot be reopened. Each extension allows up to 7 days and the resulting remaining window cannot exceed 365 days. Repeating the same submitted operation adds time only once.
- See the latest 20 extension events, including added time, old/new deadlines and the administrator's source IP. The portal countdown refreshes the persisted deadline every five seconds. There is currently one shared administrator account; individual accounts and a full activity log remain planned.
- Use selective Squid HTTPS inspection for restricted domains; other domains pass through without HTTPS decryption.
- On expiry, close the tracked restricted proxy TCP connections. Coalescing or tuple reuse may require another connection to reconnect too; see the documented limits.

**VPN identity:** each registered account is verified against live FortiGate IKE evidence, including the assigned address and observed session identifier. Missing, ambiguous or unavailable evidence denies restricted access. A changed binding invalidates the old grant rather than renewing it or passing it to the next IP holder. Register and label/disable users through **Devices & users**. Existing manual addresses alone are not identity proof. The conservative connector may also invalidate access on IKE rekey; see the activation guide.

**Enforcement:** proxy permissions use the persisted deadline. Restricted connections are tracked by their client/listener TCP tuple and closed by the worker; unrelated independent browsing is not revoked. Heartbeat/time synchronization and systemd watchdog checks fail closed for restricted access. Real closure timing and tuple/coalescing limitations are documented in the guide. Already downloaded browser content cannot be removed remotely.

**Interception:** the opt-in toolkit installs only the owned `inet access_gate` nftables table and generates a separate FortiGate change/rollback scoped to `NATIVE-VPN`. The original destination and source identity are preserved. Existing IKE, OCI tunnels and Pi-hole configuration are retained. No source-code test proves Android routing, CA trust or IPv6 lockdown; complete the target-network acceptance table before broader rollout.

## Update reports HTTP 502

`active` service processes may still be starting their HTTP workers. Version 0.3.1 waits up to 30 seconds for a real HTTPS HTTP 200 response, bypassing environment proxies while retaining certificate verification. If the portal still fails, the updater stops and prints recent portal/Nginx errors; it does not report a successful install or erase existing state.

Rerun `bash /root/Access-Gate/update.sh` to fetch and apply the startup-check fix. For an existing failure, these read-only checks distinguish a backend problem from a proxy/startup problem:

```bash
curl --noproxy '*' -sS --cacert /etc/access-gate/ca/root.crt -o /dev/null -w 'Portal HTTP: %{http_code}\n' https://10.40.22.5/
curl --noproxy '*' -sS -H 'X-Real-IP: 10.40.22.5' -o /dev/null -w 'Backend HTTP: %{http_code}\n' http://127.0.0.1:8088/
journalctl -u access-gate.service -n 60 --no-pager
tail -n 20 /var/log/nginx/error.log
```

No reset is required. A persistent 502 is not proven to be a startup race; use the recorded upstream error and backend traceback to fix its actual cause.

## Server checks

```bash
systemctl is-active access-gate access-gate-keeper squid nginx
curl --cacert /etc/access-gate/ca/root.crt -I https://10.40.22.5/
```

Expected: four `active` results and HTTP `200`. For diagnostic output:

```bash
journalctl -u access-gate -u access-gate-keeper -u squid -u nginx -n 80 --no-pager
```

The initial admin URL and password are recorded locally:

```bash
cat /root/access-gate-initial-login.txt
```

Never upload that file, the private CA key, configuration secrets, code exports or the runtime database to the repository. Generated deployment secrets are not included in this source tree.

## CA trust and administration

Download the public CA certificate from `http://10.40.22.5/ca.crt`. Compare its fingerprint against the server:

```bash
openssl x509 -in /etc/access-gate/ca/root.crt -noout -fingerprint -sha256
```

Install it as a trusted **CA** on the test device. Keep existing IKEv2 VPN certificates unchanged. After confirming browser trust, open `https://10.40.22.5/admin`, sign in and generate the first code batch. Save the code export before leaving the generation page.

Nginx permits portal clients from `10.40.0.0/16`; Gunicorn listens only on loopback. The portal uses HTTPS, secure cookies, CSRF checks and attempt limits. An internal DNS record can later point `toegang.coyseinri.nl` to `10.40.22.5`; the existing portal certificate covers both the hostname and IP. No public port forward or CloudPanel configuration is required for this local deployment.

## Domain list and local proxy test

Use **Restricted domains** to add, edit, disable or delete domain rules, including descriptions and exact-domain versus subdomain behavior. Case and IDNs are normalized. Schemes, paths, ports, wildcards and portal-trapping rules are rejected. Search rules and refresh the applied revision after changes. `domains.txt` is retained only as the one-time upgrade import source.

For an initial explicit-proxy check on the VM, add `example.org` in the portal and wait until Applied:

```bash
curl --noproxy '' --proxy http://10.40.22.5:3128 --cacert /etc/access-gate/ca/root.crt -I https://example.org/
```

After CONNECT, expect a `302` redirect to `https://10.40.22.5/`. Keep certificate verification enabled. Configure live VPN identity and follow [the activation guide](docs/ACTIVATION.md) before routing device traffic.

Squid uses 3128 for explicit tests and 3129/3130 for opt-in transparent HTTP/HTTPS interception. Only configured pilot addresses may use the proxy; initially these are localhost and the VM itself. Content caching and access logs are disabled.

The default installation permits localhost and the VM itself for explicit checks. `configure.py --identity-check` verifies the reader. `configure.py --enable-vpn-enforcement` admits the VPN subnet while requiring verified identities. Legacy `--pilot-ip` remains a narrow address selector and does not establish device identity. Neither operation changes the FortiGate.

## Runtime paths

| Path | Purpose |
| --- | --- |
| `/opt/access-gate` | Managed application, templates and static assets |
| `/etc/access-gate/domains.txt` | One-time legacy domain import |
| SQLite domain/device/policy tables | Persistent managed rules, bindings and apply status |
| `/etc/access-gate/fortigate.json` and `ssh/` | Root-only reader configuration, private key and pinned host key |
| `/etc/access-gate/network.json` | Explicit local interception activation state |
| `/run/access-gate/control.sock` | Fixed-operation local identity interface |
| `/etc/access-gate/config.json` | Session secret, code pepper, admin hash and pilot clients |
| `/etc/access-gate/ca/root.key` | Private CA key |
| `/var/lib/access-gate/data` | SQLite database and WAL files |
| `/root/access-gate-initial-login.txt` | Initial admin credentials |

For a consistent manual backup, stop portal and keeper briefly, copy the full data directory plus configuration/certificates, then restart. Restoring an older database can restore consumed codes, so revoke affected codes after a restore.

## Tests

After installing the Ubuntu packages, run from the source directory:

```bash
python3 -m unittest discover -s tests -v
bash -n install.sh
bash -n resume.sh
bash -n update.sh
bash -n access-gate.sh
bash -n reset.sh
node --check static/gate.js
```

The suite currently runs 128 tests (127 pass; the target-only real-socket test is skipped without opt-in). It covers code redemption, concurrency, exact expiry, week and DST boundaries, revocation, persistence, rate limits, CSRF, redirects and full application deployment. Deployment tests check obsolete-file removal, external-state preservation and recovery from a failed directory activation. Reset tests cover state removal, original Squid configuration restoration, preservation of unrelated files and refusal to purge when restoration checks fail. Updater integration tests use temporary local Git repositories to cover fast-forward updates, new updater execution, offline failures, dirty checkouts and diverged history. Git must be installed to run those integration tests. Code-management tests additionally cover legacy migration/rollback, independent durations, malformed forms, scoped archival, batch counts/pagination, extension idempotency, expiry under writer-lock contention and concurrent revocation/redemption/keeper actions. HTTP tests render and submit the administration flows. New tests also cover domain normalization/matching, policy rollback, applied-revision races, account/address reuse, verified-session changes, identity failures, heartbeat expiry, targeted connection cleanup, TLS SNI/ECH parsing, scoped network rendering and schema-1 upgrades. The real socket-destruction test is opt-in and requires root/CAP_NET_ADMIN on the target VM; see the guide. Live browser, Squid, Android and FortiGate integration still requires target-network verification.

References: [Squid SSL Bump](https://www.squid-cache.org/Doc/config/ssl_bump/), [external ACLs](https://www.squid-cache.org/Doc/config/external_acl_type/), [redirects](https://www.squid-cache.org/Doc/config/deny_info/), [Ubuntu squid-openssl](https://packages.ubuntu.com/noble/squid-openssl), [Flask security](https://flask.palletsprojects.com/en/stable/web-security/).
