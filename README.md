# Access Gate

A local pilot for temporary access to selected websites using single-use weekly codes. The interface, installer messages and documentation are in English.

**Version:** 0.1.4. **Current deployment:** Ubuntu Server 24.04, `10.40.22.5/24`, gateway `10.40.22.1`, portal `toegang.coyseinri.nl`.

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

- Generate a batch of 10 codes by default, or choose 1–100 codes.
- Select the Monday of the valid week. Unused codes expire the next Monday at 00:00, **Europe/Amsterdam**, including daylight-saving changes.
- Redeem each code once for 15 minutes from redemption. Sunday 23:55 gives access until Monday 00:10.
- The timer continues when the browser closes. A second code cannot be stacked while access is active and is not consumed by that attempt.
- Download full codes as text immediately after generation. They cannot be retrieved later; the database stores keyed HMAC digests.
- Revoke individual codes and their active grants.
- Use selective Squid HTTPS inspection for restricted domains; other domains pass through without HTTPS decryption.
- On expiry, close that client's proxy TCP connections. Ordinary websites on the same device may briefly reconnect too.

**Pilot limitation:** grants currently use the source IP, not a verified VPN device identity. Do not activate the entire dynamic VPN pool: a reused address could inherit another client's remaining access. Reliable VPN account/address assignment or live session identification must be connected and tested first. Portal cookies cannot identify requests to unrelated websites.

This package configures the local portal and an explicit proxy test. It does **not** modify FortiGate routes, Pi-hole settings or Linux interception rules. Automatic VPN traffic interception, QUIC/HTTP3, IPv6 and ECH handling remain integration steps after the local proxy test passes. Apps with certificate pinning may reject interception.

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

`/etc/access-gate/domains.txt` has one domain per line. An entry covers the main domain and its subdomains. Do not include schemes, URL paths, ports or wildcard characters. Keep the portal domain outside the list.

```bash
printf 'example.org\n' > /etc/access-gate/domains.txt
cd /opt/access-gate
python3 configure.py
```

The command validates the list, reloads Squid and invalidates active grants. An empty list restricts no real domains.

On the VM:

```bash
curl --noproxy '' --proxy http://10.40.22.5:3128 --cacert /etc/access-gate/ca/root.crt -I https://example.org/
```

After CONNECT, expect a `302` redirect to `https://10.40.22.5/`. Do not use `-k`: certificate trust is part of the test. Share the result before routing Android traffic automatically.

Squid uses 3128 for explicit tests; 3129/3130 are reserved for later transparent HTTP/HTTPS interception. Only configured pilot addresses may use the proxy; initially these are localhost and the VM itself. Content caching and access logs are disabled.

Determine Android's current VPN address before registering it. If it is still `10.40.135.11`:

```bash
cd /opt/access-gate
python3 configure.py --pilot-ip 10.40.135.11
```

The command replaces previous VPN pilot addresses and invalidates existing grants. A scoped FortiGate policy is still needed for NATIVE-VPN → vlan22 → 10.40.22.5. For later transparent interception, preserve the original destination and VPN source address and apply the local interception redirect on the proxy VM. FortiGate DNAT alone to 3130 is insufficient for Squid's original-destination checks.

## Runtime paths

| Path | Purpose |
| --- | --- |
| `/opt/access-gate` | Managed application, templates and static assets |
| `/etc/access-gate/domains.txt` | Restricted domains |
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
```

There are 47 tests covering code redemption, concurrency, exact expiry, week and DST boundaries, revocation, persistence, rate limits, CSRF, redirects and full application deployment. Deployment tests check obsolete-file removal, external-state preservation and recovery from a failed directory activation. Reset tests cover state removal, original Squid configuration restoration, preservation of unrelated files and refusal to purge when restoration checks fail. Updater integration tests use temporary local Git repositories to cover fast-forward updates, new updater execution, offline failures, dirty checkouts and diverged history. Git must be installed to run those integration tests. Live Squid, Android and FortiGate integration must still be verified on the target network.

References: [Squid SSL Bump](https://www.squid-cache.org/Doc/config/ssl_bump/), [external ACLs](https://www.squid-cache.org/Doc/config/external_acl_type/), [redirects](https://www.squid-cache.org/Doc/config/deny_info/), [Ubuntu squid-openssl](https://packages.ubuntu.com/noble/squid-openssl), [Flask security](https://flask.palletsprojects.com/en/stable/web-security/).
