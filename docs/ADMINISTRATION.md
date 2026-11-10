# Administration

Version 0.6 introduced **Settings**, **Sessions** and **System status** to the signed-in navigation. Use the normal updater; no reset or replacement CA is needed. The transactional schema-6 migration preserves existing codes, grants, domain rules and administrator credentials. Version 0.7 adds revocable server-side logins; older Flask-only administrator cookies require a fresh login. See [EXCLUSIONS.md](EXCLUSIONS.md) for seven-day rolling sessions and IP exceptions.

## Password and management access

In Settings, enter your current password and the new password twice (8–256 characters). Only a password hash is stored. A successful change signs out all administrator sessions, including other Gunicorn workers; users' code grants keep their original end times. Every management request checks the live server login and current authentication version in the database.

Management networks are independent of the public code portal's client networks. Initially they inherit `admin_networks` from the root-owned configuration if configured, otherwise the existing client networks. Enter IPv4/IPv6 CIDRs, one per line. Changes require the current password, valid CSRF and a fresh settings version. The current management address must remain allowed. This prevents immediate self-lockout, but administrators should retain a trusted recovery network before changing network/VPN configuration.

The filter covers administration pages, login and management APIs. It uses the same trusted loopback gateway/peer boundary as the portal, not an untrusted forwarded address. Code redemption, DNS exports and website authorization retain their existing access rules.

Runtime password/network changes are stored in the application's database; `config.json` remains root-owned. Its admin hash is the bootstrap fallback, not necessarily the current password after a portal change. The initial-login file is no longer authoritative after a password change. Include both database and root-owned config/secrets in a consistent backup.

For a lost password, on the installed server as root:

```bash
python3 /opt/access-gate/configure.py --set-admin-password
systemctl restart access-gate.service
```

This also replaces any portal password override and preserves management networks, codes and grants. For management-network recovery:

```bash
python3 /opt/access-gate/configure.py --reset-admin-networks
```

This restores management access from the configured client networks and invalidates admin sessions. It takes effect across workers without a service restart; it does not broaden the public client-network configuration.

## Live browser sessions

Sessions lists the activation address, batch, start/end time, remaining time and state. Addresses are informational and do not identify the current VPN user or prove whether a browser is connected. Access belongs to the browser session. There is no device/user enrollment.

The authenticated API `/admin/api/sessions` refreshes every five seconds. It supports `state=active|expired|terminated|revoked|all` and numbered pages of 100 records, with server timestamps and state totals. No full codes, browser-cookie hashes or other authentication material are returned. Countdown values synchronize against server time and are never used for authorization. A failed refresh is marked stale rather than leaving a false indication of current state.

Extend opens the existing administrator-only extension workflow. Terminate opens a confirmation page; its CSRF-protected POST revokes only the selected grant, even when other browsers share the activation IP. The code remains used. Repeated termination is harmless. All workers/gateway checks see the persisted change. New requests are denied; the installed gateway closes affected HTTP/WebSocket connections on its next live check (normally a 0.5-second poll, subject to API timeout, scheduling and network buffering). Already downloaded content cannot be withdrawn. A browser's connection status is not inferred from grant state.

Expired/terminated grants are shown while their records remain in the database. An explicitly invoked external cleanup hook may remove historical grants; this page is not the future activity log (#12).

## System status

The admin-only page/API (`/admin/system`, `/admin/api/health`) reports the installed VERSION file, portal/database readability, the fixed access-gate/access-gate-gateway/nginx service states, system clock synchronization and a verified HTTPS health request to the installed listener.

The TLS probe connects directly to `10.40.22.5:443` with the configured portal hostname for certificate/SNI verification, independently of system DNS/proxy settings. It uses only `/var/lib/access-gate/public/ca.crt`; it cannot read the root CA private directory. A successful response supplies issuing-certificate expiry; the verified portal certificate and public root CA expiry are also displayed. Certificate expiry warns within 30 days. An unsynchronized clock warns, an unavailable probe is Unknown/Failed and a failed service is Failed. Healthy local checks do not claim that a selected external website or every device works.

Read-only systemctl/timedatectl commands have one-second timeouts; the local TLS/HTTP socket has a one-second timeout. Results are cached for 15 seconds per web worker. Concurrent checks return a clearly stale snapshot or Unknown while the first probe is running. The page refreshes every 15 seconds and marks failed client refreshes stale. The first request may take several seconds while bounded probes run. The health check does not run arbitrary user-supplied commands and reports sanitized failure reasons.

These checks do not inspect remote Pi-hole cron state, test public DoH/origin reachability, decrypt private keys, or prove end-to-end deadline enforcement. Use the gateway/device checks in [GATEWAY.md](GATEWAY.md) for those. Services remain unprivileged; no extra sudo privileges or system configuration write access are granted to the portal.

## Validation

The 0.6 release passes 217 Python tests, including actual local HTTPS gateway/stream enforcement and certificate-health probes, cross-worker password invalidation, policy migration/recovery, concurrent settings updates, session isolation, API filtering/pagination and health timeout/staleness cases. `node tests/test_admin_ui.js` checks polling, safe text rendering, action links and failed/stale refresh states without external DOM dependencies. Python, shell and JavaScript syntax checks pass. These are local source/integration checks, not a claim that the new screens are deployed on srvaccess01.
