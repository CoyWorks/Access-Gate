# 0.19.2

- Document the proposed public portal/private gateway trust boundaries, browser handoff, enrollment, outage policy and acceptance matrix (#26).
- Keep public mode explicitly unsupported pending protocol implementation, MFA and target-system validation.

# 0.19.1

- Document supported separate-host service combinations and deferred shared CloudPanel/Pi-hole arrangements (#25).
- Reject existing enabled nginx/CloudPanel configurations before fresh installation.
- Preserve unrelated nginx/Squid services during reset and restrict default-site removal to fresh installs.

# 0.19.0

- Offer optional built-in DNS in the installation wizard and unattended profiles (#24).
- Use dnspython for bounded UDP/TCP forwarding, source-CIDR access checks, exact/subdomain mappings and local NODATA for non-A restricted queries.
- Publish rule changes automatically through an unprivileged snapshot worker; preserve last known-good rules and expose synchronization health.
- Add isolated DNS service identity, selected-only dependency installation, restore/reconfigure/reset integration and DNS verification guidance.

# 0.18.0

- Add root-only deployment reconfiguration with private staging, retained CA, generated portal certificate SANs and nginx validation (#23).
- Share maintenance locking, verify new HTTPS readiness and restore prior managed files on activation failure.
- Apply explicit management-network changes, invalidate admin/push enrollment on portal-origin changes and document client migration/recovery.

# 0.17.0

- Add interactive and unattended installation planning with explicit network review, protected password input and persisted DNS component choice (#22).
- Check addresses/ports before package changes; retain a private initial-install checkpoint for resume and print deployment-specific completion instructions.
- Built-in DNS is a separate component tracked in #24; it is not selectable until available.

# 0.16.0

- Centralize deployment identity, listeners, DNS target, portal aliases and network policy (#21).
- Preserve legacy settings explicitly on update; generate certificates, gateway and nginx from validated deployment values.
- Use direct verified TLS probes with configured SNI; parameterize external Pi-hole sync and provide neutral installation examples.

# 0.15.1

- Standardize administration headers through shared breadcrumb/title/description/action components.
- Keep Codes tabs visible and consistently selected on lists, details, create forms, confirmations and one-time output.
- Apply the same structure to Requests, Sessions, restrictions, history, security, phone setup and system maintenance; add consistent System/Settings tabs.
- Keep queued maintenance jobs in the correct navigation section without exposing private queue inputs.
- Add rendered-page regression coverage for header structure, active tabs, export controls and validation-error layouts. No schema or access-policy changes.

# 0.15.0

- Reorganize administration into Home, Requests, Sessions, Codes and More with desktop sidebar/phone bottom navigation.
- Add request-first dashboard, inline duration decisions, session cards/shared history, handout-batch separation and code presets.
- Group occasional tools, simplify the visitor shell and preserve access/security semantics and one-time exports. No schema change.

# 0.14.0

- Add an installable admin PWA, Home Screen icons and explicit per-browser push notification controls.
- Add payload-free VAPID notifications for new access requests through an unprivileged durable delivery worker; notification clicks open the pending Approve/Deny inbox.
- Add schema 10, bounded retries, subscription expiry/revocation, restore invalidation and phone setup documentation. No new Python dependencies.

# 0.13.0

- Add reviewed Git checks and confirmed admin-portal updates with persistent progress and post-deployment identity/readiness checks (#17).
- Share a single maintenance lock with CLI installation, retain private logs/snapshots and reject dirty/diverged/downgrade/stale-source updates.
- Record the actual installed clean-source commit; reload the root worker after updates and keep SQLite backup I/O under the portal account.

# 0.12.0

- Add daily/weekly scheduled code batches, DST-aware previews, pause/resume and idempotent manual runs (#16).
- Encrypt scheduled output with a public key and require a separate passphrase for one-time portal collection.
- Add schema 9 and an unprivileged scheduler; restore disables schedules and invalidates outstanding output.

# 0.11.0

- Add one-time printable A4/PDF code cards and locally generated optional QR prefill (#15).
- Keep single-use code storage; rendering failures retain the original generated codes as text.

# 0.10.0

- Add encrypted consistent backups, private restore preflight and confirmed fail-closed recovery through a fixed-action maintenance worker (#14).
- Preserve the retained CA and settings; restore revokes all saved codes/sessions and validates service readiness with encrypted rollback.

# Changelog

## 0.9.0

- Add Approve / Deny to pending access requests. Administrators choose minutes/hours; approval atomically grants the requesting browser a session without manual code entry. The waiting page polls its private decision and continues automatically through a fresh website challenge, with a manual link fallback.
- Reuse normal grant/token, expiry, extension, revocation and visit-history machinery. New approvals create an already-consumed, unexported Approval token; existing active access receives the selected duration once. Display links from the request to its session token, history and controls. All restricted-domain scope follows the existing code-session model.
- Enforce terminal/idempotent decisions, expired-request rejection, same-browser ownership and single-outcome concurrent approval/denial. Denial does not revoke unrelated access; repeated approval cannot reopen an ended session. Record approval/denial and resulting grants/extensions in Activity.
- Preserve legacy resolved/dismissed requests while migrating transactionally to schema 8. Keep passwords, codes, active grants, sessions/exclusions, CA and history. Update the request UI/docs to replace the 0.8 notification-only workflow.

## 0.8.0

- Add persistent browser-owned access requests, duplicate suppression/rate limits, visitor status and an authenticated admin inbox with unread notifications, mark-read/resolve/dismiss and 24-hour pending expiry. Notifications remain in the portal; handling a request does not issue access automatically.
- Add structured application activity with date/event/actor/batch filtering and per-code details. Record core code/batch mutations transactionally, redact submitted secrets and link events to retained codes/batches.
- Add per-code hostname history and opt-in navigation paths through the real gateway, with bounded asynchronous delivery, idempotent retry, health/drop reporting and code-only attribution. Strip querystrings/fragments/callbacks and exclude bodies/cookies/credentials. Default to domain-only logging, disclose the policy on the portal and offer Off/Pages plus 1–365-day retention (default 30).
- Add gateway maintenance for bounded retention cleanup, pending request expiry and once-only observed grant-expiry events. Preserve code consumption/revocation and existing grant/extension records independently of activity retention.
- Add confirmed individual batch removal and bulk cleanup of reviewed revoked batches. Transactionally revoke codes/grants, hide removed batches from normal lists, retain a Removed view and code history, and prevent reuse/revival across retries/restarts.
- Add an unauthenticated client-network-scoped HTTPS download of the existing public CA certificate and a home-page link. Retain the direct HTTP bootstrap URL; never expose private key material or regenerate device trust.
- Migrate transactionally to schema 7 while preserving active grants, administrator sessions/exclusions, domain rules and root CA. Document workflow, history/privacy scope and best-effort delivery limits.

## 0.7.0

- Add administrator-browser and configurable CIDR access exclusions without changing global DNS behavior. Keep management networks separate, validate aligned CIDRs and empty-list removal, require current password/CSRF/fresh policy version, and preserve existing code grants and CA.
- Add Sign in/Sign out to the public portal with entry-preserving automatic website return. Persist hashed, browser-bound administrator logins with a seven-day rolling server idle deadline; portal and actual proxied website activity renew it, passive polling/watchers do not. Revoke login/site proofs on logout and authentication-version changes, including cookie replay and other workers.
- Keep portal login credentials isolated from per-origin one-use handoffs/site proofs. Transfer only the trusted gateway peer address/activity flag through the private API; reject spoofed client headers, unmanaged domains and IP-only query assertions. Recheck exceptions on live streams so removal/logout/expiry closes only unauthorized traffic.
- Migrate transactionally to schema 6 with empty initial IP exclusions. Preserve root-owned configuration, codes, grants, domains and existing management policy; require one fresh login for old Flask-only administrator sessions. Document VPN/NAT, cookie lifetime, idle renewal and the fact that exclusions do not bypass TLS trust or unrelated Pi-hole blocking.

## 0.6.0

- Add administrator Settings for current-password-confirmed password changes and independent management networks. Persist hashed credentials/network policy with transactional optimistic concurrency and a cross-worker authentication version. Reject immediate network lockout, retain CSRF/login limits, and invalidate existing/legacy administrator sessions without changing code grants.
- Add offline management-network recovery and make the existing password command replace portal overrides. Preserve root-owned configuration and unprivileged service boundaries; runtime changes use schema-5 SQLite state.
- Add live, filtered/paginated browser session administration with server-synchronized remaining time, extensions and confirmed/idempotent per-session termination. Keep full codes and authentication hashes out of APIs; same-IP browsers remain isolated. Termination closes real gateway streams through live grant checks.
- Add sanitized admin-only system health: installed version, database, fixed service states, clock synchronization, verified local HTTPS, portal/issuer/root certificate expiry, bounded probes, 15-second cache and explicit stale/unknown/failure states. Local health does not claim remote Pi-hole/device/origin acceptance.
- Permit same-origin fetches in CSP for live status/countdown polling while retaining the strict form-action policy. Render polled values as text and keep a no-JavaScript page/confirmation fallback.
- Document the management screens, migration, recovery, session/enforcement semantics and health limits. Operator reports wired/Wi-Fi website flow and revocation working; automatic expiry and remaining device/VPN coverage are still target acceptance work.

## 0.5.3

- Add a locked Pi-hole cron sync helper that downloads the DNS configuration from 10.40.22.5, skips unchanged exports, checks DNS syntax and rolls back failed validation/restarts. Document native Linux installation and a five-minute cron schedule.

- Generate shorter single-use access codes with 8 unambiguous characters, displayed as XXXX-XXXX. Preserve existing code digests, separator/case-insensitive input, rate limiting and single-use/expiry behavior. Retry random collisions against all retained codes before committing a batch.
- Add `configure.py --set-admin-password` for hidden local password entry and confirmation. Store only the hash, rotate the Flask session secret to sign out admin sessions after restart, preserve browser grants/pepper and mark the old initial-login file obsolete. Cancelled/mismatched/short input leaves settings unchanged.

## 0.5.2

- End code form submissions on a same-origin continuation document before navigating back to the restricted website. This avoids Chrome blocking the cross-origin form redirect under the existing strict form-action policy.
- Automatically continue using the existing external script and provide a visible Continue to website link for browsers with JavaScript disabled. Keep one-time origin-bound tickets, cookies and active-grant checks unchanged.
- Cover the continuation and complete TLS/code/origin flow, including missing/invalid entries, another browser, revocation and ignored external redirect parameters.

## 0.5.1

- Fix gateway startup when the retained portal certificate was created with restrictive permissions, such as root:root 0640 under the installer's umask 027. Normalize both portal.crt and portal.key to root:accessgate-gateway 0640 while preserving their contents and the root/issuing CA.
- Refuse symlinked portal TLS files before changing their ownership/mode. Keep the original root CA directory/private key permissions untouched.
- Add a no-listener `python3 -m access_gate.gateway --check` credential/TLS probe and run it as the actual gateway service user before switching listeners. Install its runuser dependency and reset only the owned gateway unit's failed/start-limit state before restart.
- Add regression coverage for restrictive legacy certificate modes, unchanged keys/certificates/root permissions, symlink refusal and the no-bind credential probe.

## 0.5.0

- Install the client-facing HTTPS gateway on 10.40.22.5:443. Generate short-lived exact-host certificates on demand only for currently restricted names, including deep subdomains, with a bounded in-memory TLS-context cache.
- Preserve the root CA already trusted on devices. Provision/reuse a separate path-length-zero intermediate for the dedicated unprivileged gateway account; keep the root private key inaccessible to both application services and remove temporary leaf-key files immediately after loading.
- Connect automatic portal challenge/code/ticket return to verified real HTTPS origins. Keep the managed DNS mappings stable and resolve upstream IPv4 independently through bootstrapped, verified public DNS-over-HTTPS, rejecting non-public origin addresses.
- Revalidate each request and active HTTP stream/WebSocket against live grants and domain policy. Expiry, revocation, policy removal or API failure closes only the affected restricted connection; extensions update the checked deadline. Use a 0.5-second watcher with documented API/load/buffering limits.
- Hide private APIs from browsers, verify HTTP Host against TLS SNI, reject unmanaged names, strip private cookies/headers and HTTP3 advertisements, and disable shared proxy cookie jars/access logging. Preserve normal request bodies, responses, website cookies, compressed HTTP and basic WebSocket relay.
- Move Nginx to HTTP/feeds/CA handling, add the loopback HTTP gateway handler and isolated service with only the port-binding capability. Preserve code data, settings, schema 4 and existing grants; retain update backups, readiness diagnostics and known-service reset cleanup.
- Document install/update, CA reuse, real-device verification, public DNS reachability, expiry timing, rollback and unsupported transports/apps. The source has real local TLS/Flask/origin/stream/WebSocket regression evidence; the target srvaccess01/Android network deployment still needs verification.

## 0.4.3

- Add administrator-only Import from URL under DNS domains. Fetch public HTTPS hosts/domain lists, extract valid names, apply the chosen match scope and output the fixed target 10.40.22.5. No blocklist is preloaded.
- Support hosts aliases, plain domains, IDNs and simple ||domain^ records. Ignore source IPs/comments/local boilerplate; count duplicates and unsupported entries. Merge atomically while preserving existing enabled states/scopes, codes and browser grants. Reimport adds new names without deleting source removals or creating a scheduled subscription.
- Bound downloads to 32 MiB with verified TLS, checked/pinned public destinations, validated redirects and socket/download time limits. Reject local/private targets, credentials, custom ports, HTML, compressed responses and invalid UTF-8. Install ca-certificates for public TLS validation.
- Raise the stored list limit to 500,000 names. Add search, 100-row pages and a 50-rule preview while keeping full live feeds/downloads. Keep schema version 4 and normal install/resume/update behavior.
- Add parser/download/admin/atomicity regressions plus an 80,000-domain fixture covering import, bounded administration and complete output feeds. Real external-source connectivity and Pi-hole/gateway behavior still require the target deployment.

## 0.4.2

- Publish a stable read-only hosts feed at http://10.40.22.5/domains.txt, with enabled base/exact names mapped to 10.40.22.5 and explicit comments that hosts files cannot express wildcard scopes.
- Publish the complete redirect configuration at http://10.40.22.5/pihole.conf, preserving exact and all-subdomain rules. Both feeds reflect saved edits immediately without administrator login or HTTPS/canonical-host redirects, and remain restricted to the configured client networks.
- Add the two feed paths to the HTTP Nginx listener while keeping the portal/admin on HTTPS and private APIs hidden. Expose only domain data; feeds set no browser/admin cookies and do not contain codes, credentials or grants.
- Show both live URLs in DNS domains administration and retain strict downloadable exports. Document that Pi-hole adlists extract block domains rather than preserving hosts-file target addresses, and that Pi-hole still needs to fetch/apply the config for wildcard redirects.
- Keep schema version 4 and preserve the existing update/data workflow. No appliance settings, poller or global blocking-mode changes are installed.

## 0.4.1

- Add optional administrator-only DNS domains management for a custom Pi-hole list: bulk add, enable/disable, delete, per-entry match scope and live config preview.
- Default to base domain plus all subdomains, including deeper labels. Accept either example.com or *.example.com in this mode, and normalize case/IDNs and duplicates.
- Export enabled entries to a dedicated 99-access-gate.conf, always targeting 10.40.22.5. Subdomain rules use address= plus local= to prevent non-A lookups from escaping upstream through that rule. Exact entries use host-record=.
- Offer a hosts-format alternative only when all enabled rules use exact hostnames; never silently lose wildcard coverage in an export.
- Add schema version 4 transactionally while preserving existing codes, batches, credentials, browser grants and archived legacy settings. DNS list changes do not change authorization state.
- Document Pi-hole 5/6 local-configuration import, cache/record checks, rollback and the distinction from adlists, HTTPS and actual timed website enforcement. No automatic Pi-hole or firewall changes are applied.

## 0.4.0

- Make the default app a standalone code portal with automatic anonymous browser sessions. Remove mandatory VPN users, device registration and domain management screens.
- Preserve single-use batches, one-time exports, Clear revoked, batch revocation and administrator extensions. Multiple browsers sharing an IP remain independent; network changes do not renew the original deadline.
- Add private, origin-bound gateway authorization and one-time browser handoffs so an external gateway can use the portal without sharing its cookie across unrelated domains. Include browser redirects/cookie responses and an optional Nginx example.
- Remove the live FortiGate reader, privileged keeper, Squid/TLS inspection helpers and local interception toolkit from the runtime. Retire only their known local service/configuration additions during upgrade.
- Migrate transactionally to schema version 3. Retain batches, digests, used/revoked flags, extension history and historical settings. Invalidate old IP/VPN-bound grants; preserve new browser grants across ordinary restarts.
- Refuse migration before changes if legacy interception remains activated or cannot safely be restored. Keep matching remote firewall rollback an explicit prerequisite for those installations.
- Keep the 0.3.1 verified HTTPS readiness check and error diagnostics; reduce required running services to the portal and Nginx.
- Domain selection, external-site HTTPS, actual website forwarding and long-lived connection enforcement are responsibilities of the selected external gateway. This release does not claim to activate a live FortiGate/Pi-hole website gate.

## 0.3.1

- Wait up to 30 seconds for a verified HTTPS HTTP 200 response after service startup instead of failing on the first transient 502/refused connection.
- Bypass environment proxy settings for the local readiness check and retain CA/hostname verification. Redirects do not count as readiness.
- Show recent portal and Nginx error logs when startup remains unsuccessful; preserve the existing failed-update state and backup for diagnosis/resume.
- This fixes the premature final check; persistent backend startup failures still require the actual service logs.

## 0.3.0

- Add Restricted domains administration with case/IDN normalization, exact/subdomain modes, descriptions, search and enable/delete controls. Import existing rules once through schema version 2.
- Apply queued policies through the root worker with candidate validation, atomic ACL replacement, rollback, applied revisions and visible errors. Keep Flask unprivileged; grant deadlines are retained during domain updates.
- Add registered VPN accounts/device labels and a fresh, read-only FortiGate IKE query connector. Bind grants to verified accounts and session evidence; deny ambiguous, reassigned, disabled or unavailable identities.
- Track authorized restricted TCP tuples and close those on expiry/revocation. Add worker heartbeats, clock checks, watchdog/abnormal-stop cleanup and an opt-in real-stream test.
- Reject ECH/GREASE, missing SNI and malformed ClientHello data before SSL splice; preserve non-decrypted ordinary TLS with visible SNI.
- Add scoped, reversible nftables interception plus additive FortiGate plan/rollback generation. Keep interception disabled until explicit activation and verified prerequisites.
- Document Android-first activation, transport support limits, packet evidence, target-only tests and rollback in `docs/ACTIVATION.md`.
- Validate with 121 passing automated tests plus one target-only real-socket test skipped by default; Python/shell/JavaScript syntax checks pass.
- Issue #1 is implemented. Issues #2, #3 and #5 include the enforcement implementation but remain open for actual FortiGate/Squid/kernel/Android acceptance; no remote firewall changes or live device tests are claimed.

## 0.2.0

- Implement [#6](https://github.com/CoyWorks/Access-Gate/issues/6): named single-use batches with independently configurable code validity (hours/days) and access duration (minutes/hours), validation, generation summary and metadata in text exports.
- Implement [#7](https://github.com/CoyWorks/Access-Gate/issues/7): scoped Clear revoked action retaining internal records and revocation integrity.
- Implement [#8](https://github.com/CoyWorks/Access-Gate/issues/8): administrator-only extensions for active access, duplicate-submission protection, extension history and a synchronized client countdown.
- Implement [#9](https://github.com/CoyWorks/Access-Gate/issues/9): batch overview/details, status filters/counts, pagination and atomic whole-batch revocation with an impact preview.
- Add transactional schema version 1 migration preserving existing weekly batches, code digests and used/revoked state. Keep install/resume/update entry points unchanged.
- Retain the Default global domain policy and current source-IP pilot binding. Device identity, broad expiry/integration work, individual administration accounts and additional profiles remain open roadmap items.
- Add 36 regression tests for migration, management HTTP flows, validation and concurrency (83 tests total). Browser and live proxy integration require verification on the target deployment.

## 0.1.4

- Make `update.sh` fetch and fast-forward the local main branch before applying the update.
- Run the newly downloaded updater and installer after Git synchronization.
- Stop before installation on network errors, local changes, detached branches or diverged/unpublished history.
- Retain `update.sh --local` for extracted archives and explicit offline deployment.

## 0.1.3

- Add an explicit full reset command for the dedicated VM, including saved installation backups.
- Restore the original Squid configuration and remove only the Access Gate AppArmor rules.
- Keep source checkouts and installed dependency packages available for a fresh installation.

## 0.1.2

- Publish the application as source files at the GitHub repository root.
- Support downloads extracted under `/root`, with explicit install, resume and update entry points.
- Add a root-level downloader that fetches a clean `main` snapshot for every install, resume or update.
- Stage and replace the complete portal on updates, including templates and static assets; remove obsolete application files.
- Retain previous application code and back up server configuration and the database before replacing files.
- Preserve credentials, certificates, domain rules and existing code records during resume/update.

## 0.1.1

- Use English throughout the application, installer and documentation.
- Create `/var/lib/squid` explicitly before initializing the certificate cache.
- Add `install.sh --resume` to finish interrupted installations without replacing existing credentials, certificates or the code database.
- Add `update.sh` as a common entry point for updates and recovery.
- Keep the source checkout separate from `/opt/access-gate`, the installed application.
- Include ignore rules for local runtime data, generated codes and private keys.

## 0.1.0

- Initial local pilot with weekly single-use access codes and a Squid test proxy.
- Live VPN-session identity and transparent FortiGate routing remain pending integration work.
