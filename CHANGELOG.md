# Changelog

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
