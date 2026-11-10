# Changelog

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
