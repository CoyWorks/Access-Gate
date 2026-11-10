# Changelog

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
