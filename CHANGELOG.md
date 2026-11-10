# Changelog

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
