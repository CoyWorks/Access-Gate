# Roadmap

The completed section records shipped portal features. All other items remain planned. Keep the application interface, messages and documentation in English.

## Completed in 0.2.0

| Issue | Delivered |
| --- | --- |
| [#6](https://github.com/CoyWorks/Access-Gate/issues/6) | Configurable single-use batches: count, validity in hours/days, access in minutes/hours, one-time export and a repeatable legacy migration. |
| [#7](https://github.com/CoyWorks/Access-Gate/issues/7) | Clear revoked, scoped globally or to one batch, retaining internal revocation and consumption records. |
| [#8](https://github.com/CoyWorks/Access-Gate/issues/8) | Active-session administrator extensions, duplicate-operation protection, minimal extension history and refreshed client countdown. |
| [#9](https://github.com/CoyWorks/Access-Gate/issues/9) | Named batch overview/detail pages, status counts/filters, pagination and whole-batch revocation. |

Resolved behavior: unused-code validity starts at generation; an eligible activation receives the full configured access duration even near the deadline. New validity days are fixed 24-hour periods. Existing weekly batches keep their calendar windows and 15-minute access. Extensions apply only to active, non-revoked access and never reset a code. Clear revoked archives rows rather than deleting their underlying records. Current limits and update instructions are in [README.md](README.md).

These portal features do not complete the pending VPN identity, interception, full expiry or administration-security work. Batches currently share the Default global domain list. Extension history is a minimal event record, not the complete activity log.

## P0 — reliable core behavior

| Order | Feature | Scope | Issue |
| --- | --- | --- | --- |
| 1 | Restricted domains | Add, edit, remove and enable/disable domains in the portal; include subdomains and descriptions. | [#1](https://github.com/CoyWorks/Access-Gate/issues/1) |
| 2 | Devices and users | Stable device/account identification across VPN reconnects; prevent a reused VPN address from inheriting access. | [#2](https://github.com/CoyWorks/Access-Gate/issues/2) |
| 3 | Automatic unlock page | Complete HTTPS proxy/FortiGate integration, automatic portal presentation and return to the requested site. | [#5](https://github.com/CoyWorks/Access-Gate/issues/5) |
| 4 | Reliable access expiry | Enforce the configured duration, handle existing connections and show clear remaining-time/expired states. | [#3](https://github.com/CoyWorks/Access-Gate/issues/3) |
| 5 | Administration access | Separate administration access, password changes and allowed management networks/devices. | [#4](https://github.com/CoyWorks/Access-Gate/issues/4) |

## P1 — daily administration

| Order | Feature | Scope | Issue |
| --- | --- | --- | --- |
| 4 | Active sessions | Live device/session overview, remaining time, terminate access and admin-only extensions in minutes/hours without reusing the code. | [#10](https://github.com/CoyWorks/Access-Gate/issues/10) |
| 5 | Access profiles | Separate restricted-domain lists and associate code batches with a profile. | [#11](https://github.com/CoyWorks/Access-Gate/issues/11) |
| 6 | Activity log | Record activation, expiry and administrator changes with configurable retention. | [#12](https://github.com/CoyWorks/Access-Gate/issues/12) |
| 7 | System status | Portal/proxy/keeper health, clock synchronization, certificate expiry and useful errors. | [#13](https://github.com/CoyWorks/Access-Gate/issues/13) |

## P2 — convenience

| Order | Feature | Scope | Issue |
| --- | --- | --- | --- |
| 1 | Backup and restore | Consistent backup and recovery, accounting for previously consumed/revoked codes. | [#14](https://github.com/CoyWorks/Access-Gate/issues/14) |
| 2 | Code exports | Printable pages/PDFs and optional QR codes alongside the existing text export. | [#15](https://github.com/CoyWorks/Access-Gate/issues/15) |
| 3 | Automatic batches | Prepare batches on a schedule using configurable defaults. | [#16](https://github.com/CoyWorks/Access-Gate/issues/16) |
| 4 | Updates in administration | Display installed/available versions and expose an update action with progress/results. | [#17](https://github.com/CoyWorks/Access-Gate/issues/17) |

Priority levels indicate importance. The requested code-management iteration is delivered in 0.2.0; network integration and reliable identity remain prerequisites for broader deployment.
