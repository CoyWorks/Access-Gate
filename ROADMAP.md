# Roadmap

Planning only. Items below are not claims of implemented functionality. Keep the application interface, messages and documentation in English.

## Requested next: flexible code batches and revoked-code cleanup

These two items are at the top of P1 for the next portal iteration.

### Flexible code batches

- Choose how many codes to generate.
- Configure the code validity period in hours or days.
- Configure access duration per activation in minutes or hours.
- Keep validity and access duration as separate settings: validity controls whether a code may be activated; access duration controls the resulting session.
- Example: generate 10 codes, valid for 7 days, with 30 minutes of access per activation.
- Replace the fixed calendar-week and 15-minute restrictions with configurable values; existing weekly codes must retain their original behavior during migration.
- Validate quantities and duration values and show the validity and access duration clearly in administration.
- Keep activation, consumption and expiry enforcement server-side.

Decisions to confirm before implementation:
- Can one code be activated repeatedly within its validity period, or does each code remain single-use?
- Does the validity countdown start on generation, a chosen start time or first activation?
- How should an activation near the validity deadline behave: full configured session duration or a session capped by that deadline?

### Clear revoked

- Add a **Clear revoked** button to code administration.
- Remove revoked code entries from the visible code list without touching unused, active or merely expired codes.
- Clearing revoked entries must never restore access, make a consumed code reusable or interfere with active grants.
- Handle database references consistently; decide whether minimal revocation/audit records need to be retained internally.
- Show the number of affected entries and the operation result.

## P0 — reliable core behavior

| Order | Feature | Scope |
| --- | --- | --- |
| 1 | Restricted domains | Add, edit, remove and enable/disable domains in the portal; include subdomains and descriptions. |
| 2 | Devices and users | Stable device/account identification across VPN reconnects; prevent a reused VPN address from inheriting access. |
| 3 | Automatic unlock page | Complete HTTPS proxy/FortiGate integration, automatic portal presentation and return to the requested site. |
| 4 | Reliable access expiry | Enforce the configured duration, handle existing connections and show clear remaining-time/expired states. |
| 5 | Administration access | Separate administration access, password changes and allowed management networks/devices. |

## P1 — daily administration

| Order | Feature | Scope |
| --- | --- | --- |
| 1 | Flexible code batches | Configurable code count, validity in hours/days, and access per activation in minutes/hours; see requested-next details above. |
| 2 | Clear revoked | Dedicated cleanup action for revoked entries, preserving revocation and grant integrity. |
| 3 | Batch overview and controls | Name batches, show unused/redeemed/expired/revoked counts and revoke whole batches. |
| 4 | Active sessions | Live device/session overview, remaining time, terminate access and deliberate extensions. |
| 5 | Access profiles | Separate restricted-domain lists and associate code batches with a profile. |
| 6 | Activity log | Record activation, expiry and administrator changes with configurable retention. |
| 7 | System status | Portal/proxy/keeper health, clock synchronization, certificate expiry and useful errors. |

## P2 — convenience

| Order | Feature | Scope |
| --- | --- | --- |
| 1 | Backup and restore | Consistent backup and recovery, accounting for previously consumed/revoked codes. |
| 2 | Code exports | Printable pages/PDFs and optional QR codes alongside the existing text export. |
| 3 | Automatic batches | Prepare batches on a schedule using configurable defaults. |
| 4 | Updates in administration | Display installed/available versions and expose an update action with progress/results. |

Priority levels indicate importance. The requested code-management changes are the next requested portal iteration; network integration and reliable identity remain prerequisites for broader deployment.
