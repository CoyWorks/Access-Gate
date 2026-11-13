# Roadmap

Access Gate provides a code portal, managed DNS-domain exports and a local HTTPS enforcement gateway. Users enter a code; administrators manage batches, grants and restricted domains. External FortiGate/Pi-hole routing/DNS and device trust remain target-network configuration. UI, messages and documentation remain English.

## Delivered

Version 0.7 additionally delivers administrator-browser and CIDR access exclusions, public portal sign-in/out and revocable seven-day rolling logins. See [EXCLUSIONS.md](docs/EXCLUSIONS.md).

| Issue | Status |
| --- | --- |
| [#12](https://github.com/CoyWorks/Access-Gate/issues/12) | Delivered in 0.8: activity/filtering/retention and per-code domain or opt-in navigation-path history, with bounded gateway delivery and health indicators. |
| [#18](https://github.com/CoyWorks/Access-Gate/issues/18) | Delivered in 0.8: confirmed per-batch and reviewed revoked-batch removal with retained invalid codes/history. |
| [#19](https://github.com/CoyWorks/Access-Gate/issues/19) | Delivered in 0.8/0.9: browser-owned requests, persistent notifications and explicit timed Approve / Deny. Approved visitors continue automatically without a code; sessions reuse normal expiry, extension, revocation and token history. |
| [#20](https://github.com/CoyWorks/Access-Gate/issues/20) | Delivered in 0.8: public home-page CA download link and retained HTTP trust-bootstrap path. |
| [#4](https://github.com/CoyWorks/Access-Gate/issues/4) | Delivered in 0.6: Settings password/management networks, cross-worker admin-session invalidation, no-lockout validation and local recovery. |
| [#10](https://github.com/CoyWorks/Access-Gate/issues/10) | Delivered in 0.6: live browser sessions, filters/pages/countdowns, extension links and confirmed per-browser termination. |
| [#13](https://github.com/CoyWorks/Access-Gate/issues/13) | Delivered in 0.6: installed version, service/clock/verified HTTPS/certificate status with bounded cached probes and stale/unknown states. See ADMINISTRATION.md for probe limits. |
| [#6](https://github.com/CoyWorks/Access-Gate/issues/6) | Configurable single-use code count, activation validity and access duration; retained in 0.4. |
| [#7](https://github.com/CoyWorks/Access-Gate/issues/7) | Clear revoked without restoring consumed/revoked codes; retained in 0.4. |
| [#8](https://github.com/CoyWorks/Access-Gate/issues/8) | Administrator-only active access extensions and idempotent submissions; retained in 0.4. |
| [#9](https://github.com/CoyWorks/Access-Gate/issues/9) | Named batches, status totals, filtering/pagination and whole-batch revocation; retained in 0.4. |
| [#2](https://github.com/CoyWorks/Access-Gate/issues/2) | Reworked in 0.4: automatic browser identity without user registration, IP-reuse isolation, unchanged deadlines across network changes and origin-bound gateway handoff. |
| [#1](https://github.com/CoyWorks/Access-Gate/issues/1) | Historical local proxy administration delivered in 0.3, retired in 0.4. DNS domains management/export added in 0.4.1; stable hosts/config feed URLs in 0.4.2; public blocklist URL import, 500,000-name capacity and paginated search in 0.4.3. New domains use exact or base-domain/all-subdomains scope and fixed target 10.40.22.5. Historical database records are retained without automatic activation. |

The 0.3 mandatory FortiGate-reader, device enrollment and transparent-Squid approach is superseded. Those runtime components are removed, not presented as a successfully completed network rollout. An already-enabled old interception must be rolled back before migration.

## Network acceptance — signed off

The operator explicitly signed off #3 (deadline/stream enforcement) and #5 (network/device integration) on 11 November 2026. Both issues are closed. Previously recorded test evidence and gateway limitations remain documented; no additional remote test execution is inferred.

See [GATEWAY.md](docs/GATEWAY.md) for supported transports and [INTEGRATION.md](docs/INTEGRATION.md) for the private API.

## P1 — administration

| Issue | Scope |
| --- | --- |
| [#11](https://github.com/CoyWorks/Access-Gate/issues/11) | Future access profiles require coordination with externally managed domain scopes; not a prerequisite for the basic portal. |

## Original P2 issues — delivered

| Issue | Delivery |
| --- | --- |
| [#14](https://github.com/CoyWorks/Access-Gate/issues/14) | 0.10: encrypted consistent backups, preflight and confirmed fail-closed restore. [Recovery](docs/RECOVERY.md). |
| [#15](https://github.com/CoyWorks/Access-Gate/issues/15) | 0.11: one-time printable/PDF cards and optional local QR prefill. [Exports](docs/EXPORTS.md). |
| [#16](https://github.com/CoyWorks/Access-Gate/issues/16) | 0.12: recurring schedules and encrypted one-time code collection. [Schedules](docs/SCHEDULES.md). |
| [#17](https://github.com/CoyWorks/Access-Gate/issues/17) | 0.13: reviewed Git updates with installed identity, persistent progress and service validation. [Updates](docs/UPDATES.md). |

Only #11 remains open in the original issue list. Each P2 issue was implemented, tested and pushed separately before the next issue began.

Administration details and recovery: [ADMINISTRATION.md](docs/ADMINISTRATION.md).

Requests, code history and cleanup: [OPERATIONS.md](docs/OPERATIONS.md).

### 0.10.0 — #14 delivered
Encrypted SQLite/CA/configuration backup, preflight and confirmed fail-closed restore are implemented. #3 and #5 signed off by the operator on 11 November 2026. See docs/RECOVERY.md for the recovery exercise and target checks.

### 0.11.0 — #15 delivered
One-time printable/PDF exports with optional local QR codes, explicit redemption and text fallback. Profile labels remain a dependency of future #11; current cards describe the current global restricted-domain scope.

### 0.12.0 — #16 delivered
Daily/weekly schedules, explicit DST/catch-up rules and secure one-time portal collection are implemented. No external code delivery is enabled.

### 0.13.0 — #17 delivered
Reviewed fixed-repository updates, persistent progress, clean-source identity and readiness checks are implemented through the maintenance worker. All original P2 issues (#14–#17) are delivered in separate commits; #11 remains open.

### 0.14.0 — phone administration
Installable admin PWA with opt-in, generic access-request Web Push, background delivery and existing Approve/Deny navigation. Real phone/provider acceptance uses the documented Send test workflow.

### 0.15.0 — request-first interface
Five-item navigation, inline request decisions, session/history cards and grouped settings are implemented. Approval scope remains global; #11 remains open. Browser screenshot acceptance remains an operator check due to preview environment restrictions.

## 0.26–0.29 — diagnostics and managed DNS lists

| Issue | Delivery |
| --- | --- |
| [#27](https://github.com/CoyWorks/Access-Gate/issues/27) | 0.26: guided client checks, standalone redacted DNS/TCP/TLS/portal diagnostics and real-device acceptance steps. [Client diagnostics](docs/CLIENT_DIAGNOSTICS.md). |
| [#28](https://github.com/CoyWorks/Access-Gate/issues/28) | 0.27: read-only policy explanation using the same exact/suffix matcher as DNS and the gateway. [DNS](docs/DNS.md). |
| [#29](https://github.com/CoyWorks/Access-Gate/issues/29) | 0.28: reviewed list subscriptions, independent ownership, scheduled safe refresh, rollback and schema 12 migration. [Subscriptions](docs/SUBSCRIPTIONS.md). |
| [#30](https://github.com/CoyWorks/Access-Gate/issues/30) | 0.29: bounded fixed-probe DNS health history, UDP/TCP/upstream latency and explicit reset/staleness handling. [DNS](docs/DNS.md). |

Each was implemented, tested and pushed separately. Access profiles (#11) remain planned; current authorization and subscription policy remain global. Automated local fixtures do not replace phone/target-server acceptance.

## Client/server usability follow-up

Issues #35–#42 track the next usability phase. #37 delivers public device onboarding and local CA bootstrap; #38 adds removable Apple CA/portal profiles and reviewable current-user Windows setup; #40 adds supported deployment changes through reviewed root maintenance jobs. Each selected issue is tested and pushed separately. The reviewed installation wizard (#35, 0.33) and optional first-use checklist (#36, 0.34) are delivered. Visitor failure pages (#39, 0.35) are delivered. Redacted support reports (#41, 0.36) are delivered. Frequent-action navigation (#42) remains planned. Access profiles (#11) remain outside this phase.

See [Client setup](docs/CLIENT_SETUP.md) and [Server settings](docs/SERVER_SETTINGS.md). Real personal-device installation and host/service acceptance are distinct from automated fixtures.
