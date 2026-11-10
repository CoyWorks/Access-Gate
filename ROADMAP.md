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

## P0 — finish the chosen external integration

| Issue | Remaining scope |
| --- | --- |
| [#5](https://github.com/CoyWorks/Access-Gate/issues/5) | Built-in dynamic-TLS gateway, installed service, portal return and verified origin forwarding implemented in 0.5 with real local TLS tests. Operator reports the selected-site flow tested over wired/Wi-Fi. Remaining: VPN/other devices and transport/cache coverage. |
| [#3](https://github.com/CoyWorks/Access-Gate/issues/3) | Live stream/WebSocket expiry, revocation, policy/API failure and extension handling implemented/tested on real local connections in 0.5. Operator reports revocation working. Remaining: natural expiry, extensions, stream latency and restart/failure target evidence. |

See [GATEWAY.md](docs/GATEWAY.md) for the installed gateway and [INTEGRATION.md](docs/INTEGRATION.md) for its private API. The historical Nginx alternative is not installed and must not occupy the built-in gateway's 443 listener.

## P1 — administration

| Issue | Scope |
| --- | --- |
| [#11](https://github.com/CoyWorks/Access-Gate/issues/11) | Future access profiles require coordination with externally managed domain scopes; not a prerequisite for the basic portal. |

## P2 — convenience

| Issue | Scope |
| --- | --- |
| [#14](https://github.com/CoyWorks/Access-Gate/issues/14) | Consistent backups and restore without inadvertently restoring consumed codes. |
| [#15](https://github.com/CoyWorks/Access-Gate/issues/15) | Printable codes/PDFs and optional QR codes. |
| [#16](https://github.com/CoyWorks/Access-Gate/issues/16) | Scheduled batches with secure one-time code delivery. |
| [#17](https://github.com/CoyWorks/Access-Gate/issues/17) | Installed/available version display and controlled administration updates. |

Administration details and recovery: [ADMINISTRATION.md](docs/ADMINISTRATION.md).

Requests, code history and cleanup: [OPERATIONS.md](docs/OPERATIONS.md).
