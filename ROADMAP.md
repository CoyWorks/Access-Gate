# Roadmap

Access Gate is a basic, vendor-independent code portal. Users enter a code; administrators manage batches and active grants. An optional DNS domain list produces Pi-hole exports; applying DNS/routing rules and actual website enforcement belong to the external FortiGate, Pi-hole or proxy setup. UI, messages and documentation remain English.

## Delivered

| Issue | Status |
| --- | --- |
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
| [#5](https://github.com/CoyWorks/Access-Gate/issues/5) | Choose/configure the actual redirect/enforcement adapter. Verify the supplied entry/handoff/authorization contract, external-site certificates, real return flow and actual device/browser paths. |
| [#3](https://github.com/CoyWorks/Access-Gate/issues/3) | Portal/API deadlines are implemented. Verify that the chosen gateway also stops existing restricted streams/connections at expiry and handles extensions/revocation correctly. |
| [#4](https://github.com/CoyWorks/Access-Gate/issues/4) | Strengthen administrator authentication/password management and management-network restrictions. Anonymous code users do not need accounts. |

See [INTEGRATION.md](docs/INTEGRATION.md). A redirect alone is not website authorization. The optional Nginx example is not installed by the portal updater and does not claim strict open-stream expiry.

## P1 — administration

| Issue | Scope |
| --- | --- |
| [#10](https://github.com/CoyWorks/Access-Gate/issues/10) | Improve active browser-session management, remaining time and termination controls. |
| [#11](https://github.com/CoyWorks/Access-Gate/issues/11) | Future access profiles require coordination with externally managed domain scopes; not a prerequisite for the basic portal. |
| [#12](https://github.com/CoyWorks/Access-Gate/issues/12) | Activity log and configurable retention. |
| [#13](https://github.com/CoyWorks/Access-Gate/issues/13) | Portal/gateway health, clock/certificate status and useful errors. No obsolete keeper/reader dependency. |

## P2 — convenience

| Issue | Scope |
| --- | --- |
| [#14](https://github.com/CoyWorks/Access-Gate/issues/14) | Consistent backups and restore without inadvertently restoring consumed codes. |
| [#15](https://github.com/CoyWorks/Access-Gate/issues/15) | Printable codes/PDFs and optional QR codes. |
| [#16](https://github.com/CoyWorks/Access-Gate/issues/16) | Scheduled batches with secure one-time code delivery. |
| [#17](https://github.com/CoyWorks/Access-Gate/issues/17) | Installed/available version display and controlled administration updates. |
