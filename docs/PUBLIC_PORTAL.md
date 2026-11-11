# Public portal and private gateway: architecture proposal

Status: proposed architecture, issue #26. **Remote public portal mode is not implemented or supported yet.** Changing portal_url or opening firewall ports does not enable this design. No existing private control endpoint should be exposed publicly.

## Purpose and separate roles

A user should be able to enter a code or request access on a public, conventionally trusted HTTPS website. Their restricted website traffic still goes through a locally reachable gateway. The gateway enforces the grant; the public portal is not a general website proxy.

| Role | Public reachability | Responsibilities and secrets |
| --- | --- | --- |
| Visitor portal | Public HTTPS | Code redemption, access requests and browser identity; code hashes/authorization state stay server-side. |
| Administration | Private/VPN initially; separate explicitly enabled public option later | Approve/deny, code generation and audit. Public option requires MFA and abuse controls. |
| Authorization service | Authenticated gateway endpoints only | Gateway identity, restricted entry state, one-time handoff and grant introspection/revocation. |
| Website gateway | Selected LAN/VPN client networks | DNS-mapped website listeners, origin validation, site cookies and current access enforcement. Holds its local restricted-site issuer; never uploads the inspection root key. |
| DNS | LAN/VPN only | Built-in resolver or external Pi-hole. It directs restricted names to the private gateway, not to the public visitor portal. |

The initial implementation should remain single-tenant: one operator and explicitly enrolled gateways. A hosted multi-customer SaaS, arbitrary external gateways, subscription billing and account recovery are separate projects.

## Network and TLS layout

Use independent settings for public portal origin, management origin/reachability, authorization endpoint, gateway identity/listeners, DNS redirect target and permitted client networks. Public portal TLS should use a normal trusted certificate with monitored renewal, optionally managed by a supported web-host adapter. Gateway site interception retains its separate locally trusted CA and verified public-origin TLS. Publicly trusted portal TLS cannot issue certificates for restricted third-party domains.

CloudPanel could host the ordinary portal upstream on a supported separate public deployment. It would own its public TLS termination; the private gateway would continue owning its local TCP 443. Do not attempt to send all arbitrary restricted-domain TLS through an ordinary portal reverse proxy. Forwarded source addresses must be accepted only from explicitly configured, authenticated/trusted proxy hops; proxy addresses must never become automatic access exclusions.

Gateway-to-authorization traffic uses verified HTTPS and per-gateway mTLS enrollment credentials (a separate purpose-bound enrollment CA or equivalent independently reviewed scheme). Enrollment is operator initiated, short-lived and one-time. Record a gateway ID, permitted role and revocation status. Define certificate renewal and immediate credential revocation. Do not reuse the website inspection root key as a public authorization/enrollment credential.

## Browser grant and handoff

Cookies from the public portal cannot be read by the private gateway or an unrelated restricted origin. Authorization must therefore use a validated handoff, preserving the existing browser-bound intent rather than substituting the client's IP:

1. A gateway creates a restricted-site entry over its authenticated control connection, registering its ID, exact allowed destination origin, a random challenge commitment and a short deadline. It sets a secure host-only challenge cookie on that restricted origin and redirects to the public portal with an opaque entry reference.
2. The portal redeems a single-use code or receives an approved request for its own browser-bound session. It does not assume a shared cookie, browser identity or source IP across origins.
3. The authorization service creates a short-lived, single-use handoff tied to that entry, gateway, destination origin, original challenge commitment, grant and expiry. Redirect destinations are derived only from the registered allowed entry; user-provided return URLs cannot select arbitrary hosts.
4. On return to the restricted site's completion endpoint, the gateway requires the original challenge cookie and consumes/verifies the handoff through the authenticated authorization service. Missing/mismatched challenge, wrong gateway/origin, expired entry or replay grants nothing.
5. A successful handoff creates an opaque, secure host-only website token bound server-side to the grant and gateway/origin. Portal, admin, gateway/site and inspection credentials remain separate.

The protocol must be specified in sufficient detail for adversarial tests before implementation. Do not reuse a transferable bearer URL as a browser identity. Never put access codes, long-lived session credentials or private keys in redirect queries, logs, QR exports, analytics or notification payloads. Completion tokens are brief one-use proofs and should be stripped from the URL after consumption, with no-store and no-referrer responses.

## Enforcement, revocation and outages

A gateway accepts only configured restricted destinations and verified public upstream addresses; no unauthenticated arbitrary CONNECT/forwarding endpoint is introduced. DNS mapping still points to the gateway for the whole timed session.

Each new request needs current authorization, using a tightly bounded and explicitly documented cache if necessary. Grant expiry is an absolute server deadline, not a browser timer. Revocation must invalidate any cache and terminate affected streams/WebSockets within a specified tested bound; use the current short polling/timeout behavior as a baseline, not a promise that a remote network has zero latency.

When authorization is unreachable or credentials are revoked, no new access is granted and ongoing affected streams fail closed within the documented check/timeout bound. Never fall back to unrestricted forwarding or remove DNS mappings as an outage workaround. Clock synchronization, latency and remote availability become explicit health checks. Gateway reboot must not turn stale local state into authorization.

## Public abuse and administration requirements

Before a public mode can be enabled:

- Separate visitor and management routing and allowed networks; keep private management endpoints private by default.
- Require MFA for explicitly public administration. Specify enrollment, recovery, one-use recovery codes, session invalidation and rate limits; a password-only public toggle is insufficient.
- Apply bounded attempts/queues for code redemption, sign-in, access requests and gateway enrollment. Cover distributed attempts rather than relying only on one source IP. Avoid code-validity oracles and notification spam.
- Use normal CSRF and browser/origin checks. A public source address or forwarded header must not confer an exemption. Distinguish administrative identity from visitor authorization.
- Bound control API messages, timeouts, connection concurrency and gateway permissions. Authenticate before accepting entry creation/introspection data.
- Keep generic push payloads. Document retention/access for visits, pages, request reasons and authorization metadata; expose neither browsing history nor secrets through public health/debug routes.
- Test proxy/header spoofing, SSRF, origin resolution, redirect validation, token replay, clock skew and offline transitions.

## Delivery sequence

1. Review this topology/protocol, define the exact message/state schema and enforcement bounds, and inventory existing local APIs that need purpose-specific remote replacements.
2. Implement gateway enrollment, credential rotation/revocation and authenticated authorization endpoints with protocol tests. Keep local mode and its backup/update behavior compatible.
3. Implement origin-bound browser handoff and remote grant introspection; verify expiry/revoke, reconnection and failure behavior end to end.
4. Add public visitor deployment, certificate lifecycle and proxy adapter, preserving the management network boundary. Add abuse limits before public exposure.
5. Add separately configured public administration only with MFA/recovery implemented and verified. Keep private admin as a supported option.
6. Exercise clean installs, upgrade/rollback, backup/restore and phone PWA/push on actual target infrastructure. Document exactly which topology is supported before adding its installer preset.

## Acceptance matrix

| Scenario | Required result |
| --- | --- |
| Valid code and original challenge | Intended browser obtains the intended timed grant through its enrolled gateway. |
| Copied entry/handoff, another browser, wrong gateway or wrong origin | No access; no reusable bearer proof. |
| Expired/revoked code/session | New requests denied and existing streams terminated within the specified bound. |
| Authorization outage, invalid certificate or revoked gateway credential | Fail closed; no general proxy behavior. |
| Private management through a public visitor host | Admin/API data inaccessible. |
| Public management | MFA and recovery/attempt/session controls enforced. |
| Spoofed forwarded identity or private-origin target | No network exemption, admin access or SSRF. |
| Normal trusted public TLS plus local restricted-site CA | Both chains verified independently; no private CA key leaves its owner. |
| Restore/reconfigure/upgrade | Credentials and origin bindings handled deliberately; stale state cannot reopen access. |
| Phone installation and push click | Correct management origin opens; private admin still requires LAN/VPN. |

These are implementation acceptance criteria, not test results. The current release only supplies the central configuration foundation and this proposal; public mode, remote mTLS/handoff, MFA and public deployment acceptance remain open under #26.
