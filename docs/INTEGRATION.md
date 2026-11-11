# External redirect and authorization integration

Access Gate 0.5 includes the built-in HTTPS gateway described in [GATEWAY.md](GATEWAY.md). It consumes the private authorization API below, issues matching site certificates under the retained CA and enforces restricted-domain requests/streams. **DNS domains** manages the selected policy and Pi-hole export. External DNS/routing and device trust still need their matching configuration; the app does not push appliance changes automatically.

## Redirect versus authorization

A redirect to `https://192.168.10.20/` gives the user a working code form and temporary browser session. It does not itself change a firewall rule, change a DNS answer back to the original site, or forward that site's content.

For website access, the client-facing gateway must check the portal's authorization and enforce its deadline. With DNS-assisted proxying, selected domains remain pointed at the gateway throughout the session. The gateway fetches the real upstream using an independent resolver. Four-hour upstream DNS TTLs then do not determine authorization expiry.

Pi-hole only rewrites DNS addresses. The browser still expects HTTPS for the original site, so a client-facing HTTPS gateway needs a valid certificate for that original hostname, trusted on the intended devices. The portal certificate alone does not provide this. Certificate provisioning, ECH/HTTP3/IPv6 behavior, pinned-app support and direct-DNS/alternate-path bypass prevention belong to that external configuration.

A FortiGate feature that only sends an HTTP redirect cannot automatically consume this API. Its authentication/unlock adapter must be configured and tested. The portal does not pretend that its cookie creates a FortiGate authenticated firewall session.

## Browser identity

The portal automatically issues `__Host-accessgate-browser`, a random Secure/HttpOnly/SameSite=Lax host-only cookie. Its keyed digest identifies the browser grant. No account or IP mapping is required. The same browser retains the absolute deadline across Wi-Fi/VPN address changes. Another browser receiving the same IP has no access.

Browser cookies cannot be shared directly across unrelated website domains. A client-facing reverse proxy can use the supplied origin-bound handoff: it gets a separate, opaque token for each gated hostname, backed by the same code grant. Neither code values nor the portal's raw browser token are passed to upstream websites.

## Private API boundary

Gunicorn listens on `127.0.0.1:8088`. Every `/internal/` endpoint requires loopback source **and** the `X-Gate-Key` header matching the retained `acl_token`. The installed HTTPS gateway returns 404 for private portal paths and removes client-supplied private headers. Keep these endpoints private.

The integration key is stored in `/etc/access-gate/acl-token` and configuration. Supply it securely to a trusted gateway; never put it in frontend JavaScript or commit it to a repository. Remote firewall/DNS appliances need a dedicated, restricted adapter; this release does not expose an unauthenticated remote API.

The external gateway, which owns the selected domain configuration, supplies the HTTPS origin. Only normalized hostname origins are accepted: no IP literal, credentials, non-443 port, path, query, fragment, `.local` or `.internal` target. The public portal never trusts arbitrary `return=` URLs. A valid entry issued by the private gateway is required for automatic return.

The built-in gateway additionally uses `GET /internal/gateway/domain?host=HOSTNAME` to query the current managed DNS-domain policy and `GET /internal/gateway/check` for authorization that requires both a managed hostname and an active origin-bound site token. These require the same private loopback/key boundary. The generic `/internal/check` remains available for alternative adapters with their own domain selection; it does not implicitly apply the managed DNS policy.

## Optional Nginx browser adapter

This is an alternative/manual adapter retained from 0.4, not the installed 0.5 gateway. Do not enable it alongside the built-in gateway on the same address/443 listener. It does not generate dynamic site certificates or enforce existing-stream expiry.

[examples/nginx-gateway.conf.example](../examples/nginx-gateway.conf.example) shows a client-facing gateway for **one reviewed domain**. It is not installed by the portal updater. Replace the hostname, external-site certificate/key paths and key placeholder; protect the resulting file and run `nginx -t` before reload. Enable Nginx's `http_auth_request` module if it is not present.

For a Pi-hole deployment, that selected site's DNS record can point to the gateway IP. Its HTTPS certificate must already cover that hostname and be trusted by the test device. The example resolves the real origin through independent external DNS, verifies its public upstream certificate and never uses Pi-hole's rewritten answer for that fetch. Review selected upstreams and keep them outside private/loopback/link-local destinations; do not turn the example into an unrestricted public proxy.

The flow is:

1. A site request without its site cookie fails the private authorization check with 401.
2. The gateway proxies the login response from `/internal/start`. Access Gate creates a five-minute entry, returns a 302 to the canonical portal, and sets an opaque challenge cookie on the gated origin.
3. The user enters a code. If the browser already has active access, no additional code is consumed. Access Gate redirects to the gated origin's fixed `/__access_gate/complete` callback with a one-time ticket.
4. The gateway proxies that callback to `/internal/finish`, forwarding the target-origin challenge cookie. Access Gate verifies the ticket, nonce, origin and active grant atomically. It returns a host-only site cookie, deletes the challenge cookie and redirects to the site's root.
5. Every subsequent site request checks `/internal/check` with that site's cookie and the trusted `X-Gate-Origin` header. The example forwards only ordinary website cookies to the real origin, using the filtered cookie header from the check. It strips the gateway key from upstream traffic.

Tickets expire within 60 seconds, are origin/challenge-bound and can be consumed once. The callback immediately redirects to a clean root URL; it never replays a login form or forwards a private path/query through the portal. Disable access logging for the callback, send `Referrer-Policy: no-referrer` and keep authorization/control responses uncached. The example has access logging disabled and the backend supplies no-store/no-referrer headers. The example does not enable WebSocket upgrades or promise pinned/native-app compatibility.

The site cookie can outlive a grant; server checks, not cookie expiration, determine access. This lets an administrator extension update the existing persisted deadline. An expired/revoked code never becomes reusable.

## JSON API for other adapters

All requests below require the private key and `Content-Type: application/json`. No key, code or bearer token belongs in an ordinary logged query string.

### Create an entry

`POST /internal/entry`

```json
{"origin":"https://example.org"}
```

Response: `login_url`, a random `nonce`, and `expires_in: 300`. The adapter stores the nonce in a Secure/HttpOnly/SameSite=Lax **host-only** challenge cookie on the gated site, then navigates to `login_url`. The portal redirects back to the fixed callback after activation.

### Redeem the one-time handoff

`POST /internal/handoff`

```json
{"ticket":"ONE_TIME_TICKET","nonce":"ORIGINAL_SITE_CHALLENGE","origin":"https://example.org"}
```

Response: opaque site `token`, current `expires` and `session_id`. Wrong origin/challenge, replay, expired entry/ticket or inactive grant returns an error without creating access. Store the returned token as a Secure/HttpOnly host-only site cookie and remove all Access Gate cookies from requests forwarded to the real website.

### Check access

`POST /internal/check`

```json
{"token":"SITE_TOKEN","origin":"https://example.org"}
```

An authorized response is HTTP 200 with `active: true`, `expires` and `session_id`. Unauthorized, expired, revoked or wrong-origin access returns HTTP 401. GET is supported for a trusted same-host proxy using `__Host-accessgate-site` plus `X-Gate-Origin`; an old `ip=` query alone always fails.

Do not authorize solely from an IP, session identifier, boolean from an old response or client-supplied deadline. Check the persisted grant for every new protected request. Do not cache positive results beyond its deadline; the supplied example does not enable authorization caching.

## Deadline and connection enforcement

The portal and API deny new checks at the exact server deadline. Extensions modify that stored deadline and revocation is reflected immediately in subsequent checks. The browser countdown reconciles with the server; closing a tab does not pause access.

The **gateway** owns open connections. The installed 0.5 gateway revalidates streams/WebSockets every 0.5 seconds and aborts the affected transport on expiry, revocation, policy removal or API failure; extensions are read from the current state. The practical latency and buffering limits are described in [GATEWAY.md](GATEWAY.md). An ordinary Nginx `auth_request` alternative alone does not recheck already-open streams. The portal has no privileged socket-killing worker. Already downloaded content cannot be removed remotely.

The optional Python `expire(store, close, now)` maintenance hook calls `close(session_id)` transactionally before deleting expired/revoked records. It is not a daemon, does not execute operating-system commands and does not control a remote firewall or proxy. Prefer per-session connection ownership over IP-wide socket destruction.

## Acceptance before rollout

- Verify the actual gateway's HTTPS certificate and original upstream certificate validation.
- No code: normal browser navigation reaches the canonical portal without a manual browser proxy setting.
- A valid code returns to the site. Invalid/consumed/revoked codes do not unlock it.
- Another browser at the same IP does not inherit access; Wi-Fi/VPN switching does not reset the original browser's timer.
- A second gated domain can use the same active browser grant through a new origin-bound handoff.
- Replay or a callback copied to a browser without the challenge cookie fails.
- Check expiry, administrator extension and revocation for new requests **and actual open streams**.
- Verify unrestricted sites, DNS cache behavior, IPv4/IPv6, HTTP3, ECH and pinned-app limitations on the selected devices.

The backend redirects/cookies/API are tested through Flask HTTP flows, including nonce/origin binding and concurrency. The built-in gateway also has real local TLS/origin/stream/WebSocket tests. Actual service deployment, firewall/Pi-hole/device paths and the manual Nginx alternative still require target-network validation; the source release is not a claim of remote activation on srvaccess01.

References: [Nginx auth_request](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html), [Nginx proxy module](https://nginx.org/en/docs/http/ngx_http_proxy_module.html), [host-only cookies and cookie prefixes](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie).

## Built-in gateway exclusions (0.7)

The built-in gateway supplies the real peer address as `X-Gate-Client-IP` on its authenticated GET `/internal/gateway/check` requests. It sets `X-Gate-Activity: 1` only for incoming website requests; passive stream checks omit it. The backend checks managed-host scope before applying an IP exception and checks live admin proofs before code grants. It accepts no ordinary client `ip=` assertion. External adapters must preserve this trusted boundary rather than forward browser-supplied headers. Admin handoffs use the same entry/challenge callback contract but a separate token namespace/storage from portal login credentials. See [EXCLUSIONS.md](EXCLUSIONS.md).
