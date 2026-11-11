# Public portal and private gateways

Available as an explicit opt-in from 0.21.0. An ordinary installation stays private and uses local authorization. These commands configure real services; they do not publish DNS records or change router/cloud firewall rules.

## Deployment model

| Component | Placement | Responsibility |
| --- | --- | --- |
| Authority/portal | Server with a dedicated public HTTPS endpoint | Codes, requests, administrator sessions and current authorization state |
| Administration | Private LAN/VPN by default; optional public access with MFA | Code generation, approvals and audit |
| Private gateway | Client-reachable LAN/VPN server | Restricted-site TLS and verified origin forwarding; its inspection CA stays local |
| DNS | Private gateway's built-in DNS or external Pi-hole | Restricted names point to that private gateway, not the authority |

The authority currently uses the normal Access Gate installation, including its gateway frontend. On the authority this frontend supplies ordinary portal HTTPS and the mTLS control boundary. On a private node the local application/data remain installed for updates and recovery, but codes and requests are handled by the authority while remote mode is active.

Public visitors need only the portal's normally trusted TLS certificate. Devices still need to trust their **private gateway's** inspection CA to use restricted websites. Public portal TLS cannot replace that CA. Clients must still reach the private gateway through LAN/VPN; a public portal does not bypass that network requirement.

## 1. Install the authority

Install on Ubuntu 24.04 using the normal wizard/profile. Choose a public DNS hostname as the canonical portal URL, such as https://access.example.net. The local server/listener address can be private behind a source-preserving port forward. Keep the client/management networks deliberately restricted, including the server address for local verification.

Point public DNS at the authority's endpoint. Permit TCP 443 and, for HTTP-01 issuance, TCP 80. Do not publish an unusable AAAA record: the supplied listener is IPv4-bound. Use direct TLS to Access Gate. TLS-terminating CDNs/reverse proxies and TCP proxies that hide source identity are not supported for this endpoint; the control API needs the actual verified client certificate and management needs the real peer address. An ordinary DNAT mapping must preserve source identity. Separate-address shared-nginx coexistence is supported as described in DEPLOYMENTS.md; this is not SNI multiplexing of several products behind one public socket.

From the installed application directory:

```bash
cd /opt/access-gate
sudo python3 -m access_gate.public_deploy acme --email you@example.net --agree-tos
```

Review your ACME provider's terms before supplying --agree-tos. This command enables only the HTTP challenge path, installs certbot and requests a webroot certificate. Other private HTTP routes stay restricted until public mode is enabled. The hostname must already resolve correctly and port 80 must reach this nginx listener. If HTTP-01 is unavailable, obtain a certificate using your existing DNS-01/web-host tooling instead.

Enable public HTTPS using the resulting full chain and protected, unencrypted private key:

```bash
sudo python3 -m access_gate.public_deploy enable \
  --cert /etc/letsencrypt/live/access-gate/fullchain.pem \
  --key /etc/letsencrypt/live/access-gate/privkey.pem
```

The key must be root-owned, not group-writable and inaccessible to other users (root/group read is supported). Certificate hostname, validity, public chain and key match are checked before activation. Use the canonical DNS name afterward; a public certificate usually does not cover the private server IP.

Public mode permits visitor code entry and requests over HTTPS. Administration remains restricted to private peer addresses **and** its configured management networks. DNS feeds remain client-network restricted. The HTTP portal route redirects public visitors to HTTPS; only the explicit ACME path is publicly served as files.

## 2. Optional public administration and MFA

Skip this section to keep administration on LAN/VPN.

```bash
sudo python3 -m access_gate.public_deploy mfa-setup
```

Add the printed secret/otpauth URI to an authenticator, confirm a current code and save the ten recovery codes privately. Setup signs out existing administrator sessions and push subscriptions. The seed is encrypted in the database; recovery codes are hashed and one-use. TOTP uses 30-second steps, a one-step clock window and replay prevention. Wait for a new authenticator code after confirming enrollment.

Then explicitly enable public administration and the intended management networks:

```bash
sudo python3 -m access_gate.public_deploy enable \
  --cert /etc/letsencrypt/live/access-gate/fullchain.pem \
  --key /etc/letsencrypt/live/access-gate/privkey.pem \
  --admin-public --admin-networks '0.0.0.0/0,::/0'
```

Every new administrator login now requires password plus authenticator/recovery code. Factor verification is limited globally to five password-valid attempts per 15 minutes, in addition to the source sign-in limits; invalid passwords cannot exhaust that factor budget. Public administration cannot be enabled through this command without enrolled MFA. A broad management CIDR alone does not enable public administration. Existing sessions are invalidated before activation. Existing seven-idle-day session renewal remains in effect after MFA sign-in. Sign in again and re-enable phone push when necessary; notification content remains generic.

To replace a lost authenticator, root can run mfa-setup again. This replaces the seed/recovery codes and invalidates old admin sessions. Keep root recovery access independent of the portal.

## 3. Enroll a private gateway

On the authority:

```bash
sudo python3 -m access_gate.public_deploy enroll \
  --name 'Home gateway' --output /root/home-gateway.json
sudo python3 -m access_gate.public_deploy list
```

The mode-0600 bundle contains a per-gateway private client certificate and API credential. Transfer it securely to the intended private server. It is not a public download or a browser/device certificate. Enrollment uses a separate authority from all inspection CAs; no private gateway inspection key is uploaded to the portal.

On the private server, install Access Gate normally first, with its own private address and local portal identity. Choose built-in DNS or external Pi-hole as appropriate. Keep the private gateway's CA trusted on its client devices. Then:

```bash
cd /opt/access-gate
sudo python3 -m access_gate.public_deploy activate /root/home-gateway.json
```

Activation verifies public server TLS, authenticates with mTLS and the separate gateway key, and consumes the one-use activation. It retains the private inspection CA and local recovery data, switches website authorization to the authority, performs readiness checks and starts remote domain synchronization. Remove the transfer copies after successful activation. If local activation fails after the authority accepts it, the original node's private activation record supports retry; another node cannot consume the same activation. An ambiguous network failure may require root to revoke/re-enroll instead of retrying blindly.

Never activate an existing authority as its own private gateway. This command rejects that role combination.

## 4. Configure private DNS

Manage domains in the authority's admin portal. An unprivileged service on each private node fetches the enabled exact/subdomain rules over authenticated HTTPS every 30 seconds. It validates the complete snapshot before replacing the local DNS table. Built-in DNS applies that table automatically; an external Pi-hole uses the **private node's** normal /pihole.conf feed and private target IP. Do not point client DNS at the authority's feed unless that authority is itself the intended website gateway.

Keep the public authority hostname outside restricted rules, including wildcard parents. A private node rejects a snapshot that would redirect its authority connection and retains the previous valid snapshot. Unavailable/invalid synchronization never wipes the old list. Stale synchronization is reported in local health/journal output.

```bash
sudo python3 -m access_gate.remote_domains --once
systemctl status access-gate-remote-domains
```

A new restriction still depends on DNS synchronization and client caches. These cannot revoke an already cached public answer. Website authorization, expiry and revocation use live authority checks independently of the 30-second DNS interval.

## Browser proof and access behavior

The private gateway sets a secure, host-only challenge cookie on the restricted origin. The public portal redeems a code or approved request for its own browser session, then issues a brief one-use handoff bound to the entry, original challenge, exact website origin and enrolled gateway. The private gateway validates/consumes it before setting its website token. Portal and website cookies are never assumed to cross domains. Gateway tokens and admin website proofs are isolated per gateway.

Remote authorization requires a current active grant. Checks are not cached; streams/WebSockets are rechecked every 0.5 seconds with a two-second control-request timeout. Expiry, revoked credentials or an unavailable authority deny new requests and interrupt affected streams within that poll/timeout bound. A remote failure does not turn the node into an unrestricted proxy. Real networks can cause additional visible reconnect/retry time.

Public visitor IPs are not treated as network exclusions. Remote nodes use code/admin browser proofs rather than accepting an IP-exclusion claim through the control API. Local private installations retain their existing CIDR exclusions; an administrator's browser bypass still works through the gateway-bound handoff after its normal sign-in/MFA policy.

## Rotation, renewal and recovery

Gateway certificates last up to 90 days. Before expiry, enroll a new bundle, activate it on the same private node, verify access, then revoke the old ID:

```bash
sudo python3 -m access_gate.public_deploy revoke OLD_GATEWAY_ID
```

Revocation is checked on every control request, including active-stream checks. Old site tokens cannot be reused under a new gateway ID; a still-valid portal browser grant can complete a fresh handoff without consuming another code. At most 32 enabled gateways are supported. Inspect expiry with list and explicitly revoke expired/retired entries. The enrollment CA lasts two years; replacing that CA requires a planned re-enrollment of gateways and a frontend reload/restart, not reuse of old credentials.

Your ACME/web-host tool owns certificate issuance and renewal. The Access Gate public TLS timer checks the configured source paths every 12 hours and imports a changed, valid chain/key. Live symlink paths are retained so certbot's new archive versions are picked up. The gateway reloads its TLS context with SIGHUP, then verifies readiness and the expected live certificate fingerprint; failed imports restore the old pair. No inspection CA is replaced.

```bash
systemctl status certbot.timer access-gate-public-tls.timer
sudo certbot renew --dry-run
sudo python3 -m access_gate.public_deploy renew
```

Encrypted backups include the enrollment CA and remote credential files when present. Restoring an authority revokes its gateway registrations. Restore clears MFA/recovery state and disables public administration and remote-node mode; private-node credential/activation files are not reinstalled. For a private-node restore, also revoke its retired ID on the separate authority: a local restore cannot automatically revoke credentials in another server’s database. It does not silently resurrect old credentials. Public visitor TLS can remain enabled using the restored verified certificate; restore normal root access first, reconfigure source paths if needed, then re-enroll MFA/gateways. External ACME account files/source directories are not included in Access Gate backups.

To deliberately return a private gateway to its retained local authorization:

```bash
sudo python3 -m access_gate.public_deploy disconnect
```

Revoke its former credential on the authority. Local codes/data were retained; they become authoritative again in local mode. To disable a public authority, run public_deploy disable. This revokes gateway credentials, restores local-CA portal TLS/private network behavior and stops renewal imports. Clients using that local portal must trust its retained CA.

## Bounds and supported validation

Public POSTs have a global budget of 300/minute plus 20/minute per source; normal sign-in/code limits remain in force. Authenticated peers have a 6000-request/minute budget and 120 new entries/minute. The frontend caps active requests at 128 and bounds body size/time. Large authenticated recovery uploads remain separately bounded. Only fixed purpose-specific gateway API routes are relayed with verified certificate identity; /internal endpoints remain unreachable through HTTPS. Payloads, visit paths and push notifications keep their existing privacy limits. This is a small, single-operator deployment, not a multi-tenant public SaaS or a high-volume proxy service.

Automated tests use actual independent local HTTPS/mTLS nodes for code and approved-request handoffs, challenge/origin/gateway isolation, verified origin forwarding, missing/forged credentials, revoked credentials and authority outages. Tests also cover TOTP/recovery, TLS chain/name checks and private DNS mirroring. They use test CAs; production enablement requires system-trusted public TLS. No live ACME issuance, fresh Ubuntu/CloudPanel installation, real Internet exposure or remote phone acceptance was executed in this workspace.

Before publishing an installation, run the documented commands on target hosts, verify private-admin denial from an outside network, test MFA/push and code/request/revoke/expiry from a client behind the private gateway, interrupt authority connectivity, and exercise update/reboot/restore. Follow [deployment ownership](DEPLOYMENTS.md) and [gateway limitations](GATEWAY.md).

Protocol references: [Python TLS client-certificate verification](https://docs.python.org/3/library/ssl.html) and [RFC 6238 TOTP](https://www.rfc-editor.org/rfc/rfc6238.html).
