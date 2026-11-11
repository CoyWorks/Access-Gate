# Access exclusions and portal login

Version 0.7 adds two independent ways to bypass the code requirement for managed restricted websites:

1. A valid administrator login in that browser.
2. The actual client address matching a configured exclusion CIDR.

Other visitors keep the existing single-use-code flow. An exclusion bypasses only Access Gate authorization. DNS mappings, device CA trust, the HTTPS proxy and existing Pi-hole advertisement/malware blocking still apply. No extra DNS server or remote Pi-hole/FortiGate change is installed.

## Portal login

The normal portal now has **Sign in**, using the existing administrator password. It preserves a restricted-site entry and automatically returns to the website after authentication through the existing continuation/callback flow. Direct portal login returns to the portal. Management-network rules still apply to the login endpoint and all administration routes; an IP exclusion does not grant administrator privileges.

A login expires after **seven days without use**. Opening/using portal or administration pages and making authorized proxied website HTTP requests renews its server deadline to seven days from that activity. Automatic Access Gate status/API polls, static/feed requests and the gateway's passive stream watcher validate the login without renewing it. Website background HTTP requests count as website activity; Access Gate does not attempt to infer human presence. An active stream alone does not keep the login alive forever.

The portal uses a Secure, HttpOnly, SameSite=Lax host-only opaque login cookie bound to the existing browser identity. A copied Flask admin flag alone is not authority. The lookup cookie may remain stored for up to a year and is refreshed on portal use, but its **server-side authorization still expires after seven idle days**. This allows site activity to renew the same server login even when the portal's separate seven-day Flask cookie expires; reopening the portal restores only a currently valid, version-matching server login. Password/network/exclusion policy changes invalidate existing administrator login versions across workers.

Admin portal credentials never travel to visited websites. Each restricted origin gets a separate opaque site proof through a nonce/origin-bound one-use ticket. That proof can authorize website access only; it cannot log in to administration. Only proof hashes are persisted. The gateway strips reserved Access Gate cookies/headers from upstream requests and blocks upstream attempts to set those reserved cookies.

**Sign out** is available on the normal portal, including when the current network may not manage the app. Its CSRF-protected POST revokes the server login and removes its cookie; replaying an old cookie cannot restore that login. All site proofs for that login immediately fail the live checks. Other administrator logins on other browsers are independent. A new login in the same browser revokes its prior login/proofs.

Code grants are not consumed, paused, extended or reset by a login/exclusion. Their original deadline keeps running. Signing out can therefore leave access available if the address is IP-excluded or a previously activated code grant is still valid.

## IP/network exclusions

Open **Settings → Access exclusions**. Enter one CIDR per line, for example:

```text
192.168.20.20/32
192.168.30.0/24
```

A /32 excludes one IPv4 address; /24 excludes the whole aligned network. IPv6 CIDRs are parsed as well, where the deployment actually receives IPv6 clients. Up to 64 entries are supported. Duplicates are removed; invalid or misaligned networks such as 192.168.20.20/24 are rejected rather than silently broadening the exception. Leave the field empty to disable IP exclusions. Saving requires the current administrator password, valid CSRF and a fresh settings version, and signs out existing admin logins like other security-policy changes.

These are **access exclusions**, not management networks. They do not change which addresses can reach the portal/gateway, which domains are managed, or who can open administration. Only configured client networks and managed HTTPS hostnames remain eligible.

Rules use the gateway's real peer address (or its existing trusted loopback HTTP proxy boundary). Client-supplied X-Real-IP, X-Forwarded-For and X-Gate headers cannot choose an excluded address. The private gateway API receives the actual address from the authenticated built-in gateway. The old public/private ip= query parameter does not grant access.

Check the address that actually reaches the gateway: VPN-assigned addresses can change, and NAT can make several devices share one visible address. Excluding a shared address exempts every client behind that address. A reserved local /32 does not automatically identify the same device over a VPN using a different address.

## Live enforcement

Each new request checks current domain policy plus IP exemption, live admin site proof or the existing code grant. Stream/WebSocket checks re-read those same conditions. Removing an IP exception, signing out, changing security policy or reaching the admin idle deadline closes affected protected connections on the next live check, unless another valid authorization still applies. The normal 0.5-second polling target, two-second local authorization timeout and scheduling/network buffering limits remain as documented in [GATEWAY.md](GATEWAY.md). Already downloaded content cannot be withdrawn.

The Sessions page continues to list code grants. Administrator login state and the current exclusion appear on the portal; they are not represented as fake batches or unlimited access codes.

## Upgrade and recovery

Run the normal updater. The transactional schema-6 migration adds exclusion/login/proof state, preserves existing management policy, codes, grants, domains and CA, and starts with an empty IP-exclusion list. Existing v0.6 Flask-only admin cookies require a fresh login once. No reset or new device CA is needed.

The existing local password and management-network recovery commands still work and invalidate old admin logins through the shared authentication version. See [ADMINISTRATION.md](ADMINISTRATION.md). Recovery preserves the exclusion list; root can recover management access and then edit exclusions normally.

## Validation

The 0.7 source passes 236 Python tests, including real local HTTPS admin login/return, logout and idle-expiry stream closure, trusted-peer IP exclusion/removal and spoofed-header rejection. Store/web tests cover seven-day renewal, passive-check non-renewal, cookie replay, missing Flask-cookie restoration, origin/nonce/one-use proof binding, policy changes, CIDR boundaries, code preservation and migration. Dependency-free Node UI checks cover polling/stale states and exclusion countdown messages; source syntax checks pass. Installation on srvaccess01 and actual VPN/NAT/device addresses still need verification after updating.
