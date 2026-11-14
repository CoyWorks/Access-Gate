# Access Gate documentation

**A little permission. A clear timer.**

Access Gate is a self-hosted CoyWorks project for agreed internet boundaries. Choose the restricted websites, decide how access is granted, and keep the timing in one place.

## Start here

1. [Install the server](INSTALLATION.md). Review its address, portal identity, DNS component and permitted networks.
2. Set up [built-in DNS](DNS.md) or [Pi-hole integration](PIHOLE.md), and choose an enabled restricted hostname for testing.
3. [Connect a client device](CLIENT_SETUP.md). Verify the public CA fingerprint before trusting it.
4. Open **More → Getting started** in administration. Confirm the server, DNS and client checks you have actually performed; skipped steps remain unverified.
5. Create a small test batch, open the restricted website in a browser without an active session or exclusion, and check activation plus expiry or revocation. See [gateway acceptance checks](GATEWAY.md).

Addresses in the guides are examples. Use the values reviewed for your own installation. A normal update preserves existing settings; a full reset creates a new identity and CA.

## Everyday control

| I want to… | Guide |
| --- | --- |
| Find the everyday actions | [Administration interface](INTERFACE.md) |
| Approve or deny a request; inspect history or clean up batches | [Requests and operations](OPERATIONS.md) |
| Manage access settings, extend/end sessions or recover management access | [Administration](ADMINISTRATION.md) |
| Allow an exception | [Exclusions and administrator login](EXCLUSIONS.md) |
| Approve requests from my phone | [Phone app and notifications](PHONE_APP.md) |
| Hand out printable codes | [Code cards, PDF and QR](EXPORTS.md) |
| Generate recurring batches | [Code schedules](SCHEDULES.md) |
| Review changes to imported domain lists | [Blocklist subscriptions](SUBSCRIPTIONS.md) |

## Keep it running

- [Updates](UPDATES.md): review a release and preserve existing state.
- [Backup and restore](RECOVERY.md): protect configuration, database and CA together; understand restore invalidation before applying an archive.
- [Server settings](SERVER_SETTINGS.md): review supported address, identity and network changes.
- [Client diagnostics](CLIENT_DIAGNOSTICS.md): investigate DNS, TCP, TLS and portal routing from the affected client.
- [Visitor failure pages](VISITOR_FAILURES.md): understand recovery links and failures that occur before HTTP or after streaming starts.
- [Support reports](SUPPORT.md): preview an allowlisted server snapshot before downloading or sharing it.
- [Gateway performance](PERFORMANCE.md): inspect aggregate timings and certificate-cache behavior.

## Choose your deployment

- [Deployment modes and service combinations](DEPLOYMENTS.md): dedicated servers, shared nginx and port ownership.
- [Public portal and private gateways](PUBLIC_PORTAL.md): explicit opt-in deployment with separate gateway enrollment and trust.
- [HTTPS gateway](GATEWAY.md): certificate issuance, forwarding, browser authorization and enforcement.

## Know the boundaries

An access code or approved request grants a timed **browser session covering all currently restricted websites**. It does not create a user/device account or a separate permission for just the requested domain. Per-domain access profiles remain planned.

The clock keeps running when a browser closes. Changing browsers or deleting cookies does not recover a used code. Administrator logins and configured IP exclusions bypass the code requirement, so test enforcement with an affected, non-excluded browser.

Make the rules and any visit logging clear to the people using the devices. Domain history is enabled by default; page-path logging is optional, and retention is configurable. See [history settings](OPERATIONS.md) before enabling additional detail.

DNS, routing, certificate trust and client restrictions need to work together. Some apps use their own trust rules; browsers may use alternate DNS or network paths. A healthy server check is not proof of device enforcement. Verify the actual Wi-Fi/VPN/client path before relying on it.

[Project README](../README.md)
