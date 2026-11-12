# Change server settings from administration

Open **More → Server settings**, also available beside Account & security and Phone app settings. This page displays only public deployment settings, never configuration secrets or private keys. It affects this server only, not FortiGate, Pi-hole, host interfaces or enrolled remote nodes.

## Supported changes

- Assigned server/listener/DNS-target IPv4 (one local address in this topology).
- Private server canonical HTTPS origin and portal aliases.
- Client networks and effective management networks. Runtime management policy is shown, even if it differs from the original configuration file.
- Upstreams of an already installed built-in DNS resolver.

DNS/web component selection, service installation/removal, public/private or enrollment topology, paths, secrets and arbitrary commands are not accepted. Public authority origin/aliases are read-only here; use the supported root public-TLS workflow. Existing dedicated/shared-nginx ownership is preserved. Remote gateway administration remains on the authority; root reconfigure is available for private-node settings where the remote gateway redirects ordinary administration.

## Review and apply

1. Assign any new IPv4 address on the host before changing the listener. Include the server address in client networks so local HTTPS/DNS readiness works. Keep the current administrator address allowed by the proposed management/client networks.
2. Prepare external DNS, routing and Pi-hole synchronization first. A literal IPv4 portal origin must match the selected listener IP; a hostname origin needs the correct external/local DNS records.
3. Enter the requested settings and current administrator password, then choose **Validate and prepare review**. The unprivileged portal queues a fixed `server-check` action; it does not edit root files or run commands.
4. The serialized root maintenance worker validates normalized allowlisted fields, assigned IP, relevant new-address listeners and DNS upstream loops. A completed job shows the before/after changes and reconnection URL. Nothing has been applied. If there are no changes, no services are touched.
5. Within 15 minutes, enter the current password again, type `APPLY` and confirm. Confirmation contains only the preview ID. The worker independently rejects stale configuration, changed administrator policy, changed installed version, expired or inconsistent previews and unsupported request fields.
6. The root-only preview is consumed before application. Existing reconfigure staging validates certificate/key material and nginx syntax, retains a private rollback snapshot, restarts only managed services and checks local HTTPS (and installed DNS UDP/TCP) readiness. Management-network changes and origin/session invalidation commit in one database transaction after readiness. A failure restores managed configuration and rechecks the previous deployment. Interrupted jobs are never automatically replayed.

Progress/results survive portal restarts. Reconnect at the reviewed canonical address, sign in again when required, verify external DNS/Pi-hole settings and run the actual client/browser test. Local readiness does not prove a client's DNS/routing. Changing origin clears administrator sessions and phone push enrollment; visitors may need a fresh code if their browser identity changes. Management-network changes also require fresh administrator authentication. CA trust, password, code digests, consumed flags and code deadlines are retained. External clients and firewall rules are not changed automatically.

## Root recovery

If application fails with a successful rollback, the job states that the previous configuration and local readiness were restored. If rollback readiness also fails, root intervention is required; do not assume either address is ready. Inspect the managed service journals and private snapshots under `/var/lib/access-gate/reconfigure/rollback-*`. A root-only `deployment-profile.json` is retained in each snapshot, including the effective management networks from before the change, without passwords/private keys.

From `/opt/access-gate`, root can deliberately restore a selected profile through the same supported procedure:

```sh
python3 -m access_gate.reconfigure --profile /var/lib/access-gate/reconfigure/rollback-CHOSEN/deployment-profile.json --check
python3 -m access_gate.reconfigure --profile /var/lib/access-gate/reconfigure/rollback-CHOSEN/deployment-profile.json --yes
```

Choose the actual snapshot and verify its address remains assigned before applying. This restores deployment settings, not an old code database or revoked administrator sessions. Existing CLI install/resume/update and root reconfigure remain available. The same maintenance lock serializes updates, recovery and server-settings application; configuration/certificate/database files are never returned by the web job API.

## Validation scope

Automated fixtures exercise authentication/password/CSRF boundaries, private previews, version/policy/expiry/tamper checks, single use, worker locking/crash markers, staged certificate rollout, real SQLite policy transactions, readiness failure, rollback, CA/code preservation, shared-nginx ownership and DNS upstream updates. They use injected service commands rather than changing a real server's interfaces/systemd/nginx; actual deployment and device reconnection remain operator acceptance checks.
