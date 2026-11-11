# Installation

Use a dedicated Ubuntu 24.04 server with a stable IPv4 address (static or DHCP reservation). This release supports a single-host portal and gateway, not arbitrary public reverse proxies or remote authorization servers. Devices must reach this address and trust the installation's CA.

## Interactive installation

Run `sudo bash install.sh` from the cloned source. Choose existing Pi-hole, external DNS or built-in DNS (or customize that integration), select the detected server address, enter the portal hostname/IP and client/management CIDRs, review the plan and type INSTALL. Then choose or generate the administrator password. Built-in DNS is also available as its own preset or custom component choice. Enter one to three upstream DNS IPv4 addresses when selecting it.

Installation preflight checks local addresses and TCP 80/443/8088/8089 before apt or service changes. Initial deployment choices are checkpointed privately under /var/lib/access-gate/installation. Use `sudo bash resume.sh` after correcting an interrupted installation; it reuses the checkpoint rather than asking for another environment. Existing complete installations use update.sh. Service choices persist across resume/update.

## Deployment profile

Create a root-readable JSON profile outside the source checkout. These values are examples:

```json
{
  "deployment_version": 1,
  "dns_mode": "external-pihole",
  "server_ipv4": "192.168.10.20",
  "listen_ipv4": "192.168.10.20",
  "dns_target_ipv4": "192.168.10.20",
  "portal_url": "https://access.example.net",
  "portal_aliases": [],
  "client_networks": ["192.168.10.0/24", "127.0.0.1/32", "::1/128"],
  "admin_networks": ["192.168.10.0/24"]
}
```

The three IPv4 settings must currently match an address assigned to this server. The installer never changes network addressing. The portal may use an IP URL instead of a hostname. For a hostname, configure local DNS to resolve it to the server; it need not be a publicly registered domain. Keep this canonical name out of your restricted-domain list. Aliases are certificate/listener names; browser administration uses the canonical origin.

```bash
sudo env ACCESS_GATE_INSTALL_CONFIG=/root/access-gate-install.json bash install.sh
```

For unattended installation, optionally add `admin_password_file` pointing to a root-owned regular mode-0600 file containing an 8–256 character password. Otherwise a password is generated. Never pass passwords in command-line arguments. The input password is not copied into the reusable profile or installed configuration; a private temporary checkpoint is removed once credentials are stored.

The profile contains deployment settings, not generated secrets. The installer generates credentials and a unique CA locally. Review the completion output and verify its CA fingerprint before trusting the certificate on devices. Configure external DNS using the exported /pihole.conf and permit clients to reach TCP 80/443. Select network ranges deliberately; do not allow all addresses for convenience.

## Existing installations

Run the usual update.sh. Pre-portability configurations are migrated to their actual legacy listener/target, retained portal URL/aliases and existing permitted networks. Existing administrator policy in the database continues to apply. Certificates, root CA, passwords, codes and database are retained. Update and resume do not take deployment settings from an installation profile.

Configuration is stored in /etc/access-gate/config.json. Do not hand-edit deployment fields on a working installation: generated configuration and portal certificates must be updated together. Use the safe reconfigure workflow below.

## Validation

After installation, check portal/gateway/nginx service status, verified HTTPS readiness, one restricted and one unrelated DNS lookup, and an actual client code/revoke flow. Local health checks do not prove all client paths work. A fresh-host installation still needs real system integration validation; unit tests do not exercise apt/systemd on the target server.

## Reconfigure an installed server

From the installed application directory:

```bash
cd /opt/access-gate
sudo python3 -m access_gate.reconfigure
```

Review the changes and type RECONFIGURE. Assign a new server IP in Ubuntu first; this command does not modify host networking. Alternatively supply `--profile /root/deployment-changes.json` containing only changed deployment fields. `--check` validates/shows the plan without applying it; `--yes` explicitly confirms unattended changes. Component selection is not a deployment-address change.

The command uses the shared maintenance lock, privately stages certificate/gateway/nginx configuration, tests nginx syntax, backs up managed files and verifies HTTPS readiness after restart. On activation failure it restores previous files and verifies rollback readiness; if that also fails, use the printed root-only rollback directory and inspect systemd logs. Existing CA and code records are preserved. Root rollback copies contain private keys and are retained for deliberate operator cleanup.

A changed portal origin clears admin logins and push subscriptions. Sign in again and reinstall/re-enroll the phone app as necessary. Visitor cookies belong to an origin; users who lose their portal browser identity may need a fresh code. IP changes require external DNS, Pi-hole sync URL/target and firewall changes; those are never applied remotely by this command. A successful local readiness check does not prove external clients have been updated.

For the optional DNS component, see [Built-in DNS](DNS.md). In unattended profiles set `dns_mode` to `builtin` and supply `dns_upstreams`, for example `["1.1.1.1", "9.9.9.9"]`. External modes install no DNS listener or extra DNS package.
