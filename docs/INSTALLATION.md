# Installation

Use a dedicated Ubuntu 24.04 server with a stable IPv4 address (static or DHCP reservation). This release supports a single-host portal and gateway, not arbitrary public reverse proxies or remote authorization servers. Devices must reach this address and trust the installation's CA.

## Deployment profile

Create a root-readable JSON profile outside the source checkout. These values are examples:

```json
{
  "deployment_version": 1,
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

The profile contains deployment settings, not generated secrets. The installer generates credentials and a unique CA locally. Review the completion output and verify its CA fingerprint before trusting the certificate on devices. Configure external DNS using the exported /pihole.conf and permit clients to reach TCP 80/443. Select network ranges deliberately; do not allow all addresses for convenience.

## Existing installations

Run the usual update.sh. Pre-portability configurations are migrated to their actual legacy listener/target, retained portal URL/aliases and existing permitted networks. Existing administrator policy in the database continues to apply. Certificates, root CA, passwords, codes and database are retained. Update and resume do not take deployment settings from an installation profile.

Configuration is stored in /etc/access-gate/config.json. Do not hand-edit deployment fields on a working installation: generated configuration and portal certificates must be updated together. A safe reconfigure workflow is tracked separately in #23.

## Validation

After installation, check portal/gateway/nginx service status, verified HTTPS readiness, one restricted and one unrelated DNS lookup, and an actual client code/revoke flow. Local health checks do not prove all client paths work. A fresh-host installation still needs real system integration validation; unit tests do not exercise apt/systemd on the target server.
