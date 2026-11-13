# Installation

Use a dedicated Ubuntu 24.04 server with a stable IPv4 address (static or DHCP reservation). The initial installer configures a single private host. Explicit public-authority/remote-gateway deployment is configured afterward through the documented root workflow. Devices must reach this address and trust the installation's CA.

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

For an existing nginx/CloudPanel host, select `web_mode: "shared-nginx"` and follow [address-separated service combinations](DEPLOYMENTS.md). Default dedicated behavior is unchanged.

For a public authority or private remote gateway, first complete the normal private installation, then use the explicit root configuration/enrollment flow in [Public portal deployment](PUBLIC_PORTAL.md). Initial profiles do not silently expose public administration or replace trusted certificates.

## Planner navigation and reusable profiles (0.33)

The existing terminal wizard now validates each field and retains previous answers after mistakes. At a field enter `BACK` to return to the preceding choice, or `CANCEL` to stop before installation. The final review accepts `EDIT 1` through `EDIT 7` for the displayed fields, `EDIT aliases`, `BACK`, `RETRY`, `SAVE /root/reviewed-install.json`, and `INSTALL` or `CANCEL`. Editing a single field returns to review; a newly selected built-in resolver asks for missing upstreams. Password length/confirmation mistakes do not discard the plan. No password is collected until explicit installation confirmation and successful preflight.

`SAVE` exports only deployment settings to a new mode-0600 file, never passwords, password-file references, runtime secrets or a live configuration. It refuses existing files and symbolic links. A saved plan may need host conflicts corrected before reuse; preflight is always repeated. Choose a fresh output filename outside the Git checkout.

For planning only, without starting installation or collecting a password:

```bash
sudo python3 -m access_gate.installer /root/reviewed-install.json --plan-only
```

At review use `FINISH` instead of `INSTALL`. To review/edit a previously saved profile, or validate one unattended:

```bash
sudo python3 -m access_gate.installer /root/revised-install.json --edit-profile /root/reviewed-install.json --plan-only
sudo python3 -m access_gate.installer /root/validated-install.json --profile /root/reviewed-install.json --plan-only
sudo env ACCESS_GATE_INSTALL_CONFIG=/root/revised-install.json bash install.sh
```

The planner uses only the Python standard library, so it works before application dependencies are installed. A real install may use the existing private `admin_password_file` mechanism; plan-only mode does not read that password file. Existing installed hosts use update/resume or Server settings, not a new initial profile.

The launcher reports four phases: planning, packages/checkpoint, managed deployment and readiness. A saved interrupted initial installation directs a fresh `install` attempt to `resume.sh`. Resume retains its original checkpoint; completed installs retain their live configuration and identity and ignore initial-profile overrides. Missing configuration with an existing database/completion marker or orphaned certificates stops for recovery rather than regenerating credentials. None of this changes host addresses, VPN, firewall or external DNS.

Automated tests cover retry/back/edit, local conflict retry, reusable profile export, plan-only password handling, file/link protection and install/resume state selection. Package/systemd/nginx changes still require a real fresh-host acceptance test.

## First-use checklist (0.34)

After sign-in, open **Home → Open checklist** or **More → Getting started** (`/admin/setup`). Work through server health, client DNS, an enabled restricted test hostname, client certificate installation and a real client test. Use the existing management links to make configuration changes; the checklist itself never changes restrictions, credentials, DNS or certificates and never redeems a code.

Confirm a step only after performing the stated checks. Server-local health and published CA availability do not prove device DNS, certificate trust or actual access. Test on an affected device/browser without an administrator exclusion or active grant. On a public authority, configure and trust the private gateway instead of the authority certificate. An administrator can skip a step, mark it incomplete or hide/show the Home reminder. Skipped steps are not verified; the checklist remains available from More.

Progress and the selected hostname live in the application database and survive normal restart/update. Changes to deployment identity, resolver settings, selected restriction, CA fingerprint or relevant exclusions flag affected confirmed steps as **Needs review**. Software version changes alone do not invalidate progress. Explicit confirmations are administrator observations, not automated proof; unobserved changes on a client still require manual retesting. A restore resets acknowledgements because old client observations should not be treated as current acceptance.

Existing installations receive an optional reminder, with no forced setup redirect and no configuration overwrite. Local automated tests cover persistence, validation, review flags, skip/defer, CSRF/admin access and recovery reset. A physical Wi-Fi/VPN/client acceptance test remains an operator step.

The checklist migration adds schema 13 tables without changing existing codes or configuration. Encrypted recovery archives retain the existing strict matching-schema requirement: keep the matching application version for old archives and create a new backup after updating.
