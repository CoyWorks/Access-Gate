# Standalone portal activation

1. Run `bash /root/Access-Gate/update.sh`. No reset, VPN reader, user registration or domain registration is required.
2. Verify `systemctl is-active access-gate nginx` and a trusted HTTPS HTTP 200 response from `https://10.40.22.5/`.
3. Sign in at `/admin` with the existing administrator password. Create a batch and save the one-time code export.
4. Open the portal in a normal browser from Wi-Fi or VPN. Enter one unused code. The page shows its persisted deadline/countdown.
5. A different browser on the same address must still ask for a code. The original browser keeps its deadline when moving between the local and VPN networks.
6. Test an administrator extension and revocation through `/status`.
7. Choose the external website gateway and configure it according to [INTEGRATION.md](INTEGRATION.md). A portal redirect alone does not apply website access or solve external-site HTTPS certificates.
8. Optionally maintain the selected Pi-hole domains under **DNS domains**. Leave **Domain + all subdomains** selected for whole-domain coverage, then download and apply the dedicated export as described in [PIHOLE.md](PIHOLE.md).

The old 0.3 FortiGate-reader/transparent-Squid procedure is retired. If it was already activated, apply its matching rollback **before** upgrading; see the historical guide linked in the README. Do not bypass the migration guard by deleting activation files.
