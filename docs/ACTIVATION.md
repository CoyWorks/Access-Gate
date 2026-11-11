# Portal and HTTPS gateway activation

1. Run `bash /root/Access-Gate/update.sh`. No reset, VPN reader, user registration or domain registration is required.
2. Verify `systemctl is-active access-gate nginx access-gate-gateway` and a trusted HTTPS HTTP 200 response from `https://192.168.10.20/`.
3. Sign in at `/admin` with the existing administrator password. Create a batch and save the one-time code export.
4. Open the portal in a normal browser from Wi-Fi or VPN. Enter one unused code. The page shows its persisted deadline/countdown.
5. A different browser on the same address must still ask for a code. The original browser keeps its deadline when moving between the local and VPN networks.
6. Test an administrator extension and revocation through `/status`.
7. Maintain the restricted domains under **DNS domains**. Leave **Domain + all subdomains** selected for whole-domain coverage, then apply the dedicated Pi-hole export as described in [PIHOLE.md](PIHOLE.md).
8. Trust the retained root CA on the test browser/device and follow [GATEWAY.md](GATEWAY.md) to verify a matching certificate, automatic portal return, real website forwarding, open-stream expiry/revocation and Wi-Fi/VPN behavior. The gateway is installed by the updater; no manual per-domain certificates or separate Nginx proxy site are required.

The old 0.3 FortiGate-reader/transparent-Squid procedure is retired. If it was already activated, apply its matching rollback **before** upgrading; see the historical guide linked in the README. Do not bypass the migration guard by deleting activation files.
