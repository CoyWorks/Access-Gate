# Activate the VPN traffic path

This release supplies the local enforcement components and an additive FortiGate plan. Updating the portal does not remotely configure the firewall or prove device/browser compatibility. Start with Android and one distinct VPN account. Keep the existing FortiGate configuration; no rebuild is required.

## 1. Update and check the server

```bash
bash /root/Access-Gate/update.sh
systemctl is-active access-gate access-gate-keeper squid nginx
timedatectl show -p NTPSynchronized --value
```

Expected: four `active` results and `yes`. Code records, the admin password and the public CA are retained. Schema version 2 imports the old domain file once. Existing grants close during restart; codes stay consumed.

In administration, add a known public test website to **Restricted domains**, such as `example.org`. Refresh until the proxy revision says **Applied**. **Retry apply** requests another attempt after an error. Changes reconnect proxy sockets so a previously spliced connection cannot evade a newly added restriction. They do not reset or revoke unrelated code deadlines. Manage rules here after the one-time import; later edits to `domains.txt` are not imported automatically.

The root worker validates candidates and retains the previous applied rules on failure. If rollback itself fails it stops Squid. Read `journalctl -u access-gate-keeper -u squid -n 80 --no-pager`; fix the service before retrying.

## 2. Prepare live VPN identity

On `srvaccess01`:

```bash
cd /opt/access-gate
python3 configure.py --reader-setup --fortigate-host 10.40.22.1 --fortigate-user accessgate-reader
```

This creates a private local SSH key and a root-only `fortigate.json`; it prints only the public key. It makes no FortiGate changes. If the FortiGate management address differs from the VLAN gateway, supply that address instead.

Create a dedicated FortiGate administrator through your existing trusted management connection. Confirm these object names are unused. Use a new strong password and paste the **first two fields** of the printed public key in place of the placeholder:

```text
config system accprofile
    edit "AG-Reader"
        set vpngrp read
        set system-diagnostics enable
        set system-execute-ssh disable
        set system-execute-telnet disable
    next
end
config system admin
    edit "accessgate-reader"
        set accprofile "AG-Reader"
        set vdom "root"
        set trusthost1 10.40.22.5 255.255.255.255
        set password "REPLACE_WITH_A_NEW_STRONG_PASSWORD"
        set ssh-public-key1 "ssh-ed25519 REPLACE_WITH_PUBLIC_KEY_VALUE"
    next
end
```

Use the existing SSH management listener; do not replace interface `allowaccess` settings or expose SSH publicly. FortiOS 7.2 diagnostic permission is broader than a per-command SSH restriction. The connector itself invokes only `diagnose vpn ike gateway list`; protect the key and restrict the administrator's trusted source as above. The unprivileged portal cannot read these credentials.

Pin the FortiGate SSH host key. A candidate can be collected with:

```bash
ssh-keyscan -T 5 -t ed25519 10.40.22.1 > /root/access-gate-hostkey.candidate
ssh-keygen -lf /root/access-gate-hostkey.candidate
```

Compare the fingerprint/key with the FortiGate host key already trusted by your management client through a separate trusted connection. Only after a match:

```bash
install -o root -g root -m 0600 /root/access-gate-hostkey.candidate /etc/access-gate/ssh/known_hosts
```

`ssh-keyscan` alone does not authenticate the firewall. The connector enforces host-key verification and never accepts unknown/changed host keys automatically. If the firewall advertises a different supported host-key type, collect that verified type instead.

Keep Android connected to `NATIVE-VPN` and run:

```bash
cd /opt/access-gate
python3 configure.py --identity-check
```

Expected: the authenticated EAP username, assigned `10.40.135.x` address and dynamic tunnel name. The parser requires an established IKE SA and IPsec SA, an `eap-user`, an assigned IPv4 address and an `id/spi` pair. An unfamiliar/incomplete format, ambiguous account, command error or SSH failure produces no authorization. If this check finds nothing, capture the complete output of `diagnose vpn ike gateway list` privately before enabling interception; the parser must match the actual device evidence.

In **Devices & users**, register that exact VPN username with a device label. The existing `vpn-mobile` account can be the Android pilot. Use distinct VPN accounts for additional devices; add them to the existing `NATIVE-VPN-Users` group without replacing its other members. Reusing one account concurrently on multiple devices is ambiguous and both sessions are denied.

Enable verified clients locally:

```bash
cd /opt/access-gate
python3 configure.py --enable-vpn-enforcement
```

This admits the VPN subnet to the proxy and requires live identity for VPN permission decisions. It restarts the local portal/worker and invalidates active grants. Wait a few seconds, refresh **Devices & users**, and confirm Android is **Verified** at its current address. Do not rely on a manually registered IP as identity.

A fresh FortiGate query is used for each VPN permission decision. The stable ID is the registered VPN account; the current binding includes assigned address, tunnel and IKE SPI evidence. A changed binding, disconnect, ambiguous account or identity-source failure revokes the old grant. A returning device then needs another unused code. An unchanged verified session keeps its original deadline. This conservative behavior also means an IKE rekey that changes the observed SPI may close access early. No browser cookie or supplied header proves VPN identity.

The root worker also polls current sessions approximately once a second, with a four-second SSH timeout. New permission checks fail closed when their live query fails. Existing restricted streams are revoked after a failed background query (normally within about 5.5 seconds plus socket cleanup). This first connector favors fresh evidence over throughput; test responsiveness before adding many devices.

## 3. Prepare the supported browser path

- Install the existing **public** Access Gate CA as trusted on Android. Do not copy its private key or change IKEv2 certificates.
- Use Android's **Always-on VPN** and **Block connections without VPN**. Test on mobile data as well as Wi-Fi.
- Turn off browser Secure DNS and Android Private DNS for the pilot, so configured DNS is `10.40.22.10`.
- This release intercepts IPv4 HTTP on TCP 80 and HTTPS on TCP 443. QUIC/HTTP3 is denied by the reviewed firewall rules so browsers can fall back to TCP. Alternate website ports, other tunnels/proxies and deliberate domain fronting are outside this pilot's enforcement guarantee.
- TLS requires a visible, valid SNI. The TLS helper rejects ECH extension `0xfe0d`, including indistinguishable ECH GREASE, before a splice can occur. Browsers that send ECH/GREASE need a supported setting/policy disabling it. A browser with no such setting is unsupported for this strict pilot; it may show a connection failure even for unrestricted sites. Do not weaken the helper to assume encrypted names are harmless.
- Encrypted or missing SNI produces a connection failure, not an unlock page. A pinned application may also reject the generated site certificate. The automatic unlock flow targets ordinary supported browser navigations; embedded fetches may fail CORS rather than navigate the top-level page.
- IPv6 is not intercepted by this version. With VPN lockdown enabled, prove that external IPv6 connections fail instead of leaving via the carrier/Wi-Fi interface. If IPv6 succeeds, stop rollout on that device. iPhone/iPad on-demand VPN alone does not establish this guarantee; validate its IPv6/routing behavior before adding it. Do not claim all device combinations are supported from the Android test.

For Chrome, the documented policy control is `EncryptedClientHelloEnabled=false`. On Android this is a **managed app restriction**, not an ordinary setting guaranteed to appear on a personal phone. On Windows it can be set through the corresponding Chrome policy. Do not assume an old `chrome://flags` entry still exists. If your personal Android browser cannot disable ECH/GREASE, stop the transparent rollout at this stage and resolve browser compatibility first; a working VPN alone is insufficient.

## 4. Generate the FortiGate change and rollback

Read these on the FortiGate:

```text
show firewall policy
show router policy
```

Find the **first existing matching policy for NATIVE-VPN clients**. New narrow allows and the bypass deny must precede all broader matching allows, including LAN rules. Also inspect any existing matching policy routes. Select unused firewall/policy-route IDs and unused `AG-*` object names. The default plan uses policy-route IDs 9000–9004 and firewall policy IDs 9010–9015; it must not overwrite an existing ID/name.

Example only, if that first matching firewall policy is **123** and all generated IDs/names are unused:

```bash
cd /opt/access-gate
python3 -m access_gate.network plan --before-policy 123 --base-id 9000 --scope 10.40.135.0/24
```

The output is outside the Git checkout, under `/root/access-gate-network`:

- `fortigate-enable.conf`: additive addresses/services, scoped policy routes and policies.
- `fortigate-rollback.conf`: removes only the corresponding objects.
- `linux-intercept.nft`: inspectable local interception rules.

Review the generated files before pasting the FortiGate commands. It preserves private-destination routing, routes public TCP 80/443 through **10.40.22.5 on vlan22**, and leaves original destination and VPN source addresses intact. The VPN-to-proxy web policy has NAT disabled. The proxy's independent upstream connection can use WAN NAT. Existing IKE configuration, the VPN route, Pi-hole and OCI tunnels are not rebuilt.

If policy routes already match these clients, put the three private-route exceptions and two web routes ahead of those broader routes in the GUI/CLI. The generated IDs alone do not establish precedence over pre-existing routes. The narrow firewall rules permit DNS to Pi-hole and web traffic through the proxy, then deny direct web/QUIC/alternate-DNS bypass before existing broader policies. Other services retain the existing firewall policy behavior.

Activate Linux interception first:

```bash
cd /opt/access-gate
python3 -m access_gate.network enable --scope 10.40.135.0/24
```

Activation refuses unless verified identity enforcement is configured, a registered live user is observed, the worker is healthy and the domain revision is successfully applied. Only the dedicated `inet access_gate` nftables table is changed. There is no `flush ruleset`, DNAT on the FortiGate, global firewall replacement or enabling of IP forwarding. A guarded systemd unit restores the owned table after reboot; the installer leaves interception disabled until this explicit activation.

Now paste the reviewed FortiGate enable file. Reconnect only the test VPN so existing direct browser connections do not keep their pre-change firewall sessions. Confirm the resulting live address is verified; no old grant is silently carried across the reconnect.

## 5. End-to-end Android acceptance

Record the actual results before expanding beyond the test device. Four-hour DNS TTLs are irrelevant to the permission timer; authorization is checked at the proxy.

| Test | Expected evidence |
| --- | --- |
| No code, ordinary unrestricted HTTP/HTTPS site | Opens. HTTPS keeps the origin certificate, without Access Gate decryption. |
| No code, restricted browser navigation | Trusted unlock page appears automatically, without manually setting a browser proxy. |
| Valid one-minute code | Returns to the selected domain's root page; the server deadline is visible. |
| Invalid, consumed or revoked code | Does not unlock. A code stays single-use across clients/reconnects. |
| Open restricted download/stream at expiry | Tracked TCP connection closes. The next supported navigation shows the portal. Already downloaded data cannot be removed. |
| Unrelated open site during expiry | Its independent connection remains usable; its access was not revoked. |
| Extend active access | New persisted deadline is used by proxy checks and the countdown; one repeated submission cannot add twice. |
| VPN reconnect/address reuse | Changed session loses old access. Another registered user receiving that IP cannot inherit it. |
| Stop/restart reader availability | New restricted checks fail; previously allowed restricted streams close after identity failure detection. Ordinary sites still splice. |
| HTTP3/QUIC attempt | FortiGate deny counters/logs show UDP 443 denial; browser retries through TCP interception. |
| Forced ECH/GREASE or missing SNI | TLS fails closed. It must not reach a hidden restricted target. |
| External IPv6 attempt with mobile data | Fails under the device VPN lockdown. Any successful carrier/Wi-Fi IPv6 path blocks acceptance. |
| Browser sleep/resume/refresh | Countdown reconciles with `/status`; closing the browser never pauses the timer. |
| Reboot and worker failure | Interception returns only if explicitly enabled. Old grants stay invalid. Restricted sockets cannot remain authorized after worker loss. |

Useful read-only evidence on the server:

```bash
systemctl is-active access-gate access-gate-keeper squid nginx
nft list table inet access_gate
ss -nt '( sport = :3128 or sport = :3129 or sport = :3130 )'
journalctl -u access-gate-keeper -u squid -n 80 --no-pager
```

On the FortiGate, capture a short test while opening a public website:

```text
diagnose sniffer packet any 'net 10.40.135.0/24 and (tcp port 80 or tcp port 443 or udp port 443)' 4 30 l
```

Expected: original client source/destination through `NATIVE-VPN` and `vlan22`, plus a separate proxy-originated WAN connection. Confirm policy-route matches in `diagnose firewall proute list` and policy ordering in the GUI. Never substitute a DNAT VIP to port 3130: Squid needs the original destination.

## 6. Deadline and worker checks

From the Git checkout on the dedicated server, the normal suite runs without changing live services:

```bash
cd /root/Access-Gate
python3 -m unittest discover -s tests -v
```

A separate opt-in test creates two temporary TCP connections on **127.0.0.1:3128 and :3129**. It uses actual kernel socket destruction to close only the tracked restricted connection, then verifies an independent ordinary stream still works. Those loopback ports must be unused; production Squid listens on `10.40.22.5`:

```bash
cd /root/Access-Gate
ACCESS_GATE_LIVE_NETWORK_TESTS=1 python3 -m unittest discover -s tests -p test_live_sockets.py -v
```

Run as root; CAP_NET_ADMIN is required. This test does not change firewall policies or use production codes. It complements the actual browser/stream test rather than proving the whole proxy path.

For a healthy worker, new authorization stops at the exact persisted deadline. The expiry loop runs every 0.5 seconds; actual connection closure additionally includes scheduling and `ss -K` work (five-second timeout per tracked socket). It is best effort, not a hard real-time bound under load. SSH/policy application run separately from this loop. Worker heartbeat older than three seconds denies new restricted checks. systemd's eight-second watchdog restarts a hung expiry worker, and `ExecStopPost` invalidates grants and closes proxy sockets even after abnormal termination. If kernel socket cleanup cannot run, do not accept expiry enforcement until fixed.

Connections are tracked by the proxy's client/listener TCP tuple when a restricted request is authorized. Independent untracked browsing is not closed at normal expiry. A shared/coalesced connection, or a tuple reused before cleanup, may need to reconnect too. General unrelated access is not revoked. This pilot does not promise to erase cached content, terminate an already completed download or identify pinned/native application streams.

The worker requires synchronized server time and revokes access on a detected wall-clock jump over two seconds. Do not treat a device clock or browser countdown as the authority.

## 7. Rollback

1. Through the existing trusted FortiGate management connection, apply the **matching generated** `fortigate-rollback.conf`. Check IDs/names still belong to this activation. This restores ordinary routing/policy matching without deleting existing VPN or OCI settings.
2. On the Access Gate server:

```bash
cd /opt/access-gate
python3 -m access_gate.network disable
```

Only the owned nftables table and its local activation state are removed; the restore unit is disabled. Domain/code records and the working VPN remain. A full application reset also removes local interception state, but does **not** roll back FortiGate changes; remove those first.

Reader credentials can be removed separately when retiring the connector. Keep the public CA installed if continuing proxy tests; remove it from devices when retiring HTTPS inspection entirely.

## Sources and verification boundary

- [FortiGate: assigned IP and authenticated EAP user in IKE gateway output](https://community.fortinet.com/fortigate-3/technical-tip-ip-address-not-showing-on-forticlient-gui-196383)
- [FortiGate: gateway `id/spi` evidence](https://community.fortinet.com/fortigate-3/technical-tip-how-to-find-the-ip-address-assigned-to-the-ipsec-remote-dialup-user-205396)
- [FortiOS 7.2.1 administrator profile permissions](https://docs.fortinet.com/document/fortigate/7.2.1/cli-reference/2620/config-system-accprofile)
- [FortiOS public-key SSH administration](https://docs.fortinet.com/document/fortigate/7.2.6/administration-guide/813125/public-key-ssh-access)
- [FortiOS 7.2.1 policy routing](https://docs.fortinet.com/document/fortigate/7.2.1/cli-reference/562620/config-router-policy)
- [Squid: local NAT interception and separate-gateway policy routing](https://wiki.squid-cache.org/ConfigExamples/Intercept/LinuxRedirect)
- [Squid: SSL Bump actions and supported ACL types](https://www.squid-cache.org/Doc/config/ssl_bump/)
- [Squid: external ACL transport and cache behavior](https://www.squid-cache.org/Doc/config/external_acl_type/)
- [Squid: handshake and client/listener tuple format fields](https://www.squid-cache.org/Doc/config/logformat/)
- [Chrome ECH control and supported Android managed restriction](https://chromeenterprise.google/intl/en_ca/policies/encrypted-client-hello-enabled/)
- [Netfilter: NAT hooks and redirect](https://netfilter.org/projects/nftables/manpage.html)

The repository includes automated domain/identity/expiry/transport regression tests. Actual FortiGate permissions/output, Squid parsing/reload, kernel socket privileges, Android redirect and transport captures must be verified on the target installation. The dependent rollout issues stay open until that evidence exists; a source-code release alone is not a completed network rollout.
