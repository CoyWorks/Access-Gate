# Pi-hole domain list

The optional **DNS domains** screen creates your own list of domains pointing to `192.168.10.20`. This list is stored in the Access Gate database and preserved during updates. It is available at stable feed URLs as well as file downloads; the portal does not connect to or modify Pi-hole automatically.

## Live feed URLs

- `http://192.168.10.20/domains.txt`: a conventional hosts-format list, one enabled base/exact hostname per line, such as `192.168.10.20 example.com`. It is available even if subdomain scopes are enabled, but the comments explicitly state that those scopes cannot be represented in this format. It does not enumerate or invent subdomains.
- `http://192.168.10.20/pihole.conf`: the full dnsmasq configuration, preserving all enabled exact/subdomain rules and the target `192.168.10.20`. Use this for the actual whole-domain redirect setup.

Both URLs update from the current saved list on every fetch and need no administrator login, session cookie or private API key. Access is limited to the configured client networks (by default `192.168.0.0/16` and loopback) and the existing trusted reverse-proxy boundary. The HTTP listener serves only these feed paths and the public CA without redirecting to HTTPS; the portal/admin still use HTTPS. HTTPS access to the feeds remains available through the existing listener and certificate.

A hosts file follows the same text shape as lists such as StevenBlack/hosts. That shape alone does not tell Pi-hole to preserve its destination IP. Ordinary **adlist** import stores the extracted domains for blocking, and the DNS answer follows Pi-hole's global blocking mode. It also cannot infer all subdomains from one hosts row. Do not change global blocking settings merely to make this list redirect, since that affects unrelated blocked domains too. Use the local dnsmasq config feed for the requested mapping/scope.

The portal does not install a Pi-hole polling job. List edits appear immediately at the URLs; Pi-hole uses them only after its fetch/apply workflow. For a simple manual fetch on the Pi-hole host:

```bash
curl --fail --silent --show-error --connect-timeout 5 --max-time 20 \
  http://192.168.10.20/pihole.conf -o /tmp/99-access-gate.conf
```

Proceed only after a successful fetch, then apply and verify the dedicated file as described below. Do not pipe a downloaded config into a shell.

## Create and download

1. Update the portal normally: `bash /root/Access-Gate/update.sh`.
2. Sign in to `/admin` and open **DNS domains**.
3. Paste one domain per line. Leave **Domain + all subdomains** selected to cover an entire domain, or choose **Exact hostname only**. Blank lines and whole-line `#` comments are ignored.
4. Add the entries and review the target/match scope and preview. The live feed URLs now reflect the saved list.
5. Fetch `/pihole.conf` on Pi-hole using the command above, or select **Download Pi-hole config** and copy `99-access-gate.conf` there. Apply the new file after each list change; installed/downloaded files are snapshots.

## Import domains from an external blocklist

Instead of entering domains manually, use **DNS domains → Import a blocklist URL**. Paste a public HTTPS raw-file URL, choose the match scope and click **Import from URL**. A source such as `https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts` is an input to Access Gate: the portal extracts its domains and adds them to your own restricted list, always using `192.168.10.20` in the output. It does not copy the source's destination IPs or modify Pi-hole directly.

Supported input formats are IPv4/IPv6 hosts records with one or more hostnames, plain domain lines and simple `||domain^` entries. Comments, blank lines, local host boilerplate and IP literals used as hostnames are ignored. Unsupported filter syntax, options and allowlist exceptions are skipped and counted, rather than being turned into potentially broader restriction rules. In exact mode, `*.domain` entries are skipped; in subdomain mode they are normalized to the base name. No base/registrable domain is guessed from a source hostname.

New domains use the selected exact or all-subdomains scope. Existing entries retain their enabled/disabled state and scope. The import result reports added, already listed, duplicate and skipped counts. Reimporting is additive: deleting a domain upstream does not remove it from your saved list, and a repeated import never re-enables a disabled row.

The maximum download is 32 MiB, with up to 500,000 stored domains. A failed fetch, unsupported/empty result or exceeded limit leaves the saved list unchanged. Downloading requires a public HTTPS destination and certificate verification; private/loopback/link-local/metadata destinations are refused at each redirect, and the approved connection address is pinned to prevent DNS rebinding. Compressed/HTML/non-UTF-8 responses are rejected; use the raw text URL rather than a repository's HTML file view.

Nothing is preloaded or downloaded automatically on page loads or feed fetches. Import is a one-time administrator action. To pick up later additions, submit the URL again. After a successful import the live output feeds update immediately; Pi-hole still needs to fetch/apply the resulting `/pihole.conf` as described below.

The table has search and pages of 100 rows. Its config preview is limited to 50 enabled rules. These display limits never truncate downloads or live feeds, including after a large import. Imported domains and existing browser grants survive the normal update/restart workflow.

`example.com` and `*.example.com` are equivalent in subdomain mode: both cover the base name and every subdomain level. The match respects DNS label boundaries, so `unrelatedexample.com` is not included. Exact mode accepts a hostname without `*.`. Duplicates retain their existing enabled state and match scope. Change that scope explicitly in the table when needed.

Example export:

```ini
# Domain + all subdomains
address=/example.com/192.168.10.20
local=/example.com/

# Exact hostname only
host-record=single.example.org,192.168.10.20
```

The `local=` line is intentional. In modern dnsmasq, an IPv4-only `address=` rule alone can still forward other query types upstream. Combining the two makes this wildcard scope local, so an upstream AAAA or HTTPS/SVCB answer does not escape that rule. It also suppresses upstream MX/TXT and other record types for that scope. The export does not create an IPv6 destination.

A hosts file cannot express wildcard behavior. Its alternative download is therefore available only when every enabled entry is an exact match. Do not add the download as a Pi-hole **adlist**: gravity filtering does not retain a custom destination IP. Use local DNS configuration instead. The main config export supports mixed exact/subdomain rules without losing coverage.

## Apply on Pi-hole

Use a dedicated Access Gate file so unrelated local DNS configuration is retained. Do not replace `/etc/hosts`, `/etc/pihole/custom.list`, the generated `/etc/pihole/dnsmasq.conf`, or Pi-hole's whole configuration with this export.

For the existing DNS server, a copy from the machine holding the download might be:

```bash
scp 99-access-gate.conf root@192.168.10.10:/tmp/99-access-gate.conf
```

The following commands run **on Pi-hole**, not on the portal server.

### Pi-hole 6

Pi-hole 6 does not load `/etc/dnsmasq.d/` by default. Check and record the current setting:

```bash
sudo pihole-FTL --config misc.etc_dnsmasq_d
```

Review any other files in that directory before enabling it: this setting loads those as well. If it is not already enabled:

```bash
sudo pihole-FTL --config misc.etc_dnsmasq_d true
```

For a container managed by Docker Compose, persist the setting using `FTLCONF_misc_etc_dnsmasq_d: 'true'` and mount the dedicated config file/directory at `/etc/dnsmasq.d/`. Use the container's normal configuration/recreation workflow; host-only changes outside its mounted configuration will not survive recreation.

### Pi-hole 5

The standard Pi-hole 5 setup already reads `/etc/dnsmasq.d/`. Do not run the Pi-hole 6 configuration command on version 5. Use the same dedicated file and verification below.

### Install the file and verify

If `/etc/dnsmasq.d/99-access-gate.conf` already exists, save a copy **outside** `/etc/dnsmasq.d/` before replacing it, for example under `/root/`. Also retain the previous value of the Pi-hole 6 directory-loading setting.

```bash
sudo install -d -m 0755 /etc/dnsmasq.d
sudo install -m 0644 /tmp/99-access-gate.conf /etc/dnsmasq.d/99-access-gate.conf
sudo pihole-FTL dnsmasq-test
```

Proceed only when the syntax test succeeds. If it fails, restore the previous dedicated file (or remove the new file if this was the first import), correct the reported error and test again before restarting. Do not leave a failing candidate in the directory for a future service reload.

```bash
sudo systemctl restart pihole-FTL
sudo systemctl is-active pihole-FTL
```

In a container, run the syntax check inside the container and use its normal restart mechanism.

For a listed domain such as `example.com`, test against the actual DNS server:

```bash
dig @192.168.10.10 example.com A +short
dig @192.168.10.10 www.example.com A +short
dig @192.168.10.10 a.b.example.com A +short
dig @192.168.10.10 example.com AAAA
dig @192.168.10.10 a.b.example.com HTTPS
```

The first three should return `192.168.10.20` for a subdomain rule. The last two should not return a public IPv6 address or upstream HTTPS record for that scope. Also test an unrelated domain, and test that an exact-only rule leaves its subdomains unaffected. Clear old client/browser DNS caches or wait for their cached answers to expire; a configuration import cannot revoke cached public answers already held by clients.

Pi-hole Local DNS/hosts entries and DHCP leases can override `address=` for individual names; more-specific server/forwarding rules can also change the result. Resolve conflicting entries when the actual query result differs. Disabling or deleting a child entry does not make an exception to an enabled parent subdomain rule.

## Update or remove

After an edit in Access Gate, fetch the live config feed again or download a new snapshot, replace the dedicated Pi-hole file, then repeat the syntax check and restart. Disabling a row affects the next feed response/export; it does not change a previously installed copy. Keep one maintained copy rather than accumulating multiple exported files in the loaded directory.

To undo an import, restore the saved previous dedicated file, or remove **only** `/etc/dnsmasq.d/99-access-gate.conf` for a first import. Restore the previous Pi-hole 6 directory-loading setting if it was changed for this setup, run the syntax check and restart. Preserve unrelated local DNS entries and other custom configuration.

## Website behavior

DNS now points selected names at the gateway. The browser still requests the original site's HTTPS hostname. The installed 0.5 [HTTPS gateway](GATEWAY.md) generates a matching certificate under the retained device-trusted CA, forwards to the verified real origin after code authorization and checks open streams for expiry/revocation. Keep these DNS mappings stable during sessions; DNS TTLs are not the access timer. Device trust and actual DNS/routing/transport behavior must still be checked on the target network.

This source release has automated coverage for export construction, validation, persistence, browser-grant preservation and administration controls. Pi-hole daemon/query behavior and real-device access still require the checks above on the target network.

References: [Pi-hole configuration](https://docs.pi-hole.net/ftldns/configfile/), [Pi-hole blocking modes](https://docs.pi-hole.net/ftldns/blockingmode/), [Pi-hole domain database](https://docs.pi-hole.net/database/gravity/), [Pi-hole FAQ/local DNS sources](https://docs.pi-hole.net/main/faq/), [dnsmasq address/local/host-record semantics](https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html), [StevenBlack hosts-format example](https://github.com/StevenBlack/hosts).

## Scheduled configuration refresh (native Linux Pi-hole)

Disable the Access Gate adlist and enable loading `/etc/dnsmasq.d` first as described above. On the Pi-hole server, install the repository's sync helper as root:

```bash
curl -fS --max-time 30 https://raw.githubusercontent.com/CoyWorks/Access-Gate/main/scripts/sync_pihole.sh -o /tmp/access-gate-pihole-sync
install -m 0755 /tmp/access-gate-pihole-sync /usr/local/sbin/access-gate-pihole-sync
install -d -m 0755 /etc/default
cat > /etc/default/access-gate-pihole-sync <<'CONFIG'
ACCESS_GATE_FEED_URL=http://192.168.10.20/pihole.conf
ACCESS_GATE_TARGET_IP=192.168.10.20
CONFIG
/usr/local/sbin/access-gate-pihole-sync
```

After a successful first run, create `/etc/cron.d/access-gate-pihole`:

```cron
*/5 * * * * root /usr/local/sbin/access-gate-pihole-sync >> /var/log/access-gate-pihole-sync.log 2>&1
```

The helper fetches `http://192.168.10.20/pihole.conf` directly without environment proxies, locks against concurrent runs and skips unchanged downloads. It validates the export header and DNS syntax, rolls back failed validation/restart and restarts FTL only for changes. An empty managed list still exports the identifying header and clears the old mappings. No Gravity rebuild or allowlist changes are performed. This is for a normal Linux installation, not Docker volume management. Stop scheduled sync by removing the cron file; the last mappings remain loaded.

Existing helpers already installed on Pi-hole keep their current settings until you replace them. Before installing the new helper, create the settings file above using your actual portal address and target.
