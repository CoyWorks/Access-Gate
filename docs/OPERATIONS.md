# Requests, activity history, batch cleanup and device setup

Version 0.8 adds the Requests inbox, Activity log, per-code website history, safe batch removal and a public CA-download link. Update normally; the transactional schema-7 migration keeps codes, active grants, administrator logins/exclusions, domain rules and the existing CA. No extra packages, DNS changes or device enrollment are required.

## Request access

The ordinary portal has a **Request access** link next to the existing code/login options. A request reached through a valid gateway entry carries that entry's hostname; direct portal requests are labelled General access. Visitors can optionally provide a label (80 characters) and reason (500 characters), and can revisit the page to see only their own browser's requests. A supplied display label, address or domain is not an authorization identity.

Requests are persisted in SQLite. Administration shows an unread count in **Requests**, refreshed every 10 seconds while signed in, plus an inbox filtered by Pending/Resolved/Dismissed/Expired/All. Open a request and explicitly **Mark read**, **Resolve request** or **Dismiss**. Reading the detail page alone does not change its state. Notification/read state survives service restarts and is shared across admin tabs/workers.

This first delivery is the notification workflow: submitting, reading or resolving a request does **not** issue a code or grant access. Administrators can create a normal code and give it to the visitor. Automatic approval/grant delivery is a separate future decision; no email, external push or chat message is sent by this feature.

Pending requests expire after 24 hours. Duplicate pending requests from the same browser for the same hostname return the existing request without adding another notification. Submissions are limited to three per browser and five per source address per 15 minutes. Visitors sharing a source IP cannot see one another's requests. Stored text is escaped; requests do not collect passwords, form payloads or private browsing paths from the gateway. Notification polls do not renew an idle admin login.

## Activity log and per-code history

Open **Activity** for code/batch creation, activation, revocation, extensions, termination, observed expiry, administrator policy/login changes, DNS-list changes and request activity. Filter by date, event, actor role or batch, with 100 rows per page. The app has one administrator identity; actor labels do not invent user/VPN identities. Application events are not an operating-system/root-file-change audit trail.

Click a **code ending** in a code list, or a code link in Activity, to open its detail page. Full code values remain unrecoverable. The page shows batch/activation information and three views:

- **Domains**: requested managed hostnames, request counts, first seen and last seen.
- **Pages**: recorded navigation paths per hostname, counts and first/last seen, when page logging was enabled.
- **Events**: activity for this code and related batch-level operations.

Visit timestamps come from the gateway receiving response headers, rather than a delayed queue delivery. Website history begins after this update; previous browsing cannot be reconstructed. It covers only requests actually forwarded by this gateway under the code's grant. Requests authorized by administrator/IP exclusion are not assigned to a fake code. Attribution follows the site proof used for that request; an existing code-derived site proof remains code-scoped until a new handoff replaces it. Use a separate, non-excluded browser to test a code's history. Background resources, redirects, error responses and WebSocket handshakes may contribute domain counts; these records are not proof of deliberate human browsing or that a response was completely viewed/downloaded. Failed upstream TLS/connect attempts before a response are not included.

Page rows use GET document/iframe navigations (or a text/html request without Fetch Metadata), not every asset, API call or WebSocket message. Paths are capped at 512 characters. Querystrings, fragments, cookies, authorization headers, request/response bodies, code values and Access Gate callback tickets are not recorded. A path can still contain private text, such as a document name or account slug, so **Pages is an explicit administrator setting**. The code portal displays the active logging policy and retention period.

In **Activity → History settings**, choose:

| Mode | New website history |
| --- | --- |
| Domains only (default) | Hostnames and request metadata; no page paths |
| Domains and page paths | Hostnames plus navigation paths |
| Off | No new website history; application activity events continue |

Changing settings requires the current admin password and CSRF, with a settings-version check to avoid stale overwrites. Switching away from Pages removes retained page-path fields. Off does not immediately delete existing domain rows; they age out normally. This cannot remove data from previously taken backups.

## Retention, delivery and limitations

Activity events, website visits and access requests default to **30 days** of retention, adjustable from 1 to 365 days. History queries enforce that cutoff immediately. The running gateway invokes bounded maintenance about once per minute, even without website traffic: it deletes up to 5,000 old rows per table per pass, expires pending requests and records newly observed expired code grants once. Very large backlogs can take several passes; maintenance pauses when the gateway is stopped. Code digests, consumption/revocation records and existing grant/extension metadata are retained independently and are not made reusable by history cleanup.

State-change activity is written in the same transaction for core code/batch mutations. Invalid-code/login events contain fixed categories rather than submitted secrets. Website metadata uses a separate in-memory gateway queue (1,000 records), authenticated private delivery, one retry with the same idempotency ID and a short shutdown drain. Logging failures do not override authorization or block normal access. Queue overflow, delivery failure or abrupt process termination can lose website metadata; this is best-effort operational history, not a complete forensic browser history.

**System status** reports the activity queue and the number of dropped records since gateway start. A nonzero drop counter produces a warning. Restarting clears the in-memory counters and cannot recover lost records. Authorization/expiry checks remain authoritative and independent from this queue.

## Remove batches

The Batches overview offers **Remove** for one batch and **Clear revoked batches** for bulk cleanup. Both require confirmation and CSRF. Removing a still-active batch explicitly revokes its unused codes and browser grants in the same transaction, then hides the batch from the normal overview. Existing restricted connections close through the normal live grant checks unless another exclusion/authorization applies.

Bulk cleanup previews up to 100 revoked batches at a time and submits only that reviewed selection. Batches revoked later are not silently added to the action. Repeated removal is harmless. Current-batch/code totals and pagination exclude removed batches.

The **Removed batches** view and direct batch/code history links remain available. Removed batch details also show previously cleared code records; current batch details offer Include cleared code records for history. This is a retained archive, not physical deletion: consumed/revoked code hashes, grant links, extension history and activity cannot be reset by removing a batch. There is no action that restores the codes to unused status. Code-level Clear revoked continues to hide revoked rows in current batches without deleting their protected records.

## Download the device CA

The home page has **Download CA certificate**, available before code entry/login and for active/excluded visitors. It downloads only the existing public certificate at `/ca.crt`, over the portal's HTTPS connection. Neither the CA nor any private key is regenerated or exposed.

For first-time trust setup when the browser cannot yet open the HTTPS portal, the existing direct HTTP bootstrap URL remains:

```text
http://10.40.22.5/ca.crt
```

After installing/trusting the CA on the device, use the HTTPS portal link normally. See [GATEWAY.md](GATEWAY.md) for device/website checks and [EXCLUSIONS.md](EXCLUSIONS.md) for browser/IP bypass behavior.

## Validation

The 0.8 release passes 267 Python tests, including real local TLS code-to-page-history delivery, query redaction, logging failure without access interruption, excluded traffic scope and stream closure on batch removal. Store/web tests cover request isolation/concurrency/rate limits/persistence, notification actions, activity filters/pagination/retention, transactional rollback, preserved code state, cleared-code history discovery, schema migration and actual public-certificate download. Dependency-free Node tests verify notification polling/staleness and existing admin UI behavior; Python, JavaScript and shell syntax checks pass. These are source/local-integration checks; update srvaccess01 and validate actual device traffic there.
