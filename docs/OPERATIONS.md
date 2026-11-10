# Requests, activity history, batch cleanup and device setup

Version 0.9 provides the Requests inbox, Activity log, per-code website history, safe batch removal and a public CA-download link. Update normally; the transactional schema-8 migration keeps codes, active grants, administrator logins/exclusions, domain rules and the existing CA. No extra packages, DNS changes or device enrollment are required.

## Request access: Approve / Deny

The ordinary portal has **Request access**. A request reached through a valid gateway entry carries that hostname; direct requests are General access. Visitors can provide an optional label/reason and leave the waiting page open. The page checks their own request every three seconds and continues automatically after approval, with a visible Continue to website link and manual-refresh fallback when JavaScript is disabled.

Administration shows a persistent unread count and Requests inbox. Open a pending request to:

- **Approve**: choose a positive duration in minutes/hours, up to seven days. Grant the requesting browser direct access without copying or entering a code.
- **Deny**: close the request without granting access. This does not revoke unrelated access the browser already had.
- **Mark read**: acknowledge the notification without deciding or granting anything.

The timer starts when the administrator approves. Approval has the same scope as a normal code session: all currently managed restricted websites, rather than only the requested hostname. Separate domain profiles remain future work (#11). If the browser already has active access, the chosen time is added once to that existing session; its previous deadline is not shortened. The same 365-day maximum resulting window as administrator extensions applies.

An approval is transactionally bound to the browser hash stored with the request, not to its display label or IP. Changing networks does not transfer access to another device sharing the address. Sending, reading, polling or knowing a request ID cannot grant or claim access. Administrator authentication, management-network checks and CSRF are required for decisions. Only the requesting browser can retrieve its decision or use the continuation route; the destination comes from validated stored request context, not a supplied return URL.

For a new session the app creates an already-activated, unexported **Approval token** in the existing grant/history system. No redeemable code is sent or stored in plaintext. The session appears in Sessions, and the request links directly to its token/history plus active extension/termination actions. When approval extends an existing code session, the request links to that same token. Approval/denial and resulting activation/extension are recorded in Activity. Existing code deadlines and one-use checks remain unchanged for ordinary code entry.

The original five-minute website challenge is not kept alive while waiting. On approval the browser opens the stored hostname again and performs a fresh origin-bound gateway handoff if needed. This allows approval after the original challenge expired. A general request returns to the portal's active-access page. Closing the waiting tab does not stop the granted timer; the same browser can open the website or portal later.

Requests are terminal decisions: repeated Approve with the same duration does not create another session or extend again, and changing the duration on an already approved request is rejected. Deny cannot overwrite an approval. Concurrent decisions serialize into one outcome. Expired/denied/previously closed requests cannot later be approved; send a new request instead. After approval, use the normal session controls to extend or terminate access. Replaying approval after termination/expiry does not reopen it.

Pending requests expire after 24 hours. Duplicate pending requests from one browser/hostname reuse the existing item. Limits remain three requests per browser and five per source address per 15 minutes. Stored text is escaped, and other browsers at the same IP cannot see the request or inherit approval. Re-requesting from an owned previous request preserves its hostname without accepting a client-supplied destination.

Read/decision state survives service restarts and is shared across administrator tabs. Notification/status polling does not renew an idle admin login or the approved access deadline. Requests age out under the configured activity retention, independently from the underlying approval-token/grant integrity. Legacy Resolved/Dismissed rows from 0.8 remain readable and closed; new decisions use Approved/Denied. Submitting an old Resolve/Dismiss form is rejected with an instruction to reload. No email, external push or chat integration is required.

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

### Approval validation (0.9)

The 0.9 source passes 282 Python tests plus the Node UI checks. The approval update covers direct browser grants, one-time duration application, same-IP isolation, network changes, denied/expired/replayed requests, concurrent admin decisions, existing-session extensions, normal revocation/history integration and no administrator privilege granted to visitors. A real local TLS test returns an approved request through a fresh gateway challenge without code entry, including expiry of the original entry. Node checks cover automatic continuation, denial and rejection of an external continuation URL.
