# Administration interface

Version 0.15 reorganizes the interface around daily access decisions. It retains the existing code/grant model, approval scope, deadline checks, authentication, CSRF controls and destructive-action confirmations. No database migration is introduced.

## Main navigation

The same five destinations appear in a desktop sidebar and a phone bottom bar:

- **Home:** oldest pending requests first, active sessions, available handout-code count and scheduled batches ready to collect. The full code/extension tables have moved out of Home.
- **Requests:** pending cards with 15/30/60-minute presets, a custom duration, explicit Approve/Add time and Deny. Approved, Denied and History tabs retain previous decisions.
- **Sessions:** browser-session cards with countdowns, Extend, Details & history and Stop access. A shared session detail screen links requests, token history and the original batch.
- **Codes:** current/removed handout batches, Schedules and historical All records. Internal approval batches remain in retained history and are accessible through their session/token records, but do not fill the handout batch list.
- **More:** Restrictions, History, Settings and System groups. Existing URLs remain available for domain rules, exclusions, activity, security settings, phone notifications, health, updates and recovery.

The account menu also opens the visitor portal, phone setup and account settings. On the visitor portal the administration sidebar is absent, even for a signed-in administrator; a small Open administration link returns to management. The brand link in administration returns Home.

## Everyday flows

New requests appear on Home and Requests. Each approval shows that access covers **all restricted websites**. For a browser that already has active access, the button says **Add** and previews the new end time. Choosing a preset never submits the form; only the Approve/Add button does. The backend still enforces allowed durations, request ownership, single decisions and idempotency. Concurrent/stale inline decisions return to the inbox with feedback instead of retrying or granting another session.

The pending navigation count includes read pending requests. Unread notification accounting remains available through the existing API. Polling updates the count and displays a Refresh notice when requests change; it does not replace request forms while a duration is being chosen. Server-side access checks remain authoritative. Session list refresh pauses while one of its controls has focus; timers and server enforcement continue.

Session labels use an optional retained request label or the batch/code reference. They are not verified usernames or device identities. Activation IP addresses and internal IDs sit under Session details. Domains/pages/events remain code-scoped with the same privacy and retention rules. Missing/expired historical grant records still leave the original code/token history available.

Creating codes offers the 10 codes / 7 days / 15 minutes preset without changing the entered name or export choice. Full codes remain one-time output. Removing batches still revokes their codes/access; wording distinguishes **Revoke and remove**, **Stop access** and **Hide revoked codes**.

## Less frequent tools

Domain search and the existing rules are first. Add/import forms and Pi-hole feeds/previews are expandable panels; validation errors keep add/import expanded. History policy is expandable under Activity. Restore is expandable under Backup & restore and retains its explicit revocation warning and confirmation. Phone setup suggestions can be dismissed per browser using a local UI preference only; no code/authentication state is placed in local storage.

The Home health summary fetches the existing authenticated health API and shows Healthy, a specific issue, Stale or Unavailable rather than assuming a working system. More → System status retains complete details. No new remote health assertions are introduced.

## Validation

Automated coverage includes five-item navigation, separate visitor/admin shells, dashboard counts and ordering, inline CSRF/redirect controls, active-session additions, retained approval history, handout filtering, code-scoped session history, pending counts, management-route reachability and restored-login CSRF. Node checks exercise preset/limit behavior, safe card rendering, history/action links, polling, phone PWA controls and stale states.

Rendered template fixtures were checked for route/template errors. Browser-based screenshot/viewport verification was blocked by the execution environment's browser/socket and URL policies; no screenshots or live-phone visual acceptance are claimed. After updating, check Home, Requests, Sessions, Codes and More on the intended phone and desktop. Desktop uses a sidebar; widths up to 760px use the bottom bar with safe-area padding. Main workflow lists use cards; technical/history tables remain scrollable inside their containers. No authentication or offline-caching policy is weakened for preview/testing.

## Shared headers — 0.15.1

All administration workflows use the shared `page_header` macro in `templates/_page.html`: optional breadcrumb, section label, one page title, a concise description and an optional action area. The heading and actions use the same spacing and phone stacking rules. Breadcrumbs mark only the final item as the current page; dynamic names remain escaped.

Codes always shows **Batches / Schedules / All records**, including creation, detail, validation-error, confirmation, generated-code and print-preview screens. A batch, creation or output selects Batches; a schedule selects Schedules; code/token history selects All records. One-time export buttons retain their original IDs/data and printable-page navigation remains hidden when printed.

System status, Updates, Backup & restore and their maintenance jobs share System tabs. Account & security and Phone app & notifications share Settings tabs. Requests, Sessions and their decision/detail/confirmation screens use the same heading component, as do Home, More, restrictions and Activity. Visitor pages and sign-in retain their separate compact public layout.

Rendered HTML tests exercise list/detail/form/output/error/confirmation and maintenance pages, checking one primary title, common heading order, persistent tabs, active selection, breadcrumbs, escaping and unique export controls. Browser-based visual verification remains unavailable under the previously documented environment restrictions; no screenshot validation is claimed.

## 0.37 — Daily task shortcuts

Home and More share the same **Find a restricted domain** GET search, **Review requests**, **Extend a session** and **Connect a device** links. These reuse the existing screens and action handlers; there is no second approval/extension path. Search has an explicit label and stays usable without JavaScript. Home keeps pending-request cards and active-session Extend actions ahead of optional checklist/phone reminders.

System status is near the top of both pages, starting as not checked rather than assuming health. Existing authenticated polling retains stale/unavailable/error feedback. Pending blocklist reviews and failed refresh counts appear outside expandable sections, linking to the existing review workflow; merely viewing them does not apply or dismiss anything.

More groups restrictions, devices/account, history and server/troubleshooting tools. Infrequent server settings, DNS/performance, updates and encrypted recovery sit inside **Deployment & maintenance**, a native details/summary control usable by keyboard without JavaScript. System status, client diagnostics, support reports and unfinished setup remain directly discoverable. Existing destructive confirmations and primary current-section indicators remain unchanged.

Task regression tests verify search wiring, retained destinations, daily-work ordering, attention counts and unchanged approval/extension behavior. Responsive rules stack search/actions on narrow screens, retain visible focus and use at least 44px shortcut targets. Rendered synthetic templates are available for visual review; browser security/network restrictions in the development environment prevented the local visual preview from opening, so physical phone/desktop visual acceptance remains an operator check.
