# Phone admin app and access-request notifications

Version 0.14 adds an installable administration PWA and opt-in Web Push. Update normally, then open **Phone app & notifications** in the admin navigation (`/admin/app`). Existing codes, CA, configuration and grants are retained. Schema 10 adds persistent VAPID keys, per-browser subscriptions and queued deliveries.

## Android

1. Connect to the VPN or home network and open the canonical portal's `/admin` in Chrome.
2. Sign in and open **Phone app & notifications**.
3. Use **Install admin app**, when offered, or Chrome's menu → Install app / Add to Home screen.
4. Open the Home Screen icon. Sign in inside that app if necessary, then open **Phone app & notifications**.
5. Press **Enable notifications** and accept the browser/phone permission prompt.
6. Press **Send test**. It uses the same generic new-request alert; it does not create an access request.

## iPhone and iPad

Use iOS/iPadOS 16.4 or later. Open the canonical HTTPS portal in Safari, Share → Add to Home Screen, then launch that new icon. Sign in inside the installed app, open **Phone app & notifications**, and explicitly enable notifications there. Enabling them in an ordinary Safari tab is not the supported iOS workflow. Safari and the installed app may have separate login/storage state.

The manifest starts at `/admin` in standalone display mode, with generated 192/512px icons and a scoped service worker. Browser installation UI varies: if the install button is absent, use the browser's menu. This is a web app, not an App Store/native app or a promise that the private portal can be packaged as a WebAPK.

## What an alert does

A background service sends a standard VAPID-authenticated, **empty-body** Web Push signal to the subscribed browser's push provider. The service worker displays fixed text: **New access request. Open administration to review pending requests.** The portal does not send the domain, reason, visitor address, code, request ID or admin credentials in the push message. A test uses this same generic text. Provider acceptance means accepted for delivery, not proof that the phone displayed it.

Tapping opens `/admin/requests?state=pending`. Open the request and use the existing timed **Approve / Deny** controls. A notification is not an access grant and never bypasses sign-in or CSRF. Alerts are grouped into one request-notification tag, so several requests may share one visible notification. The normal inbox remains authoritative.

The admin tab does not have to remain open. The phone needs Internet access to its OS/browser push service. The server requires outbound HTTPS to the subscription provider. Opening the private portal still needs VPN/local connectivity: do not expose `/admin` publicly just for notifications. If VPN is disconnected, the alert may arrive but opening the portal can fail until VPN reconnects. Phone power policies, Focus/Do Not Disturb, browser force-stop and OS notification settings can delay or suppress delivery.

## Trust, permissions and login lifetime

- Use the same canonical HTTPS portal address consistently. The device must fully trust its certificate/retained CA. Clicking past a certificate warning is insufficient for a service worker. If registration fails, check the displayed error, device CA trust, VPN, canonical URL and browser support. No insecure-certificate bypass is introduced.
- Permission is requested only from an Enable button click. No automatic permission prompt, background subscription or automatic test is performed.
- Subscriptions are bound to this browser identity and its live administrator login. Logout, seven idle days, password/security-policy changes or restore prevent new deliveries. Notifications and delivery checks do not renew the login. After signing in again, open this page and press Enable again to bind the browser subscription to the new login.
- Enable separately in each app/browser installation. **Disable on this browser** deletes its server subscriptions/queued work and unsubscribes locally. Already accepted provider notifications can still arrive briefly; they contain generic text only. A denied OS/browser permission must be reset in that system's settings.
- No admin HTML, credentials, APIs, code output or submitted forms are cached. Offline navigation shows a static VPN/network hint; POST actions are never queued or replayed offline.

## Server behavior and troubleshooting

`access-gate-push.service` runs as the existing unprivileged `accessgate` user. It checks the SQLite queue every two seconds. New requests enqueue deliveries transactionally; repeated submissions of the same pending request do not create another notification. The worker skips resolved/stale requests, validates current login policy without renewal and claims work with a lease to avoid ordinary concurrent duplicates. Retries are bounded to three attempts for transient/network/429/5xx errors. Jobs expire after ten minutes; provider TTL is five minutes. Ambiguous network failure or worker interruption can result in a duplicate generic alert; delivery is best effort, not an exactly-once guarantee.

404/410 subscriptions are removed. Other failures appear as sanitized errors on the notification page; refresh after a test. Endpoint capability URLs and private signing keys are not returned through the admin API or included in activity logs. Up to 32 subscriptions are supported. Supported endpoint hosts are exactly `fcm.googleapis.com`, `updates.push.services.mozilla.com` and `web.push.apple.com`; other providers are rejected rather than accepting arbitrary outbound destinations. HTTPS certificates are verified, environment proxies/redirects are disabled, requests contain no payload and have five-second timeouts.

VAPID keys are generated once in the private database and retained across updates. The default public VAPID contact URI is this project's `https://github.com/CoyWorks/Access-Gate`; a different operator/fork should set `push_contact` in root-owned `/etc/access-gate/config.json` to a real `mailto:` or public `https:` contact URI and restart the push service. This contact is visible to the push provider. Do not use a localhost placeholder, which Apple may reject. No Firebase project, Apple developer account, mail relay or additional Python package is required for this payload-free implementation.

Check **System status**, then as root:

```bash
systemctl status access-gate-push
journalctl -u access-gate-push --no-pager -n 50
```

Pi-hole/firewall rules must allow the supported push providers for the server and the phone's OS/browser. Restores remove all saved push subscriptions and queued deliveries; explicitly enable notifications again after recovery. Backups from an earlier schema require a matching application version for initial restore, followed by the normal update.

## Validation and references

Automated tests cover durable opt-in delivery, duplicate requests, concurrent workers, restart, retry limits, gone subscriptions, stale/decided requests, logout/expiry/policy invalidation, no idle-login renewal, endpoint allowlisting, ES256 VAPID signatures/audience/expiry, empty-body HTTPS sending, protected subscription routes, manifest/icons and worker scope. Dependency-free Node tests cover no automatic permission/subscription, enable/test/disable, generic background alerts, fixed same-origin click targets and offline behavior. Real phone installation and provider delivery require the operator's Send test check; no live push to a user's device is claimed by local tests.

Primary references:
- [WebKit: Web Push for Web Apps on iOS and iPadOS](https://webkit.org/blog/13878/)
- [Apple: Sending web push notifications](https://developer.apple.com/documentation/usernotifications/sending-web-push-notifications-in-web-apps-and-browsers)
- [RFC 8292: VAPID](https://www.rfc-editor.org/rfc/rfc8292.html)
- [Web Push implementation documentation: payload-free support](https://github.com/web-push-libs/web-push)
