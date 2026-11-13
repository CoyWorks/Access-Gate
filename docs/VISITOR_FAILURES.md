# Visitor failure pages

Gateway recovery pages are self-contained and work without JavaScript, external styles or an available portal backend. Overload and policy/authorization/portal outages return 503 with a short Retry-After; a failed verified HTTPS origin returns 502; invalid handoffs return 400; host/device boundary failures retain their original status. Fixed messages never show raw upstream exceptions, credentials or requested URLs.

Expired/revoked access still redirects through the existing authority-generated entry and challenge. The code portal explains that access ended. Recovery links start from configured portal origins; arbitrary return URLs are not accepted. A failed handoff asks the visitor to reopen the original website, rather than reconstructing a destination from input. Local failure pages never grant access or consume a code.

After stream/WebSocket response headers have been sent, expiry, revocation or failed authorization closes the connection as before. It is impossible to replace an already started response safely with an HTML error page. TLS failures before HTTP, untrusted CAs and SNI/policy failures during the TLS handshake remain browser/connection errors. Device setup and client diagnostics cover those cases.

Failure counters are fixed-label process-local aggregates, reset on gateway restart. They contain no domains, URLs, client addresses, cookies or exception strings. Site-origin HTTP error responses themselves remain the website's response.
