# Client connection diagnostics

Open **System → Client diagnostics**, choose an enabled restricted hostname and download the standalone Python client. Run it on the affected computer, using the same Wi-Fi/VPN connection as its browser. Install its only dependency with `python -m pip install dnspython`, then use the command prepared by the page. It contains only your configured hostname, listener IPv4 and portal origin, never credentials.

The tool checks A, AAAA, HTTPS and SVCB via the system-configured resolver, gateway TCP reachability, verified SNI/hostname TLS, the unauthenticated redirect to the configured portal and its code-entry page. It uses no cookies, never redeems a code, never follows an unapproved redirect and does not bypass TLS verification. The transient normal gateway entry expires through the existing entry lifecycle. Reports contain generic layer states/guidance only; no names, client IPs, entry tokens, cookies, codes, response bodies or keys are retained or uploaded.

Wrong/stale A or non-empty AAAA/HTTPS/SVCB: check local DNS mappings, gravity conflicts, browser Secure DNS and cached answers. DNS timeout: check resolver reachability and UDP/TCP 53. Refused/timed-out TCP: inspect VPN routes, firewall and listener. TLS failure: inspect installed CA, hostname and clock. A missing entry redirect may indicate an IP exclusion; a broken portal may indicate its separate DNS/TLS/application path.

`--resolver IP` tests an explicit resolver, not the device's default DNS configuration. `--ca FILE` tests explicit Python trust, not browser trust. Even the default Python trust store can differ from a browser or mobile user-CA store. Do not publish a diagnosis as real-device acceptance until the browser check below succeeds.

## Real-device acceptance

1. Test from an affected Wi-Fi/VPN device outside configured IP exclusions. Check that the intended DNS is selected and no conflicting Secure/Private DNS override is active.
2. Install the portal's device CA. On iOS enable full trust for this root separately. Verify the device clock.
3. Open a private browser window, without an active code or administrator session.
4. Open the selected restricted HTTPS hostname. Expect no certificate warning and a redirect to the code-entry page. Do not enter a code for this check.
5. Record the layer that fails, compare System status and a report run on that device, then repeat after the fix. A report run on the server or another computer cannot establish phone/browser trust.

The administrator page offers these steps for iPhone/iPad/Android as well as desktop clients. Results are not stored by the portal. Actual phone/target-server acceptance must be performed on that installation; automated tests use local fixtures.
