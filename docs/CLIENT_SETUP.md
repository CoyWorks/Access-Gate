# Connect a client device

Open the visitor portal and choose **Connect this device**, or open the configured portal's `/setup` page. Administration → More links to the same page. Select iPhone/iPad, Android or Windows; device platform is a choice, not a collected identifier. The page never activates a code or records completion as proof of trust.

## First connection without CA trust

On a configured local/VPN client network, use `http://GATEWAY_IP/setup/bootstrap`. This simple HTTP page needs no stylesheet, JavaScript, password or trusted TLS. It links the existing public CA download and the canonical HTTPS setup page. HTTP cannot authenticate the certificate: compare its SHA-256 fingerprint with a value provided independently by the administrator, for example the server's `openssl x509 -in /etc/access-gate/ca/root.crt -noout -fingerprint -sha256` output. Never ignore a browser TLS warning to complete setup.

The page reads only `/var/lib/access-gate/public/ca.crt`, validates that it is a currently valid self-signed root CA and displays its fingerprint/expiry. Missing, expired or invalid public CA data produces instructions to contact the administrator; setup never regenerates certificates or reads a private key. An existing device CA remains unchanged by onboarding.

## Platform steps

- **iPhone/iPad:** install the downloaded certificate/profile in Settings, then separately enable full SSL/TLS trust under General → About → Certificate Trust Settings. Installing a profile alone does not establish trust. See [Apple's guidance](https://support.apple.com/en-ie/102390).
- **Android:** install it as a CA certificate using the device's security settings. Labels vary by manufacturer. Some applications do not trust user-added CAs even when the browser does.
- **Windows:** install the verified certificate into the current user's Trusted Root Certification Authorities store and reopen the browser. A browser with its own trust store may need separate configuration.

The page explains the selected DNS mode. The optional built-in resolver uses the gateway IP; external/Pi-hole deployments must use the administrator's actual DNS address, not assume the gateway is also DNS. Existing Wi-Fi/VPN setup is retained; no VPN keys or passwords are bundled.

Enter a known enabled restricted hostname to prepare a browser test. Unmanaged/invalid names are rejected. In a private browser window without active access, the expected result is trusted HTTPS followed by the code-entry page. Administrator sign-in or an IP exclusion can skip the code page. No code must be consumed to test. This manual check complements [Client diagnostics](CLIENT_DIAGNOSTICS.md), not automatic proof of device DNS, browser CA trust or VPN enforcement.

## Public authority and remote gateways

A public approval authority does not present its root/enrollment authority as the client's interception CA. Its setup page directs the operator to the correct private gateway. A remote private gateway serves only the narrowly allowlisted setup, public CA and setup assets from its own local backend; ordinary administration/access still redirects to the authority. The local page uses that gateway's public CA copy and local identity. HTTP bootstrap remains restricted to configured client networks, including when the approval portal is public.

Automated tests cover real TLS page delivery, remote route isolation, platform text, fingerprint, CA failures, network boundaries and hostname validation. Installation and full trust in actual iOS/Android/Windows browsers must be accepted on those devices.
