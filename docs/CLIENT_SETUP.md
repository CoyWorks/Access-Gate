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

## Installation artifacts

The iPhone/iPad and Windows tabs offer downloadable installation artifacts over trusted HTTPS. Before the CA is trusted, use the local HTTP bootstrap's manual CA steps or obtain the artifact through an already trusted administrator device/channel; do not disable TLS verification to download executable code. Both the CA fingerprint and complete file SHA-256 hashes appear on the setup page. When bootstrapping, obtain verification values independently from the administrator. Artifacts contain public data only and are not CMS/code-signed; platform warnings and device policies must be respected.

### Apple profile

`/setup/apple.mobileconfig` contains exactly two removable payloads: `com.apple.security.root` with the DER public root certificate, and `com.apple.webClip.managed` with the canonical visitor portal URL. Profile/payload identifiers and UUIDs remain stable for one portal origin, so a new certificate replaces the same deployment profile rather than creating a new identity. Changing the portal origin creates a different deployment identity; remove the old profile deliberately. Review the payload list, install, then manually enable full SSL/TLS trust. Removing the configuration profile removes its payloads; inspect device certificate settings if a CA had been installed separately. No MDM, VPN, DNS, passcode or restrictions payload is included.

### Windows script

`/setup/windows.ps1` embeds the public DER certificate, exact SHA-256 fingerprint, canonical portal URL and a deployment identifier. It makes no network requests. Default `-Action Inspect` is read-only; `-Action Install -ConfirmTrust` explicitly adds only a missing certificate in the **CurrentUser Root** store and creates a deployment-specific desktop URL shortcut. No administrator elevation or DNS/VPN/Windows execution-policy changes are requested. Unsigned scripts may be disallowed by device policy; use manual certificate installation instead of weakening that policy.

An ownership record under `%LOCALAPPDATA%/AccessGate` preserves whether this installation actually added each item. Repeat installation retains that record. `-Action Remove -ConfirmTrust` removes only the same fingerprint if this setup owned it and no other setup references it, and only an unchanged owned shortcut. Pre-existing certificates, altered shortcuts and unrelated trust remain. Failed installation attempts remove only additions from that attempt. A changed CA refuses to overwrite the old ownership record: keep the previous script for explicit removal and obtain fresh verification from the administrator. If another setup references the same CA, conservative cleanup can leave that CA installed.

### Acceptance on personal devices

Automated tests decode profile certificates, check payload boundaries/identity, validate download hashes and Windows public-data/ownership guardrails. A Windows PowerShell runtime is not available in the development environment; source/format checks are not a claim of successful Windows installation. On a disposable Windows test user, inspect and install twice, verify there is one matching root and shortcut, remove twice and verify pre-existing trust/modified shortcuts survive. On iPhone/iPad, inspect the two payloads, install, enable full trust and perform the browser test. Android retains manual user-CA installation and browser/application limitations.
