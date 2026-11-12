import base64,hashlib,json,plistlib,re,unittest
from pathlib import Path
from unittest.mock import patch
from cryptography.hazmat.primitives import hashes,serialization
from access_gate.client_profiles import apple_profile,windows_script,identity
from access_gate.deployment import normalize
from gateway_fixtures import ca,write_pair
from test_browser_portal import BrowserWebFixture


class ProfileTests(BrowserWebFixture,unittest.TestCase):
    def setUp(self):
        super().setUp();self.c=normalize(self.config);self.cert,key=ca('Profile CA');self.ca=self.root/'public-ca';write_pair(self.cert,key,self.ca,self.root/'unread.key')
    def test_apple_payloads_exact_certificate_stable_identity_and_origin(self):
        data=apple_profile(self.c,self.ca);profile=plistlib.loads(data)
        self.assertEqual(data,apple_profile(self.c,self.ca));self.assertFalse(profile['PayloadRemovalDisallowed'])
        certificate,shortcut=profile['PayloadContent']
        self.assertEqual(certificate['PayloadType'],'com.apple.security.root');self.assertEqual(certificate['PayloadContent'],self.cert.public_bytes(serialization.Encoding.DER))
        self.assertEqual(shortcut['PayloadType'],'com.apple.webClip.managed');self.assertTrue(shortcut['IsRemovable']);self.assertEqual(shortcut['URL'],self.c['portal_url']+'/')
        self.assertNotIn(b'BEGIN PRIVATE KEY',data)
        old_identifier=profile['PayloadIdentifier'];changed_cert,key=ca('Rotated CA');write_pair(changed_cert,key,self.ca,self.root/'unread.key')
        changed=plistlib.loads(apple_profile(self.c,self.ca));self.assertEqual(changed['PayloadIdentifier'],old_identifier);self.assertNotEqual(changed['PayloadContent'][0]['PayloadContent'],certificate['PayloadContent'])
        self.assertNotEqual(identity(self.c),identity(dict(self.c,portal_url='https://other.example')))
    def test_windows_public_payload_and_owned_only_guardrails(self):
        script=windows_script(self.c,self.ca).decode();encoded=re.search("FromBase64String\\('([A-Za-z0-9+/=]+)'\\)",script).group(1);payload=json.loads(base64.b64decode(encoded))
        self.assertEqual(payload['RootSha256'],self.cert.fingerprint(hashes.SHA256()).hex().upper())
        self.assertEqual(base64.b64decode(payload['Certificate']),self.cert.public_bytes(serialization.Encoding.DER))
        self.assertEqual(set(payload),{'RootSha256','Portal','Deployment','Certificate'})
        for required in ("$Action = 'Inspect'",'-not $ConfirmTrust',"'Root','CurrentUser'",'$state.OwnedRoot -eq $true','$otherReferences.Count -eq 0','$state.OwnedShortcut -eq $true','$existingCertificates.Count -eq 0','-ceq $settings.RootSha256','-cne $shortcutContent','$state.RootSha256 -cne $settings.RootSha256'):
            self.assertIn(required,script)
        for forbidden in ('LocalMachine','Set-DnsClientServerAddress','Set-ExecutionPolicy','Invoke-WebRequest','-ExecutionPolicy Bypass','BEGIN PRIVATE KEY','gateway-key'):
            self.assertNotIn(forbidden,script)
        self.assertEqual(windows_script(self.c,self.ca),windows_script(self.c,self.ca))
    def test_downloads_hashes_and_public_authority_rejection(self):
        with patch('access_gate.web.PUBLIC_CA',self.ca):
            for platform,path,kind in [('ios','/setup/apple.mobileconfig','apple'),('windows','/setup/windows.ps1','windows')]:
                response=self.request(path);self.assertEqual(response.status_code,200);data=response.data;response.close()
                page=self.request('/setup?platform='+platform);self.assertEqual(page.status_code,200)
                self.assertIn(hashlib.sha256(data).hexdigest().upper().encode(),page.data);self.assertIn(path.encode(),page.data)
        for builder in (apple_profile,windows_script):
            with self.assertRaises(ValueError):builder(dict(self.c,public_portal=True),self.ca)
