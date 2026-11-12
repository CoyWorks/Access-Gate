import datetime as dt,json,ssl,unittest
from pathlib import Path
from unittest.mock import patch,AsyncMock
from cryptography.hazmat.primitives import hashes,serialization
from access_gate.onboarding import public_root,setup_context
from access_gate.deployment import normalize,render_http
from access_gate.web import create_app
from gateway_fixtures import ca,write_pair
from test_browser_portal import BrowserWebFixture


class OnboardingTests(BrowserWebFixture,unittest.TestCase):
    def setUp(self):
        super().setUp();cert,key=ca('Device setup test CA');self.cert=cert;self.ca=self.root/'public-ca.crt';write_pair(cert,key,self.ca,self.root/'do-not-read.key')
        self.patcher=patch('access_gate.web.PUBLIC_CA',self.ca);self.patcher.start()
    def tearDown(self):self.patcher.stop();super().tearDown()
    def test_public_platform_steps_fingerprint_no_secrets_or_activation(self):
        for platform,text in [('ios',b'full trust'),('android',b'Some apps do not trust'),('windows',b'Current User')]:
            page=self.request('/setup?platform='+platform);self.assertEqual(page.status_code,200);self.assertIn(text,page.data)
            self.assertIn(self.cert.fingerprint(hashes.SHA256()).hex().upper().encode(),page.data)
            for secret in (b'gateway-key',b'BEGIN PRIVATE KEY',b'pepper'):self.assertNotIn(secret,page.data)
        self.assertFalse(self.store.list_grants());self.assertEqual(self.request('/setup?platform=bad').status_code,400)
    def test_selected_test_host_is_validated_and_escaped(self):
        self.store.add_dns_domains('example.com')
        self.assertIn(b'https://www.example.com/',self.request('/setup?platform=ios&hostname=www.example.com').data)
        self.assertEqual(self.request('/setup?hostname=unmanaged.example').status_code,400)
        page=self.request('/setup?hostname=%22%3E%3Cscript%3E');self.assertNotIn(b'<script>',page.data)
    def test_bootstrap_does_not_require_https_or_canonical_host_but_requires_client_network(self):
        page=self.client.get('/setup/bootstrap',base_url='http://10.40.22.5',environ_overrides={'REMOTE_ADDR':'127.0.0.1'},headers={'X-Real-IP':'10.40.135.11'})
        self.assertEqual(page.status_code,200);self.assertIn(b'An HTTP page cannot authenticate',page.data);self.assertNotIn(b'<script',page.data)
        self.assertEqual(self.request('/setup/bootstrap',ip='203.0.113.4').status_code,403)
        conf=normalize(self.config);http=render_http(conf);self.assertIn('location = /setup/bootstrap',http)
    def test_invalid_missing_ca_and_public_authority_do_not_offer_incorrect_ca(self):
        self.ca.write_text('invalid');page=self.request('/setup?platform=ios');self.assertEqual(page.status_code,200);self.assertIn(b'missing, invalid or expired',page.data)
        info=setup_context(normalize(dict(self.config,public_portal=True)),self.ca);self.assertIsNone(info['ca']);self.assertTrue(info['authority'])
        with patch('access_gate.onboarding.read_regular',side_effect=AssertionError('Authority must not read private-gateway CA')):
            setup_context(normalize(dict(self.config,public_portal=True)),self.ca)
    def test_public_root_contains_only_der_and_metadata(self):
        info=public_root(self.ca);self.assertEqual(info['der'],self.cert.public_bytes(serialization.Encoding.DER));self.assertNotIn('private',info)
