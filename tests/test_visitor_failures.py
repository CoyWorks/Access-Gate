import unittest
from unittest.mock import patch
from access_gate.failures import page,portal_origin,MESSAGES
from access_gate.core import GateError
from test_browser_portal import BrowserWebFixture

class FailureTests(BrowserWebFixture,unittest.TestCase):
    def test_fixed_pages_and_invalid_origins_never_reflect_untrusted_text(self):
        for value in ('javascript:alert(1)','https://good.example/?SECRET','https://user:SECRET@good.example','https://good.example/evil'):
            self.assertIsNone(portal_origin(value));self.assertNotIn('SECRET',page('origin',value))
        for kind in MESSAGES:
            html=page(kind,'https://10.40.22.5');self.assertIn('name="viewport"',html)
            self.assertIn('https://10.40.22.5/setup',html);self.assertNotIn('<script',html)
    def test_public_expired_entry_and_http_errors_have_recovery_links(self):
        for path,status in [('/?entry=invalid',400),('/does-not-exist',404)]:
            response=self.request(path);self.assertEqual(response.status_code,status)
            self.assertIn(b'Device setup',response.data);self.assertNotIn(b'Traceback',response.data)
        self.assertFalse(self.store.list_grants())
    def test_public_gate_error_never_discloses_exception_and_ended_reason_is_allowlisted(self):
        with patch.object(self.store,'entry',side_effect=GateError('SECRET arbitrary details')):
            response=self.request('/?entry=invalid');self.assertNotIn(b'SECRET',response.data)
        page=self.request('/?reason=ended');self.assertIn(b'expired or was revoked',page.data)
        self.assertNotIn(b'<script>',self.request('/?reason=%3Cscript%3E').data)
