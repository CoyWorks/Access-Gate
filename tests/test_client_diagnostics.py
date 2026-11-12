import json,ssl,unittest
from unittest.mock import patch,MagicMock
import dns.resolver
from access_gate.client_diagnostics import run_checks
from test_browser_portal import BrowserWebFixture


class Answer(list):
    @property
    def rrset(self):return self if self else None


class ClientDiagnosticsTests(unittest.TestCase):
    def run_case(self,*,dns_error=None,wrong=False,tls_error=None,network_error=None,bad_redirect=False,portal_failure=False):
        resolver=MagicMock()
        resolver.resolve.side_effect=dns_error or (lambda host,kind,**kw:Answer(['1.1.1.1' if wrong else '10.40.22.5'] if kind=='A' else []))
        responses=[(302,'https://portal.example/?entry=private-token',b''),(502 if portal_failure else 200,'',b'<input id="code">')]
        if bad_redirect:responses[0]=(302,'https://evil.example/?entry=private-token',b'')
        with patch('dns.resolver.Resolver',return_value=resolver),patch('socket.create_connection',side_effect=network_error or None),patch('access_gate.client_diagnostics.get_page',side_effect=tls_error or responses) as fetch:
            result=run_checks('restricted.example','10.40.22.5','https://portal.example')
        return result,fetch

    def test_success_and_report_contains_no_target_cookie_or_entry(self):
        result,_=self.run_case();self.assertTrue(result['success']);self.assertEqual(len(result['layers']),8)
        for secret in ('10.40.22.5','restricted.example','portal.example','private-token'):
            self.assertNotIn(secret,json.dumps(result))

    def test_additional_ca_keeps_default_roots(self):
        resolver=MagicMock();resolver.resolve.side_effect=lambda host,kind,**kw:Answer(['10.40.22.5'] if kind=='A' else [])
        with patch('dns.resolver.Resolver',return_value=resolver),patch('socket.create_connection'),patch('ssl.create_default_context') as trust,patch('access_gate.client_diagnostics.get_page',side_effect=[(302,'https://portal.example/?entry=token',b''),(200,'',b'<input id="code">')]):
            self.assertTrue(run_checks('restricted.example','10.40.22.5','https://portal.example',ca_file='extra-ca.crt')['success'])
            trust.assert_called_once_with();trust.return_value.load_verify_locations.assert_called_once_with(cafile='extra-ca.crt')

    def test_wrong_dns_timeout_network_tls_and_redirect_are_distinct(self):
        result,_=self.run_case(wrong=True);self.assertEqual(result['layers'][0]['state'],'failed')
        result,_=self.run_case(dns_error=dns.resolver.LifetimeTimeout());self.assertEqual(result['layers'][0]['state'],'unknown')
        result,_=self.run_case(network_error=ConnectionRefusedError());self.assertEqual(result['layers'][4]['state'],'failed')
        result,_=self.run_case(tls_error=ssl.SSLCertVerificationError());self.assertEqual(result['layers'][5]['state'],'failed')
        result,fetch=self.run_case(bad_redirect=True);self.assertEqual(fetch.call_count,1);self.assertEqual(result['layers'][-1]['state'],'unknown')
        result,_=self.run_case(portal_failure=True);self.assertFalse(result['success']);self.assertEqual(result['layers'][-1]['state'],'failed')


class ClientDiagnosticsWebTests(BrowserWebFixture,unittest.TestCase):
    def test_admin_only_download_and_configured_client_steps(self):
        self.assertEqual(self.request('/admin/client-diagnostics').status_code,302)
        self.assertEqual(self.request('/admin/client-diagnostics/download').status_code,302)
        self.request('/admin/login','POST',dict(csrf=self.csrf(),password='admin'))
        self.app.extensions['store'].add_dns_domains('example.com')
        result=self.request('/admin/client-diagnostics?hostname=www.example.com')
        self.assertEqual(result.status_code,200);self.assertIn(b'--hostname www.example.com',result.data)
        self.assertEqual(self.request('/admin/client-diagnostics?hostname=unmanaged.example').status_code,400)
        response=self.request('/admin/client-diagnostics/download');source=response.data;response.close()
        self.assertIn(b'def run_checks',source);self.assertNotIn(b'from .',source)
