import json
import threading
import time
import unittest
from html.parser import HTMLParser
from types import SimpleNamespace
from unittest.mock import Mock,patch
from access_gate.deployment import normalize
from access_gate.support_report import SupportReport,blank,encode,MAX_REPORT,stamp
from test_browser_portal import BrowserWebFixture
from gateway_fixtures import ca,write_pair

SECRET='SECRET-CANARY-COOKIE-CODE-CLIENT-URL'

class Fields(HTMLParser):
    def __init__(self,html):super().__init__();self.values={};self.feed(html)
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if tag=='input' and a.get('name'):self.values[a['name']]=a.get('value','')

class ReportTests(BrowserWebFixture,unittest.TestCase):
    def provider(self,**kwargs):
        health=SimpleNamespace(snapshot=Mock(return_value=dict(checked_at=time.time(),stale=False,checks=[dict(name='Portal',state='healthy',detail=SECRET),dict(name=SECRET,state=SECRET)])),
            performance=Mock(return_value=dict(started=time.time(),counters={'failure_origin':2,'failure_portal':SECRET,SECRET:SECRET},urls=[SECRET])))
        return SupportReport(normalize(self.config),health,self.root/'public-ca.crt',root=self.root,**kwargs)
    def test_allowlist_drops_secret_canaries_and_preserves_known_numbers(self):
        p=self.provider()
        with patch('access_gate.support_report.installed',return_value=dict(version='0.36.0',commit='a'*40,deployed_at=1000,secret=SECRET)):
            report=p.collect()
        raw=encode(report);self.assertNotIn(SECRET,raw);self.assertLess(len(raw.encode()),MAX_REPORT)
        self.assertEqual(report['installed']['commit'],'a'*40);self.assertEqual(report['checks'][0]['state'],'healthy')
        self.assertEqual(report['gateway_failures']['counts']['failure_origin'],2)
        self.assertIsNone(report['gateway_failures']['counts']['failure_portal'])
        self.assertEqual(report['diagnostics']['client'],'not-collected')
    def test_public_certificate_subject_not_exported_and_dates_are_real(self):
        cert,key=ca(SECRET);write_pair(cert,key,self.root/'public-ca.crt',self.root/'private-do-not-read.key')
        report=self.provider().collect();root=report['certificates'][0]
        self.assertEqual(root['state'],'published');self.assertGreater(root['expires_at'],time.time())
        self.assertEqual(len(root['sha256']),64);self.assertNotIn(SECRET,encode(report))
    def test_malformed_unavailable_components_are_unknown_not_exception_text(self):
        p=self.provider();p.health.snapshot.side_effect=OSError(SECRET);p.health.performance.return_value={'counters':[]}
        with patch('access_gate.support_report.installed',return_value=dict(version=SECRET,commit=SECRET,deployed_at=float('nan'))):report=p.collect()
        self.assertNotIn(SECRET,encode(report));self.assertEqual(report['installed']['version'],'Unknown')
        self.assertTrue(all(c['state']=='unknown' for c in report['checks']))
        self.assertEqual(report['gateway_failures']['state'],'unknown');self.assertIsNone(stamp(True))
    def test_stale_or_future_health_never_claims_current_success(self):
        p=self.provider();p.health.snapshot.return_value=dict(checked_at=time.time()+3600,stale=False,checks=[dict(name='Portal',state='healthy')])
        self.assertEqual(p.collect()['checks'][0]['state'],'unknown')
        p.health.snapshot.return_value=dict(checked_at=time.time()-30,stale=True,checks=[dict(name='Portal',state='healthy')])
        self.assertEqual(p.collect()['checks'][0]['state'],'unknown')
    def test_collection_deadline_has_no_unbounded_task_queue(self):
        p=self.provider(deadline=.01);release=threading.Event();calls=[]
        def blocked():calls.append(1);release.wait(1);return blank(p.config,'complete')
        with patch.object(p,'collect',side_effect=blocked):
            try:
                start=time.monotonic()
                self.assertEqual(p.capture()['collection'],'deadline-exceeded')
                self.assertEqual(p.capture()['collection'],'deadline-exceeded')
                self.assertEqual(len(calls),1);self.assertLess(time.monotonic()-start,.3)
            finally:release.set();p.future.result(timeout=1)
    def test_public_authority_does_not_read_private_gateway_ca(self):
        p=self.provider();p.config['public_portal']=True
        with patch('access_gate.support_report.certificate',side_effect=AssertionError('Do not read authority CA')):
            self.assertEqual(p.collect()['certificates'][0]['state'],'unknown')
    def login(self,client=None):self.request('/admin/login','POST',dict(csrf=self.csrf(client),password='admin'),client=client)
    def test_admin_csrf_preview_and_exact_signed_download(self):
        self.assertEqual(self.request('/admin/support').status_code,302)
        self.login();self.assertEqual(self.request('/admin/support','POST',dict(action='collect')).status_code,400)
        report=blank(normalize(self.config),'complete');report['installed']['version']='0.36.0'
        with patch.object(self.app.extensions['support_report'],'capture',return_value=report) as collect:
            self.assertEqual(self.request('/admin/support').status_code,200);collect.assert_not_called()
            response=self.request('/admin/support','POST',dict(csrf=self.csrf(),action='collect'))
        fields=Fields(response.data.decode()).values
        result=self.request('/admin/support','POST',dict(csrf=self.csrf(),action='download',preview=fields['preview']))
        self.assertEqual(result.status_code,200);self.assertEqual(json.loads(result.data),report)
        self.assertEqual(result.headers['Cache-Control'],'no-store');self.assertIn('attachment',result.headers['Content-Disposition'])
        self.assertEqual(self.request('/admin/support',ip='203.0.113.4').status_code,403)
        # Preview token is self-contained and portable across application workers.
        self.app.extensions['support_report'].future=None
        self.assertEqual(self.request('/admin/support','POST',dict(csrf=self.csrf(),action='download',preview=fields['preview'])).data,result.data)
    def test_modified_or_other_browser_preview_cannot_be_downloaded(self):
        self.login()
        with patch.object(self.app.extensions['support_report'],'capture',return_value=blank(normalize(self.config),'complete')):
            fields=Fields(self.request('/admin/support','POST',dict(csrf=self.csrf(),action='collect')).data.decode()).values
        token=fields['preview'];other=self.app.test_client();self.login(other)
        self.assertEqual(self.request('/admin/support','POST',dict(csrf=self.csrf(other),action='download',preview=token),client=other).status_code,400)
        self.assertEqual(self.request('/admin/support','POST',dict(csrf=self.csrf(),action='download',preview=token+'tampered')).status_code,400)
