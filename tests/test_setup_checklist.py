import json
import unittest
from unittest.mock import patch
from access_gate.core import Store,GateError
from access_gate.deployment import normalize
from access_gate.recovery import invalidate
from test_browser_portal import BrowserWebFixture


class ChecklistTests(BrowserWebFixture,unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.config=normalize(self.config)
        self.ca_patch=patch('access_gate.onboarding.public_root',return_value={'sha256':'A'*64})
        self.ca_patch.start()
        self.store.add_dns_domains('example.org')
    def tearDown(self):self.ca_patch.stop();super().tearDown()
    def view(self,config=None,ca='A'*64):return self.store.setup_checklist(config or self.config,ca)
    def change(self,action='done',step='server',ack='1',hostname='',config=None,ca='A'*64,revision=None):
        return self.store.change_setup(config or self.config,ca,revision or self.view()['revision'],action,step,hostname,ack)
    def login(self):self.request('/admin/login','POST',dict(csrf=self.csrf(),password='admin'))
    def test_new_checklist_is_unknown_and_never_grants_or_changes_configuration(self):
        before=json.dumps(self.config,sort_keys=True)
        _,codes=self.store.create_batch(count=1)
        self.assertEqual(self.view()['confirmed'],0)
        for step,_ in [('server',None),('dns',None),('domain',None),('device',None),('client',None)]:
            self.change(step=step,hostname='www.example.org')
        self.assertTrue(self.view()['complete']);self.assertFalse(self.store.list_grants())
        with self.store.connect() as db:self.assertIsNone(db.execute('SELECT used FROM codes WHERE digest=?',(self.store.digest(codes[0]),)).fetchone()[0])
        self.assertEqual(before,json.dumps(self.config,sort_keys=True))
    def test_explicit_ack_required_and_selected_domain_must_be_live(self):
        for args in (dict(ack=''),dict(step='domain',hostname='unmanaged.example'),dict(step='domain',hostname='https://example.org'),dict(step='client')):
            with self.assertRaises(GateError):self.change(**args)
        self.change(step='domain',hostname='www.example.org')
        self.store.change_dns_domain('example.org','disable')
        with self.assertRaises(GateError):self.change(step='client')
        self.assertEqual(self.view()['steps'][2]['state'],'needs-review')
    def test_skip_reset_defer_and_return_survive_restart(self):
        self.change();self.change('skip','dns');self.change('hide','')
        other=Store(self.store.path,'pepper');other.initialize();other.initialize()
        saved=other.setup_checklist(self.config,'A'*64)
        self.assertEqual(saved['confirmed'],1);self.assertEqual(saved['skipped'],1);self.assertTrue(saved['hidden']);self.assertFalse(saved['complete'])
        self.change('reset','server');self.change('show','')
        self.assertEqual(self.view()['confirmed'],0);self.assertFalse(self.view()['hidden'])
    def test_stale_revision_cannot_overwrite_progress(self):
        revision=self.view()['revision'];self.change()
        with self.assertRaises(GateError):self.change('skip','server',revision=revision)
        self.assertEqual(self.view()['steps'][0]['state'],'done')
    def test_device_confirmation_requires_available_private_ca(self):
        with self.assertRaises(GateError):self.change(step='device',ca=None)
        self.change(step='domain',hostname='example.org')
        with self.assertRaises(GateError):self.change(step='client',ca=None)
        self.change(step='device',ca=None,config=dict(self.config,public_portal=True))
    def test_config_ca_and_exclusion_changes_require_review_without_reset_on_version(self):
        for step in ('server','dns','domain','device','client'):self.change(step=step,hostname='www.example.org')
        self.assertTrue(self.view(dict(self.config,version='next'))['complete'])
        ca_view=self.view(ca='B'*64)
        self.assertEqual([s['state'] for s in ca_view['steps']],['done','done','done','needs-review','needs-review'])
        changed=self.view(dict(self.config,portal_aliases=['new.example.org']))
        self.assertTrue(all(s['state']=='needs-review' for s in changed['steps']))
        self.store.save_admin_security(self.config,exclusions=['10.40.40.0/24'])
        self.assertEqual(self.view()['steps'][-1]['state'],'needs-review')
    def test_schema12_upgrade_retains_existing_codes_and_settings(self):
        batch,codes=self.store.create_batch(count=1)
        with self.store.connect() as db:
            db.execute('DROP TABLE setup_progress');db.execute('DROP TABLE setup_steps');db.execute('PRAGMA user_version=12')
        self.store.initialize()
        self.assertEqual(self.view()['confirmed'],0);self.assertEqual(self.store.batch_detail(batch)['id'],batch)
        self.assertTrue(self.store.restricted_host('example.org'))
        with self.store.connect() as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0],13)
            self.assertIsNotNone(db.execute('SELECT 1 FROM codes WHERE digest=?',(self.store.digest(codes[0]),)).fetchone())
    def test_restore_resets_acknowledgements_and_reminder_without_losing_hostname(self):
        self.change(step='domain',hostname='www.example.org');self.change('hide','')
        old=self.view()['revision'];invalidate(self.store.path,self.config)
        new=self.view();self.assertEqual(new['confirmed'],0);self.assertFalse(new['hidden'])
        self.assertNotEqual(new['revision'],old);self.assertEqual(new['hostname'],'www.example.org')
    def test_admin_and_csrf_guards_no_public_progress_writes(self):
        old=self.view()['revision']
        self.assertEqual(self.request('/admin/setup').status_code,302)
        self.assertNotEqual(self.request('/admin/setup','POST',dict(csrf=self.csrf(),action='skip',step='server',revision=old)).status_code,303)
        self.login()
        self.assertEqual(self.request('/admin/setup','POST',dict(action='skip',step='server',revision=old)).status_code,400)
        self.assertEqual(self.view()['revision'],old)
        self.assertEqual(self.request('/admin/setup',ip='203.0.113.4').status_code,403)
        response=self.request('/admin/setup','POST',dict(csrf=self.csrf(),action='skip',step='server',revision=old))
        self.assertEqual(response.status_code,303);self.assertEqual(self.view()['skipped'],1)
    def test_checklist_links_unknown_evidence_and_no_local_probe_infers_completion(self):
        self.login()
        with patch.object(self.app.extensions['health'],'snapshot',side_effect=AssertionError('No automatic health probe')):
            page=self.request('/admin/setup')
        self.assertEqual(page.status_code,200);self.assertIn(b'not proof of client trust',page.data)
        for link in (b'/admin/system',b'/admin/dns-domains',b'/setup?',b'/admin/client-diagnostics'):
            self.assertIn(link,page.data)
        with patch.object(self.app.extensions['health'],'snapshot',return_value=dict(version='test',state='healthy',checks=[],checked_at=None,stale=False,scope='local')):
            self.assertEqual(self.request('/admin/system').status_code,200)
        self.assertEqual(self.view()['confirmed'],0)
        with patch('access_gate.onboarding.public_root',side_effect=ValueError('bad certificate')):
            page=self.request('/admin/setup');self.assertIn(b'Unknown / unavailable',page.data)
        self.assertIn(b'/admin/setup',self.request('/admin/more').data)
    def test_public_authority_never_reads_or_claims_private_gateway_ca(self):
        from access_gate.web import create_app
        self.app=create_app(dict(self.config,public_portal=True,public_admin=False))
        self.app.config['TESTING']=True;self.client=self.app.test_client();self.login()
        with patch('access_gate.onboarding.public_root',side_effect=AssertionError('Never read authority CA')):
            page=self.request('/admin/setup')
        self.assertEqual(page.status_code,200)
        self.assertIn(b'public authority',page.data);self.assertIn(b'private gateway',page.data)
        self.assertNotIn(b'Available on server',page.data)
    def test_invalid_actions_and_hostnames_are_never_audited_as_secrets(self):
        for action,step in [('inject-secret','server'),('done','<script>')]:
            with self.assertRaises(GateError):self.change(action,step)
        self.change()
        with self.store.connect() as db:
            row=db.execute("SELECT details FROM activity_events WHERE event='setup.changed'").fetchone()
        self.assertEqual(json.loads(row[0]),{'reason':'server:done'})


if __name__=='__main__':unittest.main()
