import copy,fcntl,json,os,time,unittest
from pathlib import Path
from unittest.mock import patch
import test_reconfigure
from access_gate.core import GateError
from access_gate.server_settings import ServerSettings,public_settings
from access_gate.maintenance import Jobs
from access_gate.maintenance_worker import Worker
from test_browser_portal import BrowserWebFixture
from test_page_headers import PageStructure


class ServerSettingsFixture:
    def setUp(self):
        test_reconfigure.ReconfigureTests.setUp(self)
        app=self.root/'opt/access-gate';app.mkdir(parents=True);(app/'VERSION').write_text('0.31.0\n')
        self.calls=[];self.worker=Worker(self.root,runner=self.calls.append,gid=os.getgid());self.worker.setup()
        self.changes=ServerSettings(self.root,runner=self.calls.append,gid=os.getgid());self.jobs=Jobs(self.worker.jobs)
        self.host=patch('access_gate.server_settings.local_addresses',return_value=[self.c['listen_ipv4'],'192.168.20.20']);self.host.start()
    def tearDown(self):self.host.stop();test_reconfigure.ReconfigureTests.tearDown(self)
    def review(self,requested=None):
        jid='a'*32;self.preview_id=jid
        version=self.store.admin_security(self.c)['version']
        result=self.changes.review(jid,requested or {'portal_aliases':['new-alias.example']},'192.168.10.45',version)
        return result


class ServerSettingsTests(ServerSettingsFixture,unittest.TestCase):
    def test_private_single_use_review_success_and_state_preservation(self):
        root=(self.base/'ca/root.crt').read_bytes();result=self.review()
        self.assertTrue(result['server_confirm']);self.assertEqual(self.calls,[])
        private=self.worker.private/(self.preview_id+'.server-preview');self.assertEqual(private.stat().st_mode&0o777,0o600)
        serialized=json.dumps(result);self.assertNotIn('policy_version',serialized);self.assertNotIn('configuration',serialized);self.assertNotIn('password_hash',serialized);self.assertNotIn('requested',serialized)
        answer=self.changes.apply(self.preview_id,lambda text:None);self.assertEqual(answer['reconnect_url'],self.c['portal_url'])
        self.assertEqual((self.base/'ca/root.crt').read_bytes(),root)
        with self.store.connect() as db:self.assertEqual(db.execute('SELECT count(*) FROM codes WHERE revoked=0').fetchone()[0],1)
        self.assertTrue(any('access_gate.readiness' in call for call in self.calls))
        with self.assertRaises(GateError):self.changes.apply(self.preview_id,lambda text:None)

    def test_stale_configuration_policy_version_expiry_and_tampered_proposal(self):
        self.review();private=self.worker.private/(self.preview_id+'.server-preview');original=private.read_text()
        saved=(self.base/'config.json').read_text();config=json.loads(saved);config['portal_aliases']=['other.example'];(self.base/'config.json').write_text(json.dumps(config))
        with self.assertRaisesRegex(GateError,'changed'):self.changes.apply(self.preview_id,lambda text:None)
        (self.base/'config.json').write_text(saved)
        record=json.loads(original);record['summary']['checked_at']-=1000;private.write_text(json.dumps(record))
        with self.assertRaisesRegex(GateError,'expired'):self.changes.apply(self.preview_id,lambda text:None)
        private.write_text(original);(self.root/'opt/access-gate/VERSION').write_text('0.31.1\n')
        with self.assertRaisesRegex(GateError,'version changed'):self.changes.apply(self.preview_id,lambda text:None)
        (self.root/'opt/access-gate/VERSION').write_text('0.31.0\n')
        record=json.loads(original);record['requested']['portal_aliases']=['tampered.example'];private.write_text(json.dumps(record))
        with self.assertRaisesRegex(GateError,'inconsistent'):self.changes.apply(self.preview_id,lambda text:None)
        private.write_text(original);self.store.save_admin_security(self.c,exclusions=['192.168.30.0/24'])
        with self.assertRaisesRegex(GateError,'policy'):self.changes.apply(self.preview_id,lambda text:None)
        self.assertEqual(self.calls,[])

    def test_field_allowlist_no_changes_and_management_lockout_prevention(self):
        version=self.store.admin_security(self.c)['version']
        for field in ('secret','pepper','database','dns_mode','web_mode','public_portal','remote_gateway','command'):
            with self.assertRaises(GateError):self.changes.review('b'*32,{field:'bad'},'192.168.10.45',version)
        with self.assertRaisesRegex(GateError,'administrator address'):self.changes.review('b'*32,{'admin_networks':['10.41.0.0/16']},'192.168.10.45',version)
        answer=self.changes.review('b'*32,{},'192.168.10.45',version);self.assertFalse(answer['server_confirm']);self.assertFalse((self.worker.private/('b'*32+'.server-preview')).exists())
        self.assertEqual(self.calls,[])

    def test_unassigned_address_and_listener_conflict_are_rejected_before_changes(self):
        version=self.store.admin_security(self.c)['version']
        with patch('access_gate.server_settings.local_addresses',return_value=[]):
            with self.assertRaises(GateError):self.changes.review('b'*32,{},'192.168.10.45',version)
        requested=dict(server_ipv4='192.168.20.20',listen_ipv4='192.168.20.20',dns_target_ipv4='192.168.20.20',client_networks=['192.168.0.0/16'])
        response=type('Discovery',(),{'stdout':'tcp LISTEN 0 128 192.168.20.20:443 0.0.0.0:*\n'})()
        with patch('access_gate.server_settings.local_addresses',return_value=['192.168.20.20']),patch('access_gate.server_settings.subprocess.run',return_value=response):
            with self.assertRaises(GateError):self.changes.review('b'*32,requested,'192.168.10.45',version)
        self.assertEqual(self.calls,[])

    def test_readiness_failure_restores_configuration_and_consumes_preview(self):
        self.review();before=(self.base/'config.json').read_bytes();fail=[True]
        def runner(args):
            self.calls.append(args)
            if 'access_gate.readiness' in args and fail[0]:fail[0]=False;raise RuntimeError('synthetic readiness failure')
        self.changes.runner=runner
        with self.assertRaisesRegex(GateError,'restored and local readiness passed'):self.changes.apply(self.preview_id,lambda text:None)
        self.assertEqual((self.base/'config.json').read_bytes(),before);self.assertFalse((self.worker.private/(self.preview_id+'.server-preview')).exists())
        with self.store.connect() as db:self.assertEqual(db.execute('SELECT count(*) FROM codes WHERE revoked=0').fetchone()[0],1)

    def test_queue_serialization_unknown_fields_and_public_result(self):
        policy=self.store.admin_security(self.c)['version']
        review=self.jobs.submit('server-check',requested={'portal_aliases':['new.example']},address='192.168.10.45',policy_version=policy)
        self.assertNotIn('requested',self.jobs.status(review));self.assertEqual(self.jobs.status(review)['action'],'server-check')
        with open(self.worker.private/'worker.lock','a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);self.worker.run_once();self.assertEqual(self.jobs.status(review)['state'],'queued')
        self.worker.run_once();self.assertTrue(self.jobs.status(review)['server_confirm'])
        bad=self.jobs.submit('server-apply',preview=review,command='/bin/sh');self.worker.run_once();self.assertEqual(self.jobs.status(bad)['state'],'failed');self.assertEqual(self.calls,[])
        job=self.jobs.submit('server-apply',preview=review);self.worker.run_once();self.assertEqual(self.jobs.status(job)['state'],'complete')
        again=self.jobs.submit('server-apply',preview=review);self.worker.run_once();self.assertEqual(self.jobs.status(again)['state'],'failed')

    def test_policy_commit_failure_rolls_back_files_and_database(self):
        self.review();before=(self.base/'config.json').read_bytes();original=self.store._event
        def fail(db,event,*args,**kwargs):
            if event=='system.reconfigured':raise RuntimeError('synthetic policy transaction failure')
            return original(db,event,*args,**kwargs)
        from access_gate.core import Store
        with patch.object(Store,'_event',side_effect=fail):
            with self.assertRaisesRegex(GateError,'previous configuration was restored'):self.changes.apply(self.preview_id,lambda text:None)
        self.assertEqual((self.base/'config.json').read_bytes(),before)
        self.assertEqual(self.store.admin_security(self.c)['networks'],self.c['admin_networks'])

    def test_live_management_policy_and_shared_nginx_ownership_are_preserved(self):
        self.c=dict(self.c,web_mode='shared-nginx');(self.base/'config.json').write_text(json.dumps(self.c))
        networks=['192.168.0.0/16'];self.store.save_admin_security(self.c,networks=networks)
        before=self.store.admin_security(self.c)['version']
        self.review(dict(portal_aliases=['new.example']))
        self.changes.apply(self.preview_id,lambda text:None)
        after=json.loads((self.base/'config.json').read_text());self.assertEqual(after['web_mode'],'shared-nginx')
        self.assertEqual(self.store.admin_security(after)['version'],before)
        rollback=next((self.root/'var/lib/access-gate/reconfigure').glob('rollback-*/deployment-profile.json'))
        profile=json.loads(rollback.read_text());self.assertEqual(profile['admin_networks'],networks);self.assertNotIn('secret',profile);self.assertEqual(rollback.stat().st_mode&0o777,0o600)
        self.assertFalse(any('nginx.service' in command and ('stop' in command or 'restart' in command) for command in self.calls))

    def test_literal_portal_origin_must_follow_the_selected_listener(self):
        current=dict(self.c,portal_url='https://192.168.10.20')
        with self.assertRaisesRegex(GateError,'portal URL'):
            self.changes.candidate(current,dict(server_ipv4='192.168.20.20',listen_ipv4='192.168.20.20',dns_target_ipv4='192.168.20.20'),'192.168.10.45')

    def test_public_identity_changes_require_root_tls_workflow(self):
        current=dict(self.c,public_portal=True)
        with self.assertRaisesRegex(GateError,'root TLS'):self.changes.candidate(current,{'portal_url':'https://new.example'},'192.168.10.45')

    def test_interrupted_server_apply_is_never_replayed(self):
        jid='b'*32;(self.worker.private/(jid+'.running')).write_text(json.dumps({'action':'server-apply'}))
        self.worker.run_once();result=self.jobs.status(jid)
        self.assertEqual(result['action'],'server-apply');self.assertEqual(result['state'],'failed');self.assertIn('not replayed',result['message']);self.assertEqual(self.calls,[])

    def test_existing_builtin_dns_upstreams_can_change_without_component_switch(self):
        self.c=type(self.c)(self.c,dns_mode='builtin',dns_upstreams=['1.1.1.1']);(self.base/'config.json').write_text(json.dumps(self.c))
        self.review({'dns_upstreams':['9.9.9.9']});self.changes.apply(self.preview_id,lambda text:None)
        self.assertEqual(json.loads((self.base/'dns.json').read_text())['dns_upstreams'],['9.9.9.9'])
        self.assertTrue(any('access_gate.dns_service' in call for call in self.calls))


class ServerSettingsWebTests(BrowserWebFixture,unittest.TestCase):
    def setUp(self):
        super().setUp();self.jobs=self.app.extensions['jobs'];self.jobs.root=self.root/'jobs';(self.jobs.root/'inbox').mkdir(parents=True);(self.jobs.root/'results').mkdir()
    def login(self):self.request('/admin/login','POST',dict(csrf=self.csrf(),password='admin'))
    def form(self):return dict(csrf=self.csrf(),action='review',current_password='admin',server_ipv4='10.40.22.5',portal_url='https://10.40.22.5',portal_aliases='new.example',client_networks='10.40.0.0/16',admin_networks='10.40.0.0/16')
    def test_auth_password_csrf_fields_and_safe_review_queue(self):
        self.assertEqual(self.request('/admin/server-settings').status_code,302);self.login()
        page=self.request('/admin/server-settings');self.assertEqual(page.status_code,200)
        for secret in ('gateway-key','secret','pepper','password_hash'):self.assertNotIn(secret.encode(),page.data)
        data=self.form();data.pop('csrf');self.assertEqual(self.request('/admin/server-settings','POST',data).status_code,400)
        data=self.form();data['current_password']='wrong';self.assertEqual(self.request('/admin/server-settings','POST',data).status_code,400)
        data=self.form();data['secret']='bad';self.assertEqual(self.request('/admin/server-settings','POST',data).status_code,400)
        response=self.request('/admin/server-settings','POST',self.form());self.assertEqual(response.status_code,303)
        record=json.loads(next((self.jobs.root/'inbox').glob('*.json')).read_text());self.assertEqual(record['action'],'server-check');self.assertNotIn('current_password',record)
    def test_review_confirmation_page_uses_settings_chrome_and_queues_only_preview(self):
        self.login();jid='a'*32
        (self.jobs.root/'results'/(jid+'.json')).write_text(json.dumps(dict(id=jid,action='server-check',state='complete',message='Ready',server_confirm=True)))
        page=self.request('/admin/maintenance/'+jid);parser=PageStructure();parser.feed(page.data.decode());self.assertEqual(parser.sections,['Settings']);self.assertIn(b'Type APPLY',page.data)
        data=dict(csrf=self.csrf(),action='apply',current_password='admin',preview=jid,confirm='wrong');self.assertEqual(self.request('/admin/server-settings','POST',data).status_code,400)
        data['confirm']='APPLY';response=self.request('/admin/server-settings','POST',data);self.assertEqual(response.status_code,303)
        record=json.loads(next((self.jobs.root/'inbox').glob('*.json')).read_text());self.assertEqual(record['preview'],jid);self.assertEqual(set(record),{'id','action','created','preview'})
