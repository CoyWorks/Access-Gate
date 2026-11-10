import concurrent.futures
import json
import secrets
import time
import unittest
from unittest.mock import patch
from werkzeug.security import generate_password_hash
from access_gate.core import GateError,Store
from access_gate.web import create_app
from test_browser_portal import BrowserWebFixture


class AdministrationTests(BrowserWebFixture,unittest.TestCase):
    def login(self,client=None,password='admin',ip='10.40.135.11'):
        return self.request('/admin/login','POST',dict(csrf=self.csrf(client),password=password),client=client,ip=ip)
    def settings(self,**data):
        form=dict(csrf=self.csrf(),version=self.store.admin_security(self.config)['version'],current_password='admin',action='password',new_password='new-password',confirm_password='new-password')
        form.update(data)
        return self.request('/admin/settings','POST',form)
    def test_management_pages_and_apis_require_admin_and_csrf(self):
        for path in ('/admin/settings','/admin/sessions','/admin/system','/admin/api/health','/admin/api/sessions'):
            self.assertEqual(self.request(path).status_code,302,path)
        self.login()
        self.assertEqual(self.request('/admin/settings','POST',dict(action='password')).status_code,400)
        _,codes=self.store.create_batch(count=1);self.store.redeem(codes[0],'10.40.135.11',browser_token='a'*64)
        sid=self.store.list_grants()[0]['session_id']
        self.assertEqual(self.request('/admin/access/'+sid+'/terminate','POST').status_code,400)
    def test_password_change_invalidates_all_workers_sessions_and_retains_browser_grant(self):
        second_app=create_app(self.config);second_app.config['TESTING']=True
        other=second_app.test_client();self.activate()
        expires=self.request('/status').json['expires']
        self.login(client=other);self.login()
        self.assertEqual(self.settings().status_code,302)
        self.assertEqual(self.request('/admin').status_code,302)
        self.assertEqual(self.request('/admin',client=other).status_code,302)
        self.assertEqual(self.request('/status').json['expires'],expires)
        self.assertIn(b'Incorrect password',self.login().data)
        self.assertEqual(self.login(password='new-password').status_code,302)
        self.assertEqual(self.request('/admin').status_code,200)
        with self.store.connect() as db: text=' '.join(db.iterdump())
        self.assertNotIn('new-password',text)
    def test_invalid_password_and_stale_forms_do_not_change_security(self):
        self.login();before=self.store.admin_security(self.config)
        for overrides in (dict(current_password='wrong'),dict(new_password='short',confirm_password='short'),dict(confirm_password='different'),dict(version='old-version')):
            self.assertEqual(self.settings(**overrides).status_code,400)
            self.assertEqual(self.store.admin_security(self.config),before)
    def test_network_policy_is_separate_and_applies_to_all_admin_routes(self):
        self.login()
        response=self.settings(action='networks',networks='10.40.135.0/24\n127.0.0.1/32')
        self.assertEqual(response.status_code,302)
        for path in ('/admin','/admin/login','/admin/settings','/admin/api/sessions','/admin/api/health','/admin/system'):
            self.assertEqual(self.request(path,ip='10.40.22.99').status_code,403,path)
        self.assertEqual(self.request('/',ip='10.40.22.99').status_code,200)
        self.assertEqual(self.request('/domains.txt',ip='10.40.22.99').status_code,200)
        self.assertEqual(self.login().status_code,302)
        self.assertEqual(self.request('/admin/settings').status_code,200)
    def test_network_policy_prevents_lockout_and_rejects_bad_cidrs(self):
        self.login();before=self.store.admin_security(self.config)
        for networks in ('10.40.22.0/24','invalid','',','.join(['10.0.0.0/8']*65)):
            self.assertEqual(self.settings(action='networks',networks=networks).status_code,400)
            self.assertEqual(self.store.admin_security(self.config),before)
    def test_legacy_admin_cookie_is_not_accepted(self):
        self.csrf()
        with self.client.session_transaction(base_url='https://10.40.22.5') as session:session['admin']=True
        self.assertEqual(self.request('/admin').status_code,302)
    def test_settings_changes_are_atomic_under_stale_concurrent_updates(self):
        version=self.store.admin_security(self.config)['version']
        def save(i):
            try:self.store.save_admin_security(self.config,expected_version=version,password_hash='hash-'+str(i));return True
            except GateError:return False
        with concurrent.futures.ThreadPoolExecutor(2) as pool:self.assertEqual(sum(pool.map(save,range(2))),1)
    def test_sessions_are_sanitized_and_termination_is_per_browser(self):
        self.login()
        _,codes=self.store.create_batch(name='<script>bad</script>',count=2)
        for code,token in zip(codes,['a'*64,'b'*64]):self.store.redeem(code,'10.40.135.11',browser_token=token)
        data=self.request('/admin/api/sessions').json
        self.assertEqual(data['counts']['active'],2)
        text=json.dumps(data)
        for secret in (*codes,'a'*64,'b'*64,'browser_hash','password_hash','digest'):self.assertNotIn(secret,text)
        page=self.request('/admin/sessions');self.assertEqual(page.status_code,200)
        self.assertNotIn(b'<script>bad</script>',page.data)
        sid=data['items'][0]['session_id'];path='/admin/access/'+sid+'/terminate'
        before={r['session_id']:r for r in self.store.list_grants()}
        self.assertEqual(self.request(path).status_code,200)
        self.assertFalse(self.store.list_grants()[0]['revoked'])
        self.assertEqual(self.request(path,'POST',dict(csrf=self.csrf())).status_code,302)
        self.assertEqual(self.request(path,'POST',dict(csrf=self.csrf())).status_code,302)
        rows=self.store.list_grants();self.assertEqual(sum(r['revoked'] for r in rows),1)
        for row in rows:self.assertEqual(row['expires'],before[row['session_id']]['expires'])
        with self.store.connect() as db:self.assertEqual(db.execute('SELECT count(*) FROM codes WHERE used IS NOT NULL AND revoked=0').fetchone()[0],2)
        self.assertEqual(self.request('/admin/api/sessions?state=terminated').json['total'],1)
        self.assertEqual(self.request('/admin/api/sessions').json['total'],1)
    def test_session_filters_pagination_extensions_and_server_time(self):
        self.login();_,codes=self.store.create_batch(count=103)
        for code in codes:self.store.redeem(code,'10.40.135.11',browser_token=secrets.token_hex(32))
        first=self.request('/admin/api/sessions').json;second=self.request('/admin/api/sessions?page=2').json
        self.assertEqual((first['total'],len(first['items']),len(second['items'])),(103,100,3))
        sid=first['items'][0]['session_id'];end=first['items'][0]['expires']
        self.store.extend(sid,1,'hours',secrets.token_hex(16))
        result=self.request('/admin/api/sessions').json
        self.assertEqual(next(r['expires'] for r in result['items'] if r['session_id']==sid),end+3600)
        self.assertAlmostEqual(result['server_time'],time.time(),delta=2)
        self.assertEqual(self.request('/admin/api/sessions?state=bad').status_code,400)
        self.assertEqual(self.request('/admin/api/sessions?page=0').status_code,400)
    def test_health_is_admin_only_cached_and_sanitized(self):
        provider=self.app.extensions['health']
        sample=dict(version='0.6.0',state='warning',checked_at=time.time(),checks=[dict(name='Clock',state='unknown',detail='Not verified.',action='Check server time.')],stale=False,cache_seconds=15,scope='Local checks only.')
        self.login()
        with patch.object(provider,'collect',return_value=sample) as collect:
            self.assertEqual(self.request('/admin/api/health').json['state'],'warning')
            self.assertIn(b'System status',self.request('/admin/system').data)
            self.assertEqual(collect.call_count,1)
        self.assertIn("connect-src 'self'",self.request('/admin/sessions').headers['Content-Security-Policy'])

    def test_login_throttling_and_settings_limits(self):
        for _ in range(5):self.assertIn(b'Incorrect password',self.login(password='wrong').data)
        self.assertIn(b'Too many attempts',self.login().data)
    def test_session_states_and_idempotence_preserve_ended_access(self):
        self.login();_,codes=self.store.create_batch(count=3)
        for code in codes:self.store.redeem(code,'10.40.135.11',browser_token=secrets.token_hex(32))
        rows=self.store.list_grants()
        with self.store.connect() as db:db.execute('UPDATE grants SET expires=? WHERE session_id=?',(time.time()-10,rows[0]['session_id']))
        self.store.revoke(rows[1]['code'])
        self.store.terminate_session(rows[2]['session_id'])
        for state in ('expired','revoked','terminated'):
            self.assertEqual(self.request('/admin/api/sessions?state='+state).json['total'],1)
        self.assertEqual(self.request('/admin/api/sessions').json['total'],0)
        self.assertFalse(self.store.terminate_session(rows[0]['session_id']))
        self.assertEqual(self.request('/admin/access/'+rows[2]['session_id']+'/extend').status_code,400)
    def test_admin_policy_survives_reinitialize_and_does_not_reset_credentials(self):
        saved=self.store.save_admin_security(self.config,password_hash=generate_password_hash('persistent-password'),networks=['10.40.135.0/24'])
        self.store.initialize()
        self.assertEqual(self.store.admin_security(self.config)['version'],saved)
        self.assertEqual(self.login(password='persistent-password').status_code,302)
        self.assertEqual(self.store.admin_security(self.config)['networks'],['10.40.135.0/24'])
