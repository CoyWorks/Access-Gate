import json
import secrets
import time
import unittest
from unittest.mock import patch
from werkzeug.security import generate_password_hash
from access_gate.core import GateError
from access_gate.exclusions import ADMIN_IDLE_SECONDS,exclusion_networks
from access_gate.web import ADMIN_COOKIE,BROWSER_COOKIE,create_app
from test_browser_portal import BrowserWebFixture


class ExclusionStoreTests(BrowserWebFixture,unittest.TestCase):
    def create_login(self,now=1000,browser='a'*64):
        return self.store.new_admin_login(browser,self.config,now=now)
    def site(self,login,now=1000,target='https://example.org'):
        nonce='c'*64;entry=self.store.new_entry(target,nonce,now)
        origin,ticket=self.store.issue_admin_handoff(entry,login['id'],self.config,now)
        return self.store.accept_admin_handoff(ticket,nonce,origin,self.config,now)
    def test_login_seven_day_idle_renewal_and_no_passive_renewal(self):
        token,login=self.create_login()
        self.assertEqual(login['expires'],1000+7*86400)
        self.assertEqual(self.store.admin_login(token,'a'*64,self.config,now=2000)['expires'],login['expires'])
        renewed=self.store.admin_login(token,'a'*64,self.config,touch=True,now=2000)
        self.assertEqual(renewed['expires'],2000+ADMIN_IDLE_SECONDS)
        self.assertIsNone(self.store.admin_login(token,'a'*64,self.config,touch=True,now=renewed['expires']))
    def test_login_requires_two_browser_bound_proofs_and_logout_blocks_replay(self):
        token,login=self.create_login();proof=self.site(login)
        self.assertIsNone(self.store.admin_login(token,'b'*64,self.config,now=1001))
        self.assertIsNone(self.store.admin_login(proof['token'],'a'*64,self.config,now=1001))
        self.store.end_admin_login(token,'a'*64)
        self.assertIsNone(self.store.admin_login(token,'a'*64,self.config,now=1001))
        self.assertIsNone(self.store.admin_site_grant(proof['token'],'https://example.org',self.config,now=1001))
    def test_site_activity_renews_server_idle_but_watcher_does_not(self):
        token,login=self.create_login();proof=self.site(login)
        self.assertEqual(self.store.admin_site_grant(proof['token'],'https://example.org',self.config,now=2000)['expires'],login['expires'])
        live=self.store.admin_site_grant(proof['token'],'https://example.org',self.config,activity=True,now=2000)
        self.assertEqual(live['expires'],2000+ADMIN_IDLE_SECONDS)
        self.assertEqual(self.store.admin_login(token,'a'*64,self.config,now=2001)['expires'],live['expires'])
        self.assertIsNone(self.store.admin_site_grant(proof['token'],'https://other.org',self.config,now=2001))
        self.assertIsNone(self.store.admin_site_grant(proof['token'],'https://example.org',self.config,activity=True,now=live['expires']))
    def test_handoff_is_nonce_origin_bound_single_use_and_settings_revoke(self):
        token,login=self.create_login();nonce='d'*64
        entry=self.store.new_entry('https://example.org',nonce,1000)
        target,ticket=self.store.issue_admin_handoff(entry,login['id'],self.config,1000)
        for wrong_nonce,wrong_origin in (('e'*64,target),(nonce,'https://other.org')):
            with self.assertRaises(GateError):self.store.accept_admin_handoff(ticket,wrong_nonce,wrong_origin,self.config,1000)
        proof=self.store.accept_admin_handoff(ticket,nonce,target,self.config,1000)
        with self.assertRaises(GateError):self.store.accept_admin_handoff(ticket,nonce,target,self.config,1000)
        self.store.save_admin_security(self.config,password_hash=generate_password_hash('changed-password'))
        self.assertIsNone(self.store.admin_login(token,'a'*64,self.config,now=1001))
        self.assertIsNone(self.store.admin_site_grant(proof['token'],target,self.config,now=1001))
    def test_new_login_and_restart_keep_revocation_consistent(self):
        token,login=self.create_login();proof=self.site(login)
        self.store.initialize()
        self.assertIsNotNone(self.store.admin_site_grant(proof['token'],'https://example.org',self.config,now=1001))
        self.create_login(now=1002)
        self.assertIsNone(self.store.admin_login(token,'a'*64,self.config,now=1003))
        self.assertIsNone(self.store.admin_site_grant(proof['token'],'https://example.org',self.config,now=1003))
    def test_exclusions_validate_exact_ips_network_boundaries_and_ipv6(self):
        nets=exclusion_networks('10.40.32.20/32\n10.40.33.0/24\n2001:db8:1::/64')
        self.store.save_admin_security(self.config,exclusions=nets)
        for value in ('10.40.32.20','10.40.33.255','2001:db8:1::1'):self.assertTrue(self.store.ip_excluded(value,self.config))
        for value in ('10.40.32.21','10.40.34.1','2001:db8:2::1',None,'spoofed'):self.assertFalse(self.store.ip_excluded(value,self.config))
        self.assertEqual(exclusion_networks(''),[])
        for value in ('10.40.32.20/24','bad','10.40.32.1/33'):
            with self.assertRaises(GateError):exclusion_networks(value)
    def test_login_proofs_are_not_stored_in_plaintext(self):
        token,login=self.create_login();proof=self.site(login)
        with self.store.connect() as db:dump=' '.join(db.iterdump())
        for secret in (token,proof['token'],'a'*64):self.assertNotIn(secret,dump)


class ExclusionWebTests(BrowserWebFixture,unittest.TestCase):
    def login(self,portal=False,entry=''):
        return self.request('/admin/login','POST',dict(csrf=self.csrf(),password='admin',portal='1' if portal else '0',entry=entry))
    def api_check(self,host='example.org',address=None,activity=False):
        headers={'X-Gate-Key':'gateway-key','X-Gate-Origin':'https://'+host}
        if address is not None:headers['X-Gate-Client-IP']=address
        if activity:headers['X-Gate-Activity']='1'
        return self.client.get('/internal/gateway/check',base_url='http://127.0.0.1:8088',headers=headers,environ_overrides={'REMOTE_ADDR':'127.0.0.1'})
    def test_portal_has_login_link_and_login_returns_to_portal_without_code(self):
        self.assertIn(b'>Sign in</a>',self.request().data)
        self.assertEqual(self.login(portal=True).headers['Location'],'/')
        page=self.request();self.assertIn(b'Access unrestricted',page.data)
        self.assertNotIn(b'name="code"',page.data)
        self.assertEqual(self.request('/status').json['kind'],'admin')
        self.assertEqual(self.store.list_batches()['total'],0)
    def test_portal_login_preserves_website_entry_and_creates_origin_bound_site_cookie(self):
        nonce='d'*64;entry=self.store.new_entry('https://example.org',nonce)
        result=self.login(portal=True,entry=entry)
        self.assertEqual(result.headers['Location'],'/continue?entry='+entry)
        self.assertEqual(self.request(result.headers['Location']).status_code,200)
        callback=self.request('/?entry='+entry).headers['Location']
        ticket=callback.split('ticket=')[1]
        proof=self.rpc('/internal/handoff',dict(ticket=ticket,nonce=nonce,origin='https://example.org'))
        self.assertEqual(proof.status_code,200)
        self.assertEqual(self.rpc('/internal/check',dict(token=proof.json['token'],origin='https://example.org')).status_code,200)
        self.assertEqual(self.store.list_batches()['total'],0)
    def test_logout_revokes_cookie_replay_and_site_proofs_without_affecting_code_grant(self):
        self.login();raw=self.client.get_cookie(ADMIN_COOKIE,domain='10.40.22.5').value
        browser=self.client.get_cookie(BROWSER_COOKIE,domain='10.40.22.5').value
        admin=self.store.admin_login(raw,browser,self.config)
        nonce='e'*64;entry=self.store.new_entry('https://example.org',nonce)
        target,ticket=self.store.issue_admin_handoff(entry,admin['id'],self.config)
        proof=self.store.accept_admin_handoff(ticket,nonce,target,self.config)
        _,codes=self.store.create_batch(count=1)
        self.store.redeem(codes[0],'10.40.135.11',browser_token=browser)
        expiry=self.store.browser_grant(browser)['expires']
        self.assertEqual(self.request('/logout','POST',dict(csrf=self.csrf())).status_code,302)
        self.assertIsNone(self.client.get_cookie(ADMIN_COOKIE,domain='10.40.22.5'))
        self.assertIsNone(self.store.admin_site_grant(proof['token'],target,self.config))
        self.client.set_cookie(ADMIN_COOKIE,raw,domain='10.40.22.5',secure=True)
        self.assertEqual(self.request('/admin').status_code,302)
        self.assertEqual(self.request('/status').json['kind'],'code')
        self.assertEqual(self.store.browser_grant(browser)['expires'],expiry)
    def test_admin_identity_survives_missing_flask_cookie_but_not_idle_timeout(self):
        self.login();raw=self.client.get_cookie(ADMIN_COOKIE,domain='10.40.22.5').value
        self.client.delete_cookie('session',domain='10.40.22.5')
        self.assertEqual(self.request('/admin').status_code,200)
        with self.store.connect() as db:db.execute('UPDATE admin_logins SET expires=?',(time.time()-1,))
        self.assertEqual(self.request('/admin').status_code,302)
        self.assertIsNone(self.client.get_cookie(ADMIN_COOKIE,domain='10.40.22.5'))
    def test_background_status_and_admin_api_polls_do_not_renew_login(self):
        self.login()
        with self.store.connect() as db:db.execute('UPDATE admin_logins SET expires=?',(time.time()+100,))
        self.request('/status');self.request('/admin/api/sessions')
        with self.store.connect() as db:expiry=db.execute('SELECT expires FROM admin_logins WHERE revoked=0').fetchone()[0]
        self.assertLess(expiry,time.time()+110)
        self.request('/')
        with self.store.connect() as db:renewed=db.execute('SELECT expires FROM admin_logins WHERE revoked=0').fetchone()[0]
        self.assertGreater(renewed,time.time()+ADMIN_IDLE_SECONDS-5)
    def test_exclusion_settings_require_password_csrf_and_keep_admin_networks_separate(self):
        self.login();before=self.store.admin_security(self.config)
        form=dict(csrf=self.csrf(),version=before['version'],action='exclusions',current_password='admin',exclusions='10.40.32.20/32\n10.40.33.0/24')
        self.assertEqual(self.request('/admin/settings','POST',dict(form,current_password='bad')).status_code,400)
        self.assertEqual(self.request('/admin/settings','POST',form).status_code,302)
        after=self.store.admin_security(self.config);self.assertEqual(before['networks'],after['networks'])
        self.assertEqual(after['exclusions'],['10.40.32.20/32','10.40.33.0/24'])
        self.assertEqual(self.request('/',ip='10.40.32.20').status_code,200)
        self.assertIn(b'IP exclusion',self.request('/',ip='10.40.32.20').data)
        self.assertEqual(self.request('/admin',ip='10.40.32.20').status_code,302)
    def test_ip_exception_requires_private_trusted_peer_and_managed_domain(self):
        self.store.add_dns_domains('example.org')
        self.store.save_admin_security(self.config,exclusions=['10.40.32.20/32'])
        self.assertEqual(self.api_check(address='10.40.32.20').status_code,200)
        self.assertEqual(self.api_check(address='10.40.32.21').status_code,401)
        self.assertEqual(self.api_check(address='10.40.32.20',host='other.org').status_code,403)
        self.assertEqual(self.rpc('/internal/check',dict(ip='10.40.32.20',origin='https://example.org')).status_code,401)
        result=self.client.get('/internal/gateway/check',base_url='http://127.0.0.1:8088',headers={'X-Gate-Origin':'https://example.org','X-Gate-Client-IP':'10.40.32.20'},environ_overrides={'REMOTE_ADDR':'127.0.0.1'})
        self.assertEqual(result.status_code,403)
    def test_code_not_consumed_for_excluded_browser_and_logout_csrf_required(self):
        self.login();_,codes=self.store.create_batch(count=1)
        self.assertEqual(self.request('/','POST',dict(csrf=self.csrf(),code=codes[0])).status_code,303)
        with self.store.connect() as db:self.assertIsNone(db.execute('SELECT used FROM codes').fetchone()[0])
        self.assertEqual(self.request('/logout','POST').status_code,400)
