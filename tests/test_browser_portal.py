import concurrent.futures
import importlib.util
import json
from pathlib import Path
import secrets
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

from werkzeug.security import generate_password_hash
from access_gate.core import Store,GateError
from access_gate.browser import origin
from access_gate.settings import validate
from access_gate.web import create_app,BROWSER_COOKIE


class BrowserStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name)
        self.store=Store(self.root/'db','retained-pepper'); self.store.initialize()
        self.now=1000; self.a='a'*64; self.b='b'*64
        self.batch,self.codes=self.store.create_batch(count=3,now=self.now)
    def tearDown(self): self.temp.cleanup()
    def grant(self,token=None):
        token=token or self.a
        self.store.redeem(self.codes[0],'10.40.135.11',self.now,browser_token=token)
        return self.store.browser_grant(token,self.now)
    def entry(self,origin_url='https://example.org'):
        nonce='c'*64
        return self.store.new_entry(origin_url,nonce,self.now),nonce

    def test_two_browsers_on_same_ip_do_not_share_access(self):
        self.grant()
        self.assertIsNone(self.store.browser_grant(self.b,self.now))
        self.store.redeem(self.codes[1],'10.40.135.11',self.now,browser_token=self.b)
        self.assertEqual(len(self.store.list_grants()),2)
        self.assertNotEqual(self.store.browser_grant(self.a,self.now)['code'],self.store.browser_grant(self.b,self.now)['code'])
        self.assertIsNone(self.store.grant('10.40.135.11',self.now))

    def test_browser_continues_across_network_change_without_extra_time(self):
        grant=self.grant()
        self.assertEqual(self.store.browser_grant(self.a,self.now+200)['expires'],grant['expires'])
        with self.assertRaises(GateError): self.store.redeem(self.codes[1],'10.40.22.99',self.now+200,browser_token=self.a)
        with self.store.connect() as db: self.assertIsNone(db.execute('SELECT used FROM codes WHERE digest=?',(self.store.digest(self.codes[1]),)).fetchone()[0])

    def test_expiry_allows_new_code_without_keeper_or_cleanup(self):
        grant=self.grant()
        self.assertIsNone(self.store.browser_grant(self.a,grant['expires']))
        self.store.redeem(self.codes[1],'10.40.22.99',grant['expires'],browser_token=self.a)
        self.assertEqual(self.store.browser_grant(self.a,grant['expires'])['expires'],grant['expires']+900)
        with self.assertRaises(GateError): self.store.redeem(self.codes[0],'10.40.22.98',grant['expires'],browser_token=self.b)

    def test_restart_preserves_original_browser_deadline(self):
        grant=self.grant(); self.store.initialize(); self.store.initialize()
        self.assertEqual(self.store.browser_grant(self.a,self.now+100)['expires'],grant['expires'])

    def test_session_secrets_and_codes_are_never_stored_as_plaintext(self):
        self.grant(); entry,nonce=self.entry(); target,ticket=self.store.issue_handoff(entry,self.a,self.now)
        access=self.store.accept_handoff(ticket,nonce,target,self.now)
        with self.store.connect() as db: dump='\n'.join(db.iterdump())
        for secret in (self.a,nonce,ticket,access['token'],self.codes[0]): self.assertNotIn(secret,dump)

    def test_handoff_succeeds_once_and_is_origin_bound(self):
        grant=self.grant(); entry,nonce=self.entry(); target,ticket=self.store.issue_handoff(entry,self.a,self.now)
        for supplied_nonce,supplied_target in ((self.b,target),(nonce,'https://other.org')):
            with self.assertRaises(GateError): self.store.accept_handoff(ticket,supplied_nonce,supplied_target,self.now)
        access=self.store.accept_handoff(ticket,nonce,target,self.now)
        self.assertEqual(self.store.gateway_grant(access['token'],target,self.now)['expires'],grant['expires'])
        self.assertIsNone(self.store.gateway_grant(access['token'],'https://other.org',self.now))
        with self.assertRaises(GateError): self.store.accept_handoff(ticket,nonce,target,self.now)

    def test_handoff_requires_an_active_browser_session(self):
        entry,_=self.entry()
        with self.assertRaises(GateError): self.store.issue_handoff(entry,self.a,self.now)
        grant=self.grant()
        with self.assertRaises(GateError): self.store.issue_handoff(entry,self.a,grant['expires'])

    def test_ticket_expiry_and_revocation_fail_closed(self):
        grant=self.grant(); entry,nonce=self.entry(); target,ticket=self.store.issue_handoff(entry,self.a,self.now)
        with self.assertRaises(GateError): self.store.accept_handoff(ticket,nonce,target,self.now+60)
        target,ticket=self.store.issue_handoff(entry,self.a,self.now+61)
        self.store.revoke(grant['code'])
        with self.assertRaises(GateError): self.store.accept_handoff(ticket,nonce,target,self.now+61)

    def test_gateway_check_uses_extensions_expiry_and_revocation(self):
        grant=self.grant(); entry,nonce=self.entry(); target,ticket=self.store.issue_handoff(entry,self.a,self.now)
        access=self.store.accept_handoff(ticket,nonce,target,self.now)
        self.store.extend(grant['session_id'],1,'hours','f'*32,now=self.now+1)
        self.assertEqual(self.store.gateway_grant(access['token'],target,self.now+901)['expires'],self.now+4500)
        self.assertIsNone(self.store.gateway_grant(access['token'],target,self.now+4500))
        self.store.revoke_batch(self.batch,self.now+2)
        self.assertIsNone(self.store.gateway_grant(access['token'],target,self.now+2))

    def test_concurrent_handoff_redemption_is_single_use(self):
        self.grant(); entry,nonce=self.entry(); target,ticket=self.store.issue_handoff(entry,self.a,self.now)
        def accept(_):
            try: self.store.accept_handoff(ticket,nonce,target,self.now); return True
            except GateError: return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool: self.assertEqual(sum(pool.map(accept,range(2))),1)

    def test_invalid_return_origins_and_expired_entries(self):
        for value in ('http://example.org','https://127.0.0.1','https://localhost','https://test.local','https://example.org/a','https://example.org/?x=1','https://user@example.org','https://example.org:444','https://exam\nple.org'):
            with self.subTest(value=value),self.assertRaises(GateError): origin(value)
        self.assertEqual(origin('https://BÜCHER.de/'),'https://xn--bcher-kva.de')
        entry,_=self.entry()
        with self.assertRaises(GateError): self.store.entry(entry,self.now+300)


class BrowserWebFixture:
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name)
        self.config=dict(secret='secret',pepper='pepper',acl_token='gateway-key',database=str(self.root/'db'),admin_hash=generate_password_hash('admin'))
        # Old mandatory settings must not activate old identity enforcement anymore.
        self.config.update(require_identity=True,enforcement=True,pilot_clients=['127.0.0.1/32'])
        self.app=create_app(self.config); self.app.config['TESTING']=True
        self.store=self.app.extensions['store']; self.store.initialize()
        self.client=self.app.test_client()
    def tearDown(self): self.temp.cleanup()
    def request(self,path='/',method='GET',data=None,ip='10.40.135.11',client=None):
        return (client or self.client).open(path,method=method,data=data,base_url='https://10.40.22.5',environ_overrides={'REMOTE_ADDR':'127.0.0.1'},headers={'X-Real-IP':ip})
    def csrf(self,client=None):
        self.request(client=client)
        with (client or self.client).session_transaction(base_url='https://10.40.22.5') as state: return state['csrf']
    def activate(self,client=None,ip='10.40.135.11'):
        _,codes=self.store.create_batch(count=1)
        return self.request('/','POST',dict(csrf=self.csrf(client),code=codes[0]),ip=ip,client=client)
    def rpc(self,path,data,key='gateway-key',remote='127.0.0.1'):
        return self.client.post(path,json=data,base_url='http://127.0.0.1:8088',headers={'X-Gate-Key':key},environ_overrides={'REMOTE_ADDR':remote})



class BrowserWebTests(BrowserWebFixture,unittest.TestCase):
    def test_plain_landing_has_only_code_flow_no_registrations(self):
        response=self.request()
        self.assertIn(b'Enter your access code',response.data)
        self.assertNotIn(b'pilot',response.data.lower())
        self.assertNotIn(b'VPN',response.data)
        self.assertEqual(self.activate().status_code,302)
        self.assertTrue(self.request('/status').json['active'])

    def test_wifi_and_vpn_work_without_pre_registered_users(self):
        for ip in ('10.40.135.11','10.40.22.99','10.40.31.10'):
            with self.subTest(ip=ip): self.assertEqual(self.activate(self.app.test_client(),ip).status_code,302)

    def test_same_ip_other_browser_cannot_inherit_access(self):
        self.activate()
        other=self.app.test_client()
        self.assertFalse(self.request('/status',client=other).json['active'])
        self.assertTrue(self.request('/status',ip='10.40.31.99').json['active'])

    def test_browser_cookie_is_secure_host_only_and_http_only(self):
        response=self.request(); cookie=next(v for v in response.headers.getlist('Set-Cookie') if v.startswith(BROWSER_COOKIE+'='))
        for flag in ('Secure','HttpOnly','Path=/','SameSite=Lax'): self.assertIn(flag,cookie)
        self.assertNotIn('Domain=',cookie)
        alias=self.client.get('/status',base_url='https://toegang.coyseinri.nl',headers={'X-Real-IP':'10.40.22.99'},environ_overrides={'REMOTE_ADDR':'127.0.0.1'})
        self.assertEqual(alias.status_code,308)
        self.assertEqual(alias.headers['Location'],'https://10.40.22.5/status')

    def test_admin_login_logout_does_not_reset_browser_access(self):
        self.activate(); end=self.request('/status').json['expires']
        self.request('/admin/login','POST',dict(csrf=self.csrf(),password='admin'))
        response=self.request('/admin')
        self.assertNotIn(b'Devices &amp; users',response.data); self.assertNotIn(b'Restricted domains',response.data)
        self.request('/admin/logout','POST',dict(csrf=self.csrf()))
        self.assertEqual(self.request('/status').json['expires'],end)
        self.assertEqual(self.request('/admin/devices').status_code,404)
        self.assertEqual(self.request('/admin/domains').status_code,404)

    def test_internal_api_requires_local_trusted_key(self):
        for key,remote in (('', '127.0.0.1'),('wrong','127.0.0.1'),('gateway-key','10.40.22.10')):
            self.assertEqual(self.rpc('/internal/entry',{},key,remote).status_code,403)
        self.assertEqual(self.rpc('/internal/check',{'ip':'10.40.135.11'}).status_code,401)

    def test_complete_gateway_flow_without_domain_registration(self):
        result=self.rpc('/internal/entry',dict(origin='https://example.org'))
        nonce=result.json['nonce']
        self.assertEqual(result.status_code,200)
        entry=result.json['login_url'].split('entry=')[1]
        _,codes=self.store.create_batch(count=1)
        response=self.request('/?entry='+entry,'POST',dict(csrf=self.csrf(),code=codes[0],entry=entry))
        self.assertEqual(response.status_code,303)
        target=response.headers['Location']; self.assertTrue(target.startswith('https://example.org/__access_gate/complete?ticket='))
        ticket=target.split('ticket=')[1]
        self.assertNotIn(codes[0],target)
        handoff=self.rpc('/internal/handoff',dict(ticket=ticket,nonce=nonce,origin='https://example.org'))
        self.assertEqual(handoff.status_code,200)
        allowed=self.rpc('/internal/check',dict(token=handoff.json['token'],origin='https://example.org'))
        self.assertTrue(allowed.json['active'])
        self.assertEqual(self.rpc('/internal/check',dict(token=handoff.json['token'],origin='https://other.org')).status_code,401)

    def test_invalid_entry_does_not_consume_code(self):
        _,codes=self.store.create_batch(count=1)
        response=self.request('/','POST',dict(csrf=self.csrf(),code=codes[0],entry='missing'))
        self.assertEqual(response.status_code,400)
        self.assertIsNone(self.store.dashboard()[0][0]['used'])

    def test_active_browser_handoff_does_not_consume_another_code(self):
        self.activate(); end=self.request('/status').json['expires']
        entry=self.rpc('/internal/entry',dict(origin='https://another.org',nonce='e'*64)).json['login_url'].split('entry=')[1]
        self.assertEqual(self.request('/?entry='+entry).status_code,303)
        self.assertEqual(self.request('/status').json['expires'],end)
        self.assertEqual(self.store.list_batches()['total'],1)


class SettingsTests(unittest.TestCase):
    def config(self): return dict(secret='s',pepper='p',admin_hash='h',acl_token='a',database='/db')
    def test_migration_discards_mandatory_vpn_settings_and_admits_wifi_vpn(self):
        config=validate(dict(self.config(),require_identity=True,pilot_clients=['10.40.135.11/32'],enforcement=True,domains='/old'))
        self.assertNotIn('require_identity',config); self.assertNotIn('domains',config)
        self.assertIn('10.40.0.0/16',config['client_networks'])
    def test_invalid_settings_are_rejected(self):
        for data in ({'portal_url':'http://example.org'},{'portal_url':'https://user@example.org/'},{'client_networks':['invalid']},{'client_networks':[]}):
            with self.assertRaises(ValueError): validate(dict(self.config(),**data))


class UpgradeFromV03Tests(unittest.TestCase):
    def test_schema_two_records_are_retained_but_ip_access_is_not_inherited(self):
        with tempfile.TemporaryDirectory() as root:
            store=Store(Path(root)/'db','unchanged-pepper'); store.initialize()
            batch,codes=store.create_batch(count=2,now=1000)
            store.redeem(codes[0],'10.40.135.11',1000,browser_token='a'*64)
            grant=store.browser_grant('a'*64,1000)
            store.extend(grant['session_id'],1,'hours','a'*32,now=1001)
            with store.connect() as db:
                db.execute('DROP TABLE gateway_tokens'); db.execute('DROP TABLE gateway_entries')
                db.execute('INSERT INTO grants_legacy_v03(ip,code,expires,revoked,started,session_id) VALUES(?,?,?,?,?,?)',('10.40.135.11',grant['code'],5500,0,1000,grant['session_id']))
                db.execute('DROP TABLE grants'); db.execute('ALTER TABLE grants_legacy_v03 RENAME TO grants')
                db.execute('ALTER TABLE grants ADD COLUMN device_id TEXT'); db.execute('ALTER TABLE grants ADD COLUMN vpn_binding TEXT')
                db.execute('CREATE TABLE devices(id TEXT PRIMARY KEY,label TEXT)')
                db.execute("INSERT INTO devices VALUES('legacy','Old label')")
                db.execute('CREATE TABLE domain_rules(id TEXT PRIMARY KEY,domain TEXT)')
                db.execute("INSERT INTO domain_rules VALUES('legacy','example.org')")
                db.execute('CREATE TABLE proxy_connections(session_id TEXT REFERENCES grants(session_id),ip TEXT)')
                db.execute('INSERT INTO proxy_connections VALUES(?,?)',(grant['session_id'],'10.40.135.11'))
                db.execute('PRAGMA user_version=2')
            store.initialize(); store.initialize()
            self.assertIsNone(store.grant('10.40.135.11',1002))
            self.assertIsNone(store.browser_grant('a'*64,1002))
            self.assertEqual(len(store.extension_history()),1)
            self.assertEqual(store.list_grants()[0]['revoked'],1)
            with self.assertRaises(GateError): store.redeem(codes[0],'10.40.22.20',1002,browser_token='b'*64)
            store.redeem(codes[1],'10.40.22.20',1002,browser_token='b'*64)
            with store.connect() as db:
                self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(),[])
                self.assertEqual(db.execute('SELECT count(*) FROM devices').fetchone()[0],1)
                self.assertEqual(db.execute('SELECT count(*) FROM domain_rules').fetchone()[0],1)
                self.assertEqual(db.execute('SELECT count(*) FROM proxy_connections').fetchone()[0],1)


class GatewayRedirectTests(BrowserWebFixture,unittest.TestCase):
    def test_gateway_redirect_endpoints_set_host_only_site_cookie(self):
        gateway=self.app.test_client()
        def get(path):
            return gateway.get(path,base_url='https://example.org',headers={'X-Gate-Key':'gateway-key','X-Gate-Origin':'https://example.org'},environ_overrides={'REMOTE_ADDR':'127.0.0.1'})
        begin=get('/internal/start'); self.assertEqual(begin.status_code,302)
        self.assertIn('__Host-accessgate-challenge=',begin.headers['Set-Cookie'])
        entry=begin.headers['Location'].split('entry=')[1]
        self.activate()
        callback=self.request('/?entry='+entry).headers['Location']
        finish=get('/internal/finish?ticket='+callback.split('ticket=')[1])
        self.assertEqual(finish.status_code,303); self.assertEqual(finish.headers['Location'],'https://example.org/')
        self.assertTrue(get('/internal/check').json['active'])
        self.assertEqual(get('/internal/finish?ticket='+callback.split('ticket=')[1]).status_code,400)
        other=self.app.test_client()
        denied=other.get('/internal/check',base_url='https://example.org',headers={'X-Gate-Key':'gateway-key','X-Gate-Origin':'https://example.org'},environ_overrides={'REMOTE_ADDR':'127.0.0.1'})
        self.assertEqual(denied.status_code,401)

    def test_gateway_cookie_is_removed_from_origin_cookie_header(self):
        self.activate(); nonce='f'*64
        entry=self.store.new_entry('https://example.org',nonce)
        token=self.client.get_cookie(BROWSER_COOKIE,domain='10.40.22.5').value
        target,ticket=self.store.issue_handoff(entry,token)
        proof=self.store.accept_handoff(ticket,nonce,target)
        gateway=self.app.test_client(); gateway.set_cookie('__Host-accessgate-site',proof['token'],domain='example.org'); gateway.set_cookie('ordinary_cookie','keep',domain='example.org')
        checked=gateway.get('/internal/check',base_url='https://example.org',headers={'X-Gate-Key':'gateway-key','X-Gate-Origin':'https://example.org'},environ_overrides={'REMOTE_ADDR':'127.0.0.1'})
        self.assertEqual(checked.status_code,200)
        self.assertEqual(checked.headers['X-Gate-Upstream-Cookie'],'ordinary_cookie=keep')


if __name__=='__main__': unittest.main()
