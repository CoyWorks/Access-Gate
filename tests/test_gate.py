import concurrent.futures
import datetime as dt
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlparse

from access_gate.core import Store, GateError, TZ, domains
from access_gate.keeper import expire
from access_gate.web import create_app
from werkzeug.security import generate_password_hash


class GateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root/'gate.sqlite'
        self.store = Store(self.path, 'test-pepper')
        self.store.initialize()
        self.now = dt.datetime(2026,11,10,12,tzinfo=TZ).timestamp()

    def tearDown(self):
        self.temp.cleanup()

    def batch(self, week='2026-11-09', count=10):
        return self.store.new_batch(week,count,15,now=self.now)[1]

    def test_batch_ten_unique_no_plaintext(self):
        codes = self.batch()
        self.assertEqual(len(set(codes)), 10)
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM codes').fetchone()[0],10)
            dump = '\n'.join(db.iterdump())
        self.assertNotIn(codes[0],dump)
        self.assertNotIn(codes[0].replace('-',''),dump)

    def test_single_use_across_devices(self):
        code = self.batch()[0]
        self.store.redeem(code,'10.40.135.11',self.now)
        with self.assertRaises(GateError):
            self.store.redeem(code,'10.40.135.12',self.now+1)

    def test_concurrent_single_use(self):
        code = self.batch()[0]
        def use(ip):
            try:
                self.store.redeem(code,ip,self.now)
                return True
            except GateError:
                return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sum(pool.map(use,['10.40.135.11','10.40.135.12'])),1)

    def test_exact_fifteen_minutes(self):
        code = self.batch()[0]
        self.assertEqual(self.store.redeem(code,'10.40.135.11',self.now),self.now+900)
        self.assertIsNotNone(self.store.grant('10.40.135.11',self.now+899))
        self.assertIsNone(self.store.grant('10.40.135.11',self.now+900))

    def test_no_cross_device_access(self):
        self.store.redeem(self.batch()[0],'10.40.135.11',self.now)
        self.assertIsNone(self.store.grant('10.40.135.12',self.now))

    def test_no_stacking_or_code_consumption(self):
        codes=self.batch()
        self.store.redeem(codes[0],'10.40.135.11',self.now)
        with self.assertRaises(GateError):
            self.store.redeem(codes[1],'10.40.135.11',self.now+10)
        self.store.redeem(codes[1],'10.40.135.12',self.now+10)

    def test_future_and_expired_weeks(self):
        code = self.batch('2026-11-16')[0]
        for now in (self.now,dt.datetime(2026,11,23,tzinfo=TZ).timestamp()):
            with self.assertRaises(GateError):
                self.store.redeem(code,'10.40.135.11',now)

    def test_sunday_grant_crosses_week_boundary(self):
        code = self.batch()[0]
        sunday = dt.datetime(2026,11,15,23,55,tzinfo=TZ).timestamp()
        until=self.store.redeem(code,'10.40.135.11',sunday)
        self.assertEqual(dt.datetime.fromtimestamp(until,TZ).isoformat(),'2026-11-16T00:10:00+01:00')

    def test_dst_week_is_local_midnight(self):
        spring = dt.datetime(2026,3,23,tzinfo=TZ).timestamp()
        _, codes = self.store.new_batch('2026-03-23',1,15,now=spring)
        with self.store.connect() as db:
            row=db.execute('SELECT * FROM batches').fetchone()
        self.assertEqual(row['ends']-row['starts'],167*3600)

    def test_revocation_and_expiry_cleanup(self):
        code = self.batch()[0]
        self.store.redeem(code,'10.40.135.11',self.now)
        code_id=self.store.grant('10.40.135.11',self.now)['code']
        self.store.revoke(code_id)
        self.assertIsNone(self.store.grant('10.40.135.11',self.now))
        killed=[]
        expire(self.store,killed.append,self.now+1)
        self.assertEqual(killed,['10.40.135.11'])
        self.assertEqual(self.store.dashboard()[1],[])

    def test_failed_socket_cleanup_keeps_grant_tombstone(self):
        self.store.redeem(self.batch()[0],'10.40.135.11',self.now)
        def fail(_): raise RuntimeError('kill failed')
        with self.assertRaises(RuntimeError): expire(self.store,fail,self.now+901)
        self.assertEqual(len(self.store.dashboard()[1]),1)
        self.assertIsNone(self.store.grant('10.40.135.11',self.now+901))

    def test_persisted_state_not_renewed(self):
        code=self.batch()[0]
        until=self.store.redeem(code,'10.40.135.11',self.now)
        fresh=Store(self.path,'test-pepper')
        fresh.initialize()
        self.assertEqual(fresh.grant('10.40.135.11',self.now+100)['expires'],until)

    def test_attempt_limit(self):
        for _ in range(10): self.assertTrue(self.store.attempt('redeem:ip',10,now=self.now))
        self.assertFalse(self.store.attempt('redeem:ip',10,now=self.now+1))
        self.assertTrue(self.store.attempt('redeem:ip',10,now=self.now+901))

    def test_domain_validation(self):
        path=self.root/'domains.txt'
        path.write_text('example.org\n.example.net\n# comment\n')
        self.assertEqual(domains(path),['example.net','example.org'])
        for value in ('http://example.org','127.0.0.1','example.org;some_directive','a..org'):
            path.write_text(value)
            with self.assertRaises(GateError): domains(path)


class WebTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        root=Path(self.temp.name)
        (root/'domains').write_text('example.org\n')
        self.config=dict(secret='testing-secret',pepper='testing-pepper',acl_token='testing-acl',
                         database=str(root/'gate.sqlite'),domains=str(root/'domains'),
                         pilot_clients=['10.40.135.11/32'],admin_hash=generate_password_hash('test-password'))
        self.app=create_app(self.config)
        self.app.config['TESTING']=True
        self.store=self.app.extensions['store']
        self.store.initialize()
        self.client=self.app.test_client()

    def tearDown(self): self.temp.cleanup()

    def request(self,path='/',method='GET',data=None,headers=None):
        return self.client.open(path,method=method,data=data,base_url='https://10.40.22.5',
            environ_overrides={'REMOTE_ADDR':'127.0.0.1'},headers={'X-Real-IP':'10.40.135.11',**(headers or {})})

    def csrf(self):
        self.request()
        with self.client.session_transaction(base_url='https://10.40.22.5') as session:
            return session['csrf']

    def test_csrf_and_admin_authentication(self):
        self.assertEqual(self.request('/admin').status_code,302)
        self.assertEqual(self.request('/admin/login','POST',{'password':'test-password'}).status_code,400)
        response=self.request('/admin/login','POST',{'password':'test-password','csrf':self.csrf()})
        self.assertEqual(response.status_code,302)
        response=self.request('/admin')
        self.assertEqual(response.status_code,200)
        self.assertIn(b'Manage weekly codes',response.data)

    def test_internal_endpoint_requires_key_and_is_fail_closed(self):
        self.assertEqual(self.request('/internal/check?ip=10.40.135.11').status_code,403)
        self.assertEqual(self.request('/internal/check?ip=10.40.135.11',headers={'X-Gate-Key':'testing-acl'}).data,b'ERR\n')

    def test_redeem_and_safe_redirect(self):
        now=dt.datetime.now(TZ)
        monday=(now.date()-dt.timedelta(days=now.weekday())).isoformat()
        _, codes=self.store.new_batch(monday,2)
        response=self.request('/','POST',{'csrf':self.csrf(),'code':codes[0],'return':'https://example.org/private?secret=abc'})
        self.assertEqual(response.status_code,303)
        self.assertEqual(response.headers['Location'],'https://example.org/')
        self.assertEqual(self.request('/internal/check?ip=10.40.135.11',headers={'X-Gate-Key':'testing-acl'}).data,b'OK\n')
        self.assertEqual(self.request('/internal/check?ip=10.40.135.12',headers={'X-Gate-Key':'testing-acl'}).data,b'ERR\n')
        self.assertNotIn('secret=abc',response.headers['Location'])

    def test_open_redirect_is_rejected_and_code_not_logged_in_url(self):
        today=dt.datetime.now(TZ)
        monday=(today.date()-dt.timedelta(days=today.weekday())).isoformat()
        _, codes=self.store.new_batch(monday,1)
        response=self.request('/','POST',{'csrf':self.csrf(),'code':codes[0],'return':'https://evil.example/'})
        self.assertEqual(response.headers['Location'],'/')
        self.assertNotIn(codes[0],response.headers['Location'])

    def test_unregistered_client_does_not_consume_code(self):
        today=dt.datetime.now(TZ)
        monday=(today.date()-dt.timedelta(days=today.weekday())).isoformat()
        _, codes=self.store.new_batch(monday,1)
        response=self.request('/','POST',{'csrf':self.csrf(),'code':codes[0]},headers={'X-Real-IP':'10.40.135.12'})
        self.assertIn(b'not been registered for the pilot',response.data)
        self.assertIsNone(self.store.dashboard()[0][0]['used'])


if __name__=='__main__': unittest.main()
