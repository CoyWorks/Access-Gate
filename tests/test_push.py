import base64
import concurrent.futures
import hashlib
import json
import struct
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from access_gate.core import GateError
from access_gate.push import endpoint_url,authorization,send_push
from access_gate.pwa import icon
from test_browser_portal import BrowserWebFixture

ENDPOINT='https://fcm.googleapis.com/fcm/send/private-capability-token'
def decode(value):return base64.urlsafe_b64decode(value+'='*((4-len(value)%4)%4))


class PushTests(BrowserWebFixture,unittest.TestCase):
    def enable(self,owner='a'*64,endpoint=ENDPOINT,now=None):
        now=time.time() if now is None else now
        token,login=self.store.new_admin_login(owner,self.config,now=now)
        sid=self.store.save_push(owner,login['id'],endpoint,self.config,now)
        return sid,token,login
    def request_new(self,owner='b'*64,now=None):return self.store.submit_request(owner,'10.40.22.30',reason='Private reason',now=now)
    def count(self,table):
        with self.store.connect() as db:return db.execute('SELECT count(*) FROM '+table).fetchone()[0]
    def test_opt_in_only_and_new_request_queue_is_transactional_and_deduplicated(self):
        self.request_new();self.assertEqual(self.count('push_deliveries'),0)
        self.enable();rid,created=self.request_new('c'*64);self.assertTrue(created)
        same,created=self.request_new('c'*64);self.assertEqual(same,rid);self.assertFalse(created);self.assertEqual(self.count('push_deliveries'),1)
        calls=[];self.store.deliver_push(self.config,sender=lambda *args:calls.append(args) or 201)
        self.assertEqual(len(calls),1);self.assertEqual(len(calls[0]),3);self.assertNotIn('Private reason',str(calls));self.assertNotIn(rid,str(calls))
        with self.store.connect() as db:self.assertEqual(db.execute('SELECT status FROM push_deliveries').fetchone()[0],'sent')
    def test_logout_expiry_and_policy_change_disable_delivery_without_renewal(self):
        for mode in ('logout','expiry','policy'):
            with self.subTest(mode=mode):
                self.store.disable_push('a'*64);sid,token,login=self.enable();self.store.test_push('a'*64,self.config)
                if mode=='logout':self.store.end_admin_login(token,'a'*64)
                elif mode=='expiry':
                    with self.store.connect() as db:db.execute('UPDATE admin_logins SET expires=? WHERE id=?',(time.time()-1,login['id']))
                else:self.store.save_admin_security(self.config,networks=['10.40.0.0/16'])
                calls=[];self.store.deliver_push(self.config,sender=lambda *args:calls.append(args) or 201)
                self.assertEqual(calls,[])
        sid,token,login=self.enable();before=self.store.admin_login(token,'a'*64,self.config)['expires']
        self.store.test_push('a'*64,self.config);self.store.deliver_push(self.config,sender=lambda *args:201)
        self.assertEqual(self.store.admin_login(token,'a'*64,self.config)['expires'],before)
    def test_queue_restart_and_concurrent_workers_claim_once(self):
        self.enable();self.request_new();self.store.initialize();calls=[]
        def worker(_):self.store.deliver_push(self.config,sender=lambda *args:calls.append(args) or 201)
        with concurrent.futures.ThreadPoolExecutor(3) as pool:list(pool.map(worker,range(3)))
        self.assertEqual(len(calls),1)
    def test_expired_provider_subscription_is_removed(self):
        self.enable();self.request_new();self.store.deliver_push(self.config,sender=lambda *args:410)
        self.assertEqual(self.count('push_subscriptions'),0);self.assertEqual(self.count('push_deliveries'),0)
    def test_transient_error_retries_bounded_and_does_not_log_endpoint(self):
        now=time.time();self.enable(now=now);self.request_new(now=now)
        calls=[]
        def fail(*args):calls.append(args);raise RuntimeError(ENDPOINT+' SECRET')
        for offset in (0,1,16,77,300):self.store.deliver_push(self.config,sender=fail,now=now+offset)
        self.assertEqual(len(calls),3)
        with self.store.connect() as db:
            row=db.execute('SELECT status,attempts FROM push_deliveries').fetchone();self.assertEqual(tuple(row),('failed',3))
        self.assertNotIn(ENDPOINT,str(self.store.push_state('a'*64,self.config)));self.assertNotIn('SECRET',str(self.store.push_state('a'*64,self.config)))
    def test_decided_and_stale_requests_do_not_send_late_alerts(self):
        now=time.time();self.enable(now=now);rid,_=self.request_new(now=now);self.store.decide_request(rid,'deny')
        calls=[];self.store.deliver_push(self.config,sender=lambda *a:calls.append(a) or 201,now=now+1);self.assertEqual(calls,[])
        self.request_new('c'*64,now);self.store.deliver_push(self.config,sender=lambda *a:calls.append(a) or 201,now=now+601);self.assertEqual(calls,[])
    def test_endpoint_validation_blocks_ssrf_and_cross_browser_takeover(self):
        for endpoint in ('http://fcm.googleapis.com/a','https://127.0.0.1/a','https://example.org/a','https://fcm.googleapis.com.evil.org/a','https://fcm.googleapis.com:444/a','https://user@fcm.googleapis.com/a','https://fcm.googleapis.com/a\nheader','https://fcm.googleapis.com/a#fragment'):
            with self.assertRaises(GateError):endpoint_url(endpoint)
        self.enable()
        token,other=self.store.new_admin_login('b'*64,self.config)
        with self.assertRaises(GateError):self.store.save_push('b'*64,other['id'],ENDPOINT,self.config)
    def test_vapid_signature_and_audience_are_correct_and_key_is_stable(self):
        with self.store.connect() as db:private,public=db.execute('SELECT private_key,public_key FROM push_settings').fetchone()
        self.store.initialize()
        self.assertEqual(public,self.store.push_state('a'*64,self.config)['public_key'])
        auth=authorization(private,ENDPOINT,'https://portal.example',now=1000)
        jwt=auth.split('t=',1)[1].split(',')[0];header,payload,signature=jwt.split('.')
        claims=json.loads(decode(payload));self.assertEqual(claims['aud'],'https://fcm.googleapis.com');self.assertEqual(claims['exp'],4600)
        raw=decode(signature);r=int.from_bytes(raw[:32],'big');s=int.from_bytes(raw[32:],'big')
        key=serialization.load_pem_private_key(private,password=None)
        key.public_key().verify(encode_dss_signature(r,s),(header+'.'+payload).encode(),ec.ECDSA(hashes.SHA256()))
        self.assertEqual(len(decode(public)),65)
    def test_sender_uses_empty_body_verified_https_no_redirects_and_timeout(self):
        with self.store.connect() as db:private=db.execute('SELECT private_key FROM push_settings').fetchone()[0]
        with patch('access_gate.push.build_opener') as build:
            build.return_value.open.return_value.__enter__.return_value.status=201
            self.assertEqual(send_push(ENDPOINT,private,'https://portal.example'),201)
            args,kwargs=build.return_value.open.call_args;request=args[0]
            self.assertEqual(request.data,b'');self.assertEqual(request.get_method(),'POST');self.assertEqual(kwargs['timeout'],5)
            self.assertEqual(request.get_header('Ttl'),'300');self.assertNotIn('Content-encoding',request.headers)
    def test_disable_removes_queued_deliveries_and_test_requires_opt_in(self):
        with self.assertRaises(GateError):self.store.test_push('a'*64,self.config)
        self.enable();self.request_new();self.store.disable_push('a'*64)
        self.assertEqual(self.count('push_subscriptions'),0);self.assertEqual(self.count('push_deliveries'),0)


class PushWebTests(BrowserWebFixture,unittest.TestCase):
    def login(self):self.request('/admin/login','POST',dict(csrf=self.csrf(),password='admin'))
    def test_manifest_worker_and_icons_work_before_signin_but_no_private_data(self):
        response=self.request('/admin/manifest.webmanifest');self.assertEqual(response.status_code,200)
        self.assertEqual(response.json['start_url'],'/admin');self.assertEqual(response.json['display'],'standalone')
        worker=self.request('/admin/sw.js');self.assertEqual(worker.headers['Service-Worker-Allowed'],'/admin');self.assertIn(b'showNotification',worker.data);self.assertNotIn(b'caches.open',worker.data);worker.close()
        for size in (192,512):
            png=self.request('/admin/icon-'+str(size)+'.png');self.assertEqual(png.mimetype,'image/png');self.assertEqual(struct.unpack('!II',png.data[16:24]),(size,size))
        self.assertEqual(self.request('/admin/app').status_code,302);self.assertEqual(self.request('/admin/api/push').status_code,302)
    def test_enable_and_test_require_login_csrf_and_browser_binding(self):
        self.login();self.assertEqual(self.request('/admin/app').status_code,200)
        self.assertEqual(self.request('/admin/api/push','POST',dict(action='enable',endpoint=ENDPOINT)).status_code,400)
        response=self.request('/admin/api/push','POST',dict(csrf=self.csrf(),action='enable',endpoint=ENDPOINT));self.assertEqual(response.status_code,200)
        self.assertTrue(response.json['devices']);self.assertNotIn('private-capability',str(response.json));self.assertNotIn('private_key',str(response.json))
        self.assertEqual(self.request('/admin/api/push','POST',dict(csrf=self.csrf(),action='test')).status_code,200)
        self.assertEqual(self.request('/admin/api/push','POST',dict(csrf=self.csrf(),action='disable')).json['devices'],[])
