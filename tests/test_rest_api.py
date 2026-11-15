import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from werkzeug.security import generate_password_hash
from access_gate.core import Store,GateError
from access_gate.web import create_app


class APICase(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        (self.root/'domains').write_text('example.org\n')
        self.config=dict(secret='test-secret',pepper='test-pepper',acl_token='internal-secret',
            database=str(self.root/'gate.sqlite'),domains=str(self.root/'domains'),
            client_networks=['192.0.2.0/24'],admin_networks=['192.0.2.0/24'],
            portal_url='https://access.example.org',admin_hash=generate_password_hash('test-password'))
        self.app=create_app(self.config);self.app.config['TESTING']=True
        self.store=self.app.extensions['store'];self.store.initialize();self.client=self.app.test_client()
        self.identity,self.token=self.store.create_integration('Automation',['batches:create'])

    def tearDown(self):self.temp.cleanup()

    def enable(self):
        with self.store.connect() as db:db.execute('UPDATE api_policy SET enabled=1,networks=?',(json.dumps(['192.0.2.0/24']),))

    def call(self,path='/api/v1/batches',method='POST',token=None,**kwargs):
        headers={'X-Real-IP':'192.0.2.20','X-Gate-HTTPS':'1','Authorization':'Bearer '+(token or self.token)}
        headers.update(kwargs.pop('headers',{}))
        return self.client.open(path,method=method,base_url='https://access.example.org',
            environ_overrides={'REMOTE_ADDR':'127.0.0.1'},headers=headers,**kwargs)

    def login(self):
        browser='a'*64
        login,_=self.store.new_admin_login(browser,self.config)
        self.client.set_cookie('__Host-accessgate-browser',browser,domain='access.example.org',secure=True)
        self.client.set_cookie('__Host-accessgate-admin',login,domain='access.example.org',secure=True)
        with self.client.session_transaction(base_url='https://access.example.org') as session:
            session['csrf']='test-csrf'


class CredentialTests(APICase):
    def test_only_hash_and_safe_metadata_are_stored(self):
        with self.store.connect() as db:
            row=dict(db.execute('SELECT * FROM api_credentials').fetchone())
        self.assertNotIn(self.token,json.dumps(row));self.assertNotIn('digest',self.store.integration_list()[0])
        self.assertEqual(row['digest'],self.store.api_digest(self.token))

    def test_expiry_revocation_scopes_and_source_policy(self):
        self.assertIsNotNone(self.store.authenticate_integration(self.token,'192.0.2.20'))
        self.assertIsNone(self.store.authenticate_integration(self.token,'192.0.2.20',time.time()+366*86400))
        self.store.revoke_integration(self.identity)
        self.assertIsNone(self.store.authenticate_integration(self.token,'192.0.2.20'))
        for scopes in ([],['admin'],['batches:create','batches:create']):
            with self.assertRaises(GateError):self.store.create_integration('Bad',scopes)
        _,token=self.store.create_integration('Restricted',['batches:create'],cidrs='198.51.100.0/24')
        self.assertFalse(self.store.authenticate_integration(token,'192.0.2.20')['source_allowed'])

    def test_api_is_disabled_by_default_and_never_redirects(self):
        response=self.call()
        self.assertEqual(response.status_code,404);self.assertEqual(response.mimetype,'application/json')
        self.assertEqual(response.json['request_id'],response.headers['X-Request-ID'])
        self.assertNotIn('Set-Cookie',response.headers)

    def test_bearer_auth_does_not_accept_browser_or_internal_keys(self):
        self.enable();self.login()
        for token in ('wrong',self.config['acl_token']):
            response=self.call(token=token)
            self.assertEqual(response.status_code,401)
            self.assertIn('WWW-Authenticate',response.headers)
            self.assertNotIn('Set-Cookie',response.headers)
        self.assertEqual(self.call('/internal/check',method='GET').status_code,403)
        self.store.revoke_integration(self.identity)
        self.assertEqual(self.call().status_code,401)

    def test_credential_management_requires_password_admin_and_csrf(self):
        self.login()
        payload=dict(action='create',name='Second',days='30',scopes='batches:create',csrf='test-csrf',current_password='test-password')
        response=self.call('/admin/integrations',data=payload)
        self.assertEqual(response.status_code,200)
        self.assertIn(b'Copy this credential now',response.data)
        self.assertNotIn(b'Copy this credential now',self.call('/admin/integrations',method='GET').data)
        self.assertEqual(len(self.store.integration_list()),2)
        payload.pop('csrf')
        self.assertEqual(self.call('/admin/integrations',data=payload).status_code,400)
        payload['csrf']='test-csrf';payload['current_password']='wrong'
        self.assertEqual(self.call('/admin/integrations',data=payload).status_code,400)

    def test_migration_repeat_and_future_schema_protection(self):
        self.store.initialize()
        self.assertIsNotNone(self.store.authenticate_integration(self.token,'192.0.2.20'))
        with self.store.connect() as db:db.execute('PRAGMA user_version=99')
        with self.assertRaises(GateError):self.store.initialize()


class GenerationTests(APICase):
    def setUp(self):
        super().setUp();self.enable()
        self.ready=patch('access_gate.rest_api.GENERATION_READY',True);self.ready.start();self.addCleanup(self.ready.stop)
        self.headers={'Idempotency-Key':'test-generation-operation-1'}

    def generate(self,body=None,**kwargs):
        return self.call(json={} if body is None else body,headers=self.headers,**kwargs)

    def test_generated_codes_use_normal_redemption_and_admin_counts(self):
        response=self.generate(dict(name='External',count=10,validity_value=7,validity_unit='days',access_value=15,access_unit='minutes'))
        self.assertEqual(response.status_code,201,response.json)
        data=response.json;self.assertEqual(len(data['codes']),10)
        self.assertEqual(data['access_seconds'],900);self.assertEqual(data['validity_seconds'],604800)
        self.assertEqual(self.store.api_origin(data['batch_id']),self.identity)
        self.assertEqual(self.store.batch_detail(data['batch_id'])['total'],10)
        code=data['codes'][0]['code']
        now=time.time();end=self.store.redeem(code,'192.0.2.20',now=now,browser_token='b'*64)
        self.assertEqual(end,now+900)
        with self.assertRaises(GateError):self.store.redeem(code,'192.0.2.21',browser_token='c'*64)
        self.store.revoke_batch(data['batch_id'])
        self.assertIsNone(self.store.browser_grant('b'*64))
        self.assertNotIn('Set-Cookie',response.headers)

    def test_validation_is_atomic_and_rejects_wrong_types_units_and_unknown_fields(self):
        for body in ({'count':True},{'count':'10'},{'count':1.5},{'count':1001},{'access_unit':'days'},
                     {'validity_value':366},{'profile_id':'default'},[],{'count':10**300}):
            with self.subTest(body=body):self.assertEqual(self.generate(body).status_code,400)
        self.assertEqual(self.store.list_batches()['total'],0)

    def test_json_media_type_size_and_retry_key_validation(self):
        for raw in ('{"count":1,"count":2}','{"count":NaN}','null','[1]'):
            self.assertEqual(self.call(data=raw,content_type='application/json',headers=self.headers).status_code,400)
        self.assertEqual(self.call(data='{}',headers=self.headers).status_code,415)
        self.assertEqual(self.call(json={}).status_code,400)
        self.assertEqual(self.call(data=' '*16385,content_type='application/json',headers=self.headers).status_code,413)
        self.assertEqual(self.call('/api/v1/batches?count=1',json={},headers=self.headers).status_code,400)
        self.assertEqual(self.call(method='GET').status_code,405)
        self.assertEqual(self.call('/api/v1/unknown').status_code,404)
