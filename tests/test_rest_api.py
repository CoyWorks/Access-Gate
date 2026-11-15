import json
import concurrent.futures
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
        self.assertEqual(self.call(method='PUT').status_code,405)
        self.assertEqual(self.call('/api/v1/unknown').status_code,404)


class RetryTests(GenerationTests):
    def test_replay_is_stable_and_normalizes_equivalent_units(self):
        first=self.generate().json
        second=self.generate(dict(validity_value=168,validity_unit='hours')).json
        self.assertNotEqual(first.pop('request_id'),second.pop('request_id'))
        self.assertEqual(first,second)
        self.assertEqual(self.store.list_batches()['total'],1)
        self.assertEqual(self.generate().headers['Idempotency-Replayed'],'true')
        self.assertEqual(self.generate({'count':2}).status_code,409)

    def test_parallel_creation_uses_one_transaction_and_one_result(self):
        values=dict(name='Concurrent',count=2,validity_seconds=604800,access_seconds=900)
        def create(_):
            store=Store(self.config['database'],self.config['pepper'])
            return store.api_create_batch(self.identity,'192.0.2.20','parallel-operation-key',values)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results=list(pool.map(create,range(4)))
        self.assertEqual(sum(not replay for _,replay in results),1)
        self.assertTrue(all(result==results[0][0] for result,_ in results))
        self.assertEqual(self.store.list_batches()['total'],1)

    def test_ciphertext_only_restart_recovery_and_expiry(self):
        now=time.time()
        with patch('access_gate.integrations.time.time',return_value=now):first=self.generate().json
        raw=first['codes'][0]['code'].encode()
        with self.store.connect() as db:
            payload=db.execute('SELECT payload FROM api_requests').fetchone()[0]
        self.assertNotIn(raw,payload)
        self.assertNotIn(raw,Path(self.config['database']).read_bytes())
        restarted=Store(self.config['database'],self.config['pepper']);restarted.initialize()
        self.assertEqual(restarted.api_create_batch(self.identity,'192.0.2.20',self.headers['Idempotency-Key'],dict(name='',count=10,validity_seconds=604800,access_seconds=900))[0]['batch_id'],first['batch_id'])
        with patch('access_gate.integrations.time.time',return_value=now+86400):
            response=self.generate()
        self.assertEqual(response.status_code,409)
        self.assertEqual(response.json['error']['code'],'replay_expired')
        self.assertEqual(response.json['error']['batch_id'],first['batch_id'])
        self.store.cleanup_activity(now=now+86401,force=True)
        with self.store.connect() as db:
            self.assertIsNone(db.execute('SELECT payload FROM api_requests').fetchone()[0])

    def test_invalid_ciphertext_and_failed_transaction_never_duplicate(self):
        self.generate()
        with self.store.connect() as db:db.execute('UPDATE api_requests SET payload=?',(b'invalid',))
        self.assertEqual(self.generate().status_code,503)
        self.assertEqual(self.store.list_batches()['total'],1)
        self.headers={'Idempotency-Key':'rolled-back-operation-key'}
        with patch.object(self.store,'api_cipher',side_effect=RuntimeError('private-code-must-not-leak')):
            response=self.generate()
        self.assertEqual(response.status_code,500)
        self.assertNotIn(b'private-code-must-not-leak',response.data)
        self.assertEqual(self.store.list_batches()['total'],1)
        self.assertEqual(self.generate().status_code,201)

    def test_replay_does_not_undo_revocation_or_accept_a_revoked_credential(self):
        first=self.generate().json
        self.store.revoke_batch(first['batch_id'])
        replay=self.generate()
        self.assertEqual(replay.status_code,201)
        with self.assertRaises(GateError):self.store.redeem(replay.json['codes'][0]['code'],'192.0.2.20')
        self.store.revoke_integration(self.identity)
        self.assertEqual(self.generate().status_code,401)


class ExposureTests(GenerationTests):
    def test_api_does_not_read_or_refresh_a_permanent_browser_admin_session(self):
        self.login()
        self.call('/admin/integrations',method='GET')
        with self.client.session_transaction(base_url='https://access.example.org') as session:
            session.permanent=True;session['admin']=True
        with self.store.connect() as db:before=[dict(r) for r in db.execute('SELECT * FROM admin_logins')]
        response=self.generate()
        self.assertEqual(response.status_code,201)
        self.assertNotIn('Set-Cookie',response.headers)
        with self.store.connect() as db:after=[dict(r) for r in db.execute('SELECT * FROM admin_logins')]
        self.assertEqual(before,after)

    def test_unpaired_unicode_and_unacceptable_response_types_fail_without_mutation(self):
        self.assertEqual(self.generate({'name':'\ud800'}).status_code,400)
        response=self.call(json={},headers={**self.headers,'Accept':'application/json;q=0'})
        self.assertEqual(response.status_code,406)
        self.assertEqual(self.store.list_batches()['total'],0)

    def test_networks_and_tls_origin_are_independent_and_fail_closed(self):
        self.assertEqual(self.call(json={},headers={**self.headers,'X-Real-IP':'198.51.100.20','X-Forwarded-For':'192.0.2.20'}).status_code,403)
        self.assertEqual(self.call(json={},headers={**self.headers,'Host':'other.example.org'}).status_code,400)
        response=self.client.post('/api/v1/batches',json={},base_url='http://access.example.org',
            environ_overrides={'REMOTE_ADDR':'127.0.0.1'},headers={'X-Real-IP':'192.0.2.20','Authorization':'Bearer '+self.token,**self.headers})
        self.assertEqual(response.status_code,400);self.assertEqual(response.json['error']['code'],'insecure_transport')
        self.assertNotIn('Location',response.headers)
        with self.assertRaises(GateError):self.store.save_api_policy(True,'')

    def test_limits_survive_store_restart_and_replay_does_not_spend_codes_twice(self):
        response=self.generate({'count':1000});self.assertEqual(response.status_code,201)
        self.assertEqual(self.generate({'count':1000}).status_code,201)
        self.headers={'Idempotency-Key':'another-generation-operation'}
        self.assertEqual(self.generate({'count':1}).status_code,429)
        fresh=Store(self.config['database'],self.config['pepper']);fresh.initialize()
        with fresh.connect() as db:
            self.assertEqual(db.execute("SELECT value FROM api_limits WHERE scope=?",('credential-code:'+self.identity,)).fetchone()[0],1000)
        for _ in range(70):self.store.api_request_budget('192.0.2.99')
        self.assertFalse(fresh.api_request_budget('192.0.2.99'))

    def test_policy_disable_and_credential_cidrs_are_rechecked_under_writer_lock(self):
        from access_gate.rest_api import APIError
        values=dict(name='',count=1,validity_seconds=604800,access_seconds=900)
        self.store.save_api_policy(False,'192.0.2.0/24')
        with self.assertRaises(APIError):self.store.api_create_batch(self.identity,'192.0.2.20','test-revocation-race-key',values)
        self.enable()
        with self.store.connect() as db:db.execute('UPDATE api_credentials SET networks=? WHERE id=?',(json.dumps(['198.51.100.0/24']),self.identity))
        with self.assertRaises(APIError):self.store.api_create_batch(self.identity,'192.0.2.20','test-revocation-race-key',values)

    def test_audit_has_safe_attribution_and_no_credentials_or_codes(self):
        response=self.generate();data=response.json
        rows=self.store.api_audit_list();raw=json.dumps(rows)
        self.assertNotIn(self.token,raw)
        self.assertNotIn(data['codes'][0]['code'],raw)
        self.assertTrue(any(r['credential_id']==self.identity and r['request_id']==data['request_id'] and r['source']=='192.0.2.20' and r['batch_id']==data['batch_id'] for r in rows))


class LifecycleTests(GenerationTests):
    def setUp(self):
        super().setUp()
        from access_gate.integrations import SCOPES
        self.identity,self.token=self.store.create_integration('Full automation',list(SCOPES))

    def test_reads_never_expose_raw_codes_addresses_or_other_credentials_batches(self):
        first=self.generate({'count':3}).json
        _,other=self.store.create_integration('Other',['batches:create','batches:read','batches:revoke'])
        for path in ('/api/v1/batches/'+first['batch_id'],'/api/v1/batches/'+first['batch_id']+'/codes'):
            response=self.call(path,method='GET')
            self.assertEqual(response.status_code,200,response.json)
            for item in first['codes']:self.assertNotIn(item['code'].encode(),response.data)
            self.assertNotIn(b'192.0.2.20',response.data)
            self.assertEqual(self.call(path,method='GET',token=other).status_code,404)
        self.assertEqual(self.call(method='GET',token=other).json['items'],[])
        self.assertEqual(self.call(method='GET').json['items'][0]['batch_id'],first['batch_id'])

    def test_code_and_batch_revocation_are_owned_and_idempotent(self):
        data=self.generate({'count':2}).json
        code=data['codes'][0]
        self.store.redeem(code['code'],'192.0.2.20',browser_token='d'*64)
        path='/api/v1/codes/'+code['id']+'/revoke'
        _,other=self.store.create_integration('Other',['batches:revoke'])
        self.assertEqual(self.call(path,json={},token=other).status_code,404)
        for _ in range(2):self.assertEqual(self.call(path,json={}).status_code,200)
        self.assertIsNone(self.store.browser_grant('d'*64))
        batch='/api/v1/batches/'+data['batch_id']+'/revoke'
        for _ in range(2):self.assertEqual(self.call(batch,json={}).status_code,200)
        with self.assertRaises(GateError):self.store.redeem(data['codes'][1]['code'],'192.0.2.20')
        self.assertEqual(self.call('/api/v1/batches/'+data['batch_id'],method='GET').json['batch']['counts']['revoked'],2)

    def test_pagination_is_bounded_signed_and_scoped_to_collection(self):
        data=self.generate({'count':5}).json
        path='/api/v1/batches/'+data['batch_id']+'/codes?page_size=2'
        seen=[];response=self.call(path,method='GET').json
        seen.extend(i['id'] for i in response['items'])
        cursor=response['next_cursor'];self.assertIsNotNone(cursor)
        self.assertEqual(self.call('/api/v1/batches?cursor='+cursor+'&page_size=2',method='GET').status_code,400)
        self.assertEqual(self.call(path+'&cursor='+cursor[:-1]+'!',method='GET').status_code,400)
        while response['next_cursor']:
            response=self.call(path+'&cursor='+response['next_cursor'],method='GET').json
            seen.extend(i['id'] for i in response['items'])
        self.assertEqual(len(seen),5);self.assertEqual(len(set(seen)),5)
        for suffix in ('page_size=101','page_size=0','page_size=2&page_size=3','unknown=1'):
            self.assertEqual(self.call('/api/v1/batches?'+suffix,method='GET').status_code,400)

    def test_create_only_scope_cannot_read_or_revoke_and_manual_batches_stay_private(self):
        batch,codes=self.store.create_batch(count=1)
        self.assertEqual(self.call('/api/v1/batches/'+batch,method='GET').status_code,404)
        self.assertEqual(self.call('/api/v1/batches/'+batch+'/revoke',json={}).status_code,404)
        _,create_only=self.store.create_integration('Creation only',['batches:create'])
        self.assertEqual(self.call(method='GET',token=create_only).status_code,403)
        self.assertEqual(self.call('/api/v1/batches/'+batch+'/revoke',json={},token=create_only).status_code,403)
