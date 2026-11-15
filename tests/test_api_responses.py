"""Validate actual HTTP responses against the checked-in API reference."""
import copy
import unittest
from test_rest_api import APICase
from test_api_contract import SPEC,resolve
try:
    from jsonschema import Draft202012Validator,FormatChecker
except ImportError:
    Draft202012Validator=FormatChecker=None


@unittest.skipIf(Draft202012Validator is None,'Install tests/requirements-contract.txt.')
class HTTPContractTests(APICase):
    def check_response(self,response,path,method):
        operation=SPEC['paths'][path][method]
        description=operation['responses'].get(str(response.status_code),operation['responses']['default'])
        if '$ref' in description:description=resolve(description['$ref'])
        schema={'components':SPEC['components'],**description['content']['application/json']['schema']}
        Draft202012Validator(schema,format_checker=FormatChecker()).validate(response.json)
        self.assertEqual(response.mimetype,'application/json')
        self.assertEqual(response.headers['X-Request-ID'],response.json['request_id'])
        self.assertNotIn('Set-Cookie',response.headers)
        for name,header in description['headers'].items():
            if '$ref' in header:header=resolve(header['$ref'])
            if header.get('required'):self.assertIn(name,response.headers)
            if name in response.headers:
                value=response.headers[name]
                if header['schema'].get('type')=='integer':value=int(value)
                Draft202012Validator({'components':SPEC['components'],**header['schema']}).validate(value)

    def test_success_and_replay_match_creation_contract(self):
        self.enable()
        headers={'Idempotency-Key':'contract-generation-operation'}
        for _ in range(2):
            response=self.call(json={},headers=headers)
            self.assertEqual(response.status_code,201)
            self.check_response(response,'/batches','post')

    def test_status_and_revocation_responses_match_contract(self):
        from access_gate.integrations import SCOPES
        _,self.token=self.store.create_integration('All operations',list(SCOPES))
        self.enable()
        result=self.call(json={},headers={'Idempotency-Key':'contract-lifecycle-operation'}).json
        batch=result['batch_id'];code=result['codes'][0]['id']
        for path,actual,method in [('/batches','/api/v1/batches','get'),
            ('/batches/{batch_id}','/api/v1/batches/'+batch,'get'),
            ('/batches/{batch_id}/codes','/api/v1/batches/'+batch+'/codes','get'),
            ('/codes/{code_id}/revoke','/api/v1/codes/'+code+'/revoke','post'),
            ('/batches/{batch_id}/revoke','/api/v1/batches/'+batch+'/revoke','post')]:
            kwargs={'json':{}} if method=='post' else {}
            response=self.call(actual,method=method.upper(),**kwargs)
            self.check_response(response,path,method)

    def test_json_error_statuses_match_their_declared_schemas(self):
        self.enable();headers={'Idempotency-Key':'contract-error-operation'}
        responses=[self.call(json={},token='invalid',headers=headers),self.call(json={'count':True},headers=headers),
                   self.call(data='invalid-json',content_type='application/json',headers=headers),
                   self.call(data='{}',headers=headers),self.call(method='PUT'),
                   self.call(json={},headers={**headers,'Accept':'text/html'}),
                   self.call(data=' '*16385,content_type='application/json',headers=headers)]
        for response,expected in zip(responses,[401,400,400,415,405,406,413]):
            with self.subTest(status=response.status_code):
                self.assertEqual(response.status_code,expected)
                self.check_response(response,'/batches','post')

    def test_legacy_migration_preserves_manual_batches_and_api_defaults(self):
        batch,_=self.store.create_batch(count=1)
        with self.store.connect() as db:
            for table in ('api_audit','api_limits','api_requests','api_batches','api_policy','api_credentials'):
                db.execute('DROP TABLE '+table)
            db.execute('PRAGMA user_version=13')
        self.store.initialize();self.store.initialize()
        self.assertFalse(self.store.api_policy()['enabled'])
        self.assertEqual(self.store.batch_detail(batch)['total'],1)
        with self.store.connect() as db:self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(),[])

    def test_disabled_api_is_json_and_no_browser_cookie_can_enable_it(self):
        self.login()
        response=self.call(json={})
        self.assertEqual(response.status_code,404)
        self.check_response(response,'/batches','post')
