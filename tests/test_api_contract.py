"""Validate API schemas independently of HTTP integration tests.

Extra schema validators are developer-only; see requirements-contract.txt.
Structural tests still run in the normal unittest discovery without those extras.
"""
import copy
import datetime as dt
import json
from pathlib import Path
import unittest

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ImportError:
    Draft202012Validator = FormatChecker = None
try:
    from openapi_spec_validator import validate as validate_openapi
except ImportError:
    validate_openapi = None

ROOT = Path(__file__).resolve().parents[1]
SPEC = json.loads((ROOT / 'docs/openapi/access-gate-v1.json').read_text())
OPERATION = SPEC['paths']['/batches']['post']
SCHEMAS = SPEC['components']['schemas']
EXTRAS = 'Install tests/requirements-contract.txt to validate API schemas.'


def resolve(pointer):
    value = SPEC
    for part in pointer.removeprefix('#/').split('/'):
        value = value[part.replace('~1', '/').replace('~0', '~')]
    return value


def sample():
    return copy.deepcopy(OPERATION['responses']['201']['content']['application/json']['examples']['weeklyAllowance']['value'])


class ContractStructureTests(unittest.TestCase):
    def test_only_creation_is_exposed_and_followups_are_marked_reserved(self):
        self.assertEqual(SPEC['x-implementation-status'], 'creation-implemented')
        self.assertEqual(set(SPEC['paths']), {'/batches'})
        self.assertEqual(set(SPEC['paths']['/batches']), {'post'})
        self.assertEqual(len(SPEC['x-reserved-operations']), 5)
        self.assertEqual(SPEC['security'], [{'integrationBearer': []}])
        self.assertEqual(OPERATION['x-required-scopes'], ['batches:create'])
        self.assertNotIn('profile_id', SCHEMAS['CreateBatchRequest']['properties'])

    def test_all_references_are_local_and_resolve(self):
        def walk(node):
            if isinstance(node, dict):
                if '$ref' in node:
                    self.assertTrue(node['$ref'].startswith('#/'))
                    self.assertIsInstance(resolve(node['$ref']), dict)
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for value in node:
                    walk(value)
        walk(SPEC)

    def test_all_responses_have_json_no_store_and_request_id(self):
        for status, response in OPERATION['responses'].items():
            with self.subTest(status=status):
                self.assertEqual(set(response['content']), {'application/json'})
                self.assertEqual(resolve(response['headers']['Cache-Control']['$ref'])['schema'], {'type': 'string', 'const': 'no-store'})
                self.assertTrue(resolve(response['headers']['X-Request-ID']['$ref'])['required'])
        self.assertIn('Retry-After', OPERATION['responses']['429']['headers'])
        self.assertIn('Retry-After', OPERATION['responses']['503']['headers'])
        self.assertIn('WWW-Authenticate', OPERATION['responses']['401']['headers'])
        self.assertIn('Allow', OPERATION['responses']['405']['headers'])
        self.assertIn('Idempotency-Replayed', OPERATION['responses']['201']['headers'])

    def test_retry_key_is_required_and_not_a_query_parameter(self):
        parameter, = OPERATION['parameters']
        self.assertEqual((parameter['name'], parameter['in'], parameter['required']), ('Idempotency-Key', 'header', True))
        self.assertTrue(OPERATION['requestBody']['required'])


@unittest.skipIf(validate_openapi is None, EXTRAS)
class OpenAPITests(unittest.TestCase):
    def test_openapi_document_is_valid(self):
        validate_openapi(SPEC)


@unittest.skipIf(Draft202012Validator is None, EXTRAS)
class PayloadSchemaTests(unittest.TestCase):
    def validator(self, schema):
        document = {'$schema': 'https://json-schema.org/draft/2020-12/schema',
                    'components': SPEC['components'], **schema}
        return Draft202012Validator(document, format_checker=FormatChecker())

    def request_errors(self, payload):
        return list(self.validator({'$ref': '#/components/schemas/CreateBatchRequest'}).iter_errors(payload))

    def test_every_component_schema_is_well_formed(self):
        for name, schema in SCHEMAS.items():
            with self.subTest(name=name):
                Draft202012Validator.check_schema(schema)

    def test_all_request_and_response_examples_validate(self):
        content = OPERATION['requestBody']['content']['application/json']
        for name, example in content['examples'].items():
            with self.subTest(request=name):
                self.validator(content['schema']).validate(example['value'])
        for status, response in OPERATION['responses'].items():
            content = response['content']['application/json']
            for name, example in content.get('examples', {}).items():
                with self.subTest(status=status, example=name):
                    self.validator(content['schema']).validate(example['value'])

    def test_positive_duration_boundaries_and_default_units(self):
        for payload in ({}, {'count': 1000}, {'count': 10.0}, {'name': ''}, {'name': ' x '},
                        {'validity_value': 365}, {'validity_value': 8760, 'validity_unit': 'hours'},
                        {'access_value': 10080}, {'access_value': 168, 'access_unit': 'hours'}):
            with self.subTest(payload=payload):
                self.assertFalse(self.request_errors(payload))

    def test_invalid_payloads_cannot_silently_fall_back_to_defaults(self):
        for payload in (None, [], '', {'count': True}, {'count': '10'}, {'count': 1.5},
                        {'count': 0}, {'count': 1001}, {'count': None}, {'profile_id': 'default'},
                        {'validity_value': 366}, {'validity_value': 366, 'validity_unit': 'days'},
                        {'validity_value': 8761, 'validity_unit': 'hours'}, {'validity_unit': 'minutes'},
                        {'access_value': 10081}, {'access_value': 169, 'access_unit': 'hours'},
                        {'access_unit': 'days'}, {'access_value': -1}, {'access_value': 0},
                        {'name': 'x' * 81}, {'name': 'invalid\nname'}, {'name': 'invalid\n'}, {'name': 42}):
            with self.subTest(payload=payload):
                self.assertTrue(self.request_errors(payload))

    def test_field_types_are_strict_for_both_duration_pairs(self):
        for field in ('validity_value', 'access_value'):
            for value in (True, False, '1', None, 1.5):
                with self.subTest(field=field, value=value):
                    self.assertTrue(self.request_errors({field: value}))

    def test_retry_key_bounds_and_characters(self):
        validator = self.validator(OPERATION['parameters'][0]['schema'])
        for value in ('a' * 16, 'a' * 128, 'weekly-2026_11.15:550e8400'):
            self.assertTrue(validator.is_valid(value))
        for value in ('short', 'a' * 129, 'a' * 15 + ' ', 'a' * 16 + '\n', 123):
            self.assertFalse(validator.is_valid(value))

    def test_success_example_counts_uniqueness_and_deadlines(self):
        response = sample()
        request = OPERATION['requestBody']['content']['application/json']['examples']['weeklyAllowance']['value']
        self.assertEqual(response['count'], request['count'])
        self.assertEqual(len(response['codes']), response['count'])
        for field in ('id', 'code'):
            self.assertEqual(len({item[field] for item in response['codes']}), response['count'])
        stamp = lambda name: dt.datetime.fromisoformat(response[name].replace('Z', '+00:00'))
        self.assertEqual(stamp('valid_from'), stamp('created_at'))
        self.assertEqual((stamp('valid_until') - stamp('valid_from')).total_seconds(), response['validity_seconds'])
        self.assertEqual(response['validity_seconds'], 7 * 86400)
        self.assertEqual(response['access_seconds'], 15 * 60)
        self.assertEqual((stamp('replay_until') - stamp('created_at')).total_seconds(), 86400)
        self.assertEqual((stamp('key_retained_until') - stamp('created_at')).total_seconds(), 30 * 86400)

    def test_response_rejects_secret_leaks_and_invalid_time_or_code(self):
        validator = self.validator({'$ref': '#/components/schemas/CreateBatchResponse'})
        for field, value in (('authorization', 'secret'), ('visitor_ip', '192.0.2.1'),
                             ('created_at', '2026-11-15T12:00:00+01:00'),
                             ('created_at', 'not-a-date'), ('portal_url', 'http://access.example.org/')):
            response = sample()
            response[field] = value
            with self.subTest(field=field, value=value):
                self.assertFalse(validator.is_valid(response))
        response = sample()
        response['codes'][0]['code'] = '0000-1111'
        self.assertFalse(validator.is_valid(response))

    def test_error_codes_are_bound_to_their_http_status(self):
        for status, response in OPERATION['responses'].items():
            if status in ('201', 'default'):
                continue
            content = response['content']['application/json']
            payload = copy.deepcopy(next(iter(content['examples'].values()))['value'])
            payload['error']['code'] = 'internal_error' if status != '500' else 'unauthorized'
            with self.subTest(status=status):
                self.assertFalse(self.validator(content['schema']).is_valid(payload))

    def test_only_expired_replay_discloses_original_batch_id(self):
        content = OPERATION['responses']['409']['content']['application/json']
        validator = self.validator(content['schema'])
        expired = copy.deepcopy(content['examples']['expiredReplay']['value'])
        del expired['error']['batch_id']
        self.assertFalse(validator.is_valid(expired))
        conflict = copy.deepcopy(content['examples']['example']['value'])
        conflict['error']['batch_id'] = sample()['batch_id']
        self.assertFalse(validator.is_valid(conflict))


if __name__ == '__main__':
    unittest.main()
