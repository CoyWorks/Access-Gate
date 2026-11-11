import copy
import tempfile
from pathlib import Path
import unittest
from access_gate.deployment import normalize,certificate_extensions,names
from access_gate.core import Store
from access_gate.web import create_app


def profile():
    return dict(deployment_version=1,server_ipv4='192.168.10.20',listen_ipv4='192.168.10.20',dns_target_ipv4='192.168.10.20',portal_url='https://access.example.net',portal_aliases=['alternate.example.net'],client_networks=['192.168.10.0/24'],admin_networks=['192.168.10.0/24'])


class DeploymentTests(unittest.TestCase):
    def test_legacy_migration_preserves_identity_secrets_and_networks(self):
        original=dict(portal_url='https://portal.example',client_networks=['10.40.135.0/24'],secret='unchanged')
        c=normalize(original)
        self.assertEqual(c['listen_ipv4'],'10.40.22.5')
        for key in original:self.assertEqual(c[key],original[key])
        self.assertEqual(c['admin_networks'],original['client_networks'])
        self.assertNotIn('deployment_version',original)
        self.assertEqual(normalize(c),c)

    def test_new_profiles_require_explicit_configuration(self):
        for value in ({},dict(deployment_version=1),dict(profile(),listen_ipv4='0.0.0.0'),dict(profile(),dns_target_ipv4='192.168.10.21'),dict(profile(),portal_url='https://bad.example/path'),dict(profile(),portal_aliases=['bad;injection'])):
            with self.subTest(value=value),self.assertRaises(ValueError):normalize(value,legacy=False)

    def test_certificate_names_have_only_selected_identity_and_aliases(self):
        c=normalize(profile(),legacy=False);ext=certificate_extensions(c)
        self.assertIn('DNS:access.example.net',ext);self.assertIn('IP:192.168.10.20',ext)
        self.assertIn('DNS:alternate.example.net',ext);self.assertNotIn('coyseinri',ext);self.assertNotIn('10.40.',ext)
        self.assertEqual(names(dict(c,portal_url='https://192.168.10.20')),['192.168.10.20','alternate.example.net'])

    def test_runtime_feeds_and_access_boundary_follow_selected_network(self):
        with tempfile.TemporaryDirectory() as temp:
            c=dict(profile(),secret='s',pepper='p',admin_hash='h',acl_token='t',database=str(Path(temp)/'db'))
            store=Store(c['database'],c['pepper']);store.initialize();store.add_dns_domains('restricted.example')
            app=create_app(c);client=app.test_client()
            kwargs=dict(base_url=c['portal_url'],environ_overrides={'REMOTE_ADDR':'127.0.0.1'},headers={'X-Real-IP':'192.168.10.45'})
            feed=client.get('/pihole.conf',**kwargs)
            self.assertEqual(feed.status_code,200);self.assertIn(b'address=/restricted.example/192.168.10.20',feed.data);self.assertNotIn(b'10.40.22.5',feed.data)
            self.assertIn(b'192.168.10.20 restricted.example',client.get('/domains.txt',**kwargs).data)
            kwargs['headers']={'X-Real-IP':'10.40.135.11'}
            self.assertEqual(client.get('/pihole.conf',**kwargs).status_code,403)
            self.assertEqual(app.extensions['health'].gateway_address,('192.168.10.20',443))

    def test_gateway_setup_uses_selected_address_and_preserves_ca(self):
        import json,os
        from gateway_fixtures import settings
        from access_gate.gateway_setup import prepare
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);settings(root,dict(profile(),acl_token='test-token'))
            before=(root/'etc/access-gate/ca/root.crt').read_bytes()
            c=prepare(root,gid=os.getgid())
            self.assertEqual(c['listen_host'],'192.168.10.20')
            self.assertNotIn('toegang.coyseinri.nl',c['portal_hosts'])
            self.assertEqual((root/'etc/access-gate/ca/root.crt').read_bytes(),before)

    def test_readiness_connects_directly_and_verifies_portal_hostname(self):
        from unittest.mock import Mock,patch
        from access_gate.readiness import https_probe
        response=Mock(status=200);connection=Mock();connection.getresponse.return_value=response
        with patch('access_gate.readiness.ssl.create_default_context') as ctx,patch('access_gate.readiness.http.client.HTTPSConnection',return_value=connection),patch('access_gate.readiness.socket.create_connection') as connect:
            self.assertEqual(https_probe('/ca',url='https://access.example.net/',address='192.168.10.20')(2),200)
            connect.assert_called_once_with(('192.168.10.20',443),timeout=2)
            self.assertEqual(ctx.return_value.wrap_socket.call_args.kwargs['server_hostname'],'access.example.net')
            connection.close.assert_called_once()
