import asyncio
from contextlib import asynccontextmanager
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import aiohttp
from aiohttp import web, WSMsgType
from aiohttp.abc import AbstractResolver
from werkzeug.security import generate_password_hash
from werkzeug.serving import make_server, WSGIRequestHandler
from cryptography import x509

from access_gate.core import Store
from access_gate.gateway import Gateway, BootstrapResolver, PublicResolver, public_ip, safe_headers, answer_addresses, main
from access_gate.gateway_tls import CertificateCache, server_context
from access_gate.gateway_setup import prepare
from access_gate.web import create_app
from access_gate.health import Health
from gateway_fixtures import settings, ca, leaf, write_pair


class LoopbackResolver(AbstractResolver):
    async def resolve(self, host, port=0, family=socket.AF_INET):
        return [dict(hostname=host, host='127.0.0.1', port=port, family=socket.AF_INET, proto=socket.IPPROTO_TCP, flags=socket.AI_NUMERICHOST)]
    async def close(self): pass


class QuietHandler(WSGIRequestHandler):
    def log(self, *args, **kwargs): pass


class GatewayConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.portal = dict(secret='s', pepper='p', acl_token='gateway-key', admin_hash='h', database=str(self.root/'db'),
                           portal_url='https://portal.example', client_networks=['127.0.0.0/8'])
        self.config = settings(self.root, self.portal)
    def tearDown(self): self.temp.cleanup()

    def test_setup_reuses_root_and_issuer_and_limits_issuer_authority(self):
        base = self.root/'etc/access-gate'
        before = {name: (base/name).read_bytes() for name in ('ca/root.key', 'ca/root.crt', 'gateway/issuer.key', 'gateway/issuer.crt')}
        prepare(self.root, gid=os.getgid())
        self.assertEqual(before, {name: (base/name).read_bytes() for name in before})
        cert = x509.load_pem_x509_certificate((base/'gateway/issuer.crt').read_bytes())
        limits = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        self.assertTrue(limits.ca); self.assertEqual(limits.path_length, 0)
        self.assertEqual((base/'gateway').stat().st_mode & 0o777, 0o750)
        self.assertEqual((base/'gateway/issuer.key').stat().st_mode & 0o777, 0o640)
        self.assertNotIn('pepper', json.loads((base/'gateway/gateway.json').read_text()))
        self.assertNotIn('admin_hash', json.loads((base/'gateway/gateway.json').read_text()))

    def test_rsa_root_from_existing_installer_issues_and_reuses_ec_intermediate(self):
        root = self.root/'rsa-install'
        config = settings(root, self.portal, rsa_root=True)
        certificate = Path(config['issuer_cert']).read_bytes()
        root_key = (root/'etc/access-gate/ca/root.key').read_bytes()
        prepare(root, gid=os.getgid())
        self.assertEqual(Path(config['issuer_cert']).read_bytes(), certificate)
        self.assertEqual((root/'etc/access-gate/ca/root.key').read_bytes(), root_key)
        cache = CertificateCache(config, lambda host: True)
        self.assertIsInstance(cache.for_host('restricted.example'), ssl.SSLContext)

    def test_incomplete_issuer_and_symlinked_state_are_refused(self):
        base = self.root/'etc/access-gate/gateway'; (base/'issuer.key').unlink()
        with self.assertRaises(ValueError): prepare(self.root, gid=os.getgid())
        (base/'issuer.key').symlink_to(self.root/'outside.key')
        with self.assertRaises(ValueError): prepare(self.root, gid=os.getgid())

    def test_legacy_restricted_portal_certificate_gets_gateway_group_access_without_regeneration(self):
        base = self.root/'etc/access-gate'
        certificate = (base/'portal.crt').read_bytes()
        protected = {name: (base/name).read_bytes() for name in ('portal.key', 'ca/root.key', 'ca/root.crt', 'gateway/issuer.key')}
        (base/'portal.crt').chmod(0o600)
        (base/'portal.key').chmod(0o600)
        (base/'ca').chmod(0o700); (base/'ca/root.key').chmod(0o600)
        prepare(self.root, gid=os.getgid())
        for name in ('portal.crt', 'portal.key'):
            metadata = (base/name).stat()
            self.assertEqual(metadata.st_mode & 0o777, 0o640)
            self.assertEqual(metadata.st_gid, os.getgid())
        self.assertEqual((base/'portal.crt').read_bytes(), certificate)
        self.assertEqual(protected, {name: (base/name).read_bytes() for name in protected})
        self.assertEqual((base/'ca').stat().st_mode & 0o777, 0o700)
        self.assertEqual((base/'ca/root.key').stat().st_mode & 0o777, 0o600)
        self.assertIsInstance(CertificateCache(self.config, lambda host: True).context, ssl.SSLContext)

    def test_credential_check_loads_tls_and_does_not_start_a_listener(self):
        configuration = self.root/'check.json'; configuration.write_text(json.dumps(self.config))
        with patch('access_gate.gateway.asyncio.run') as run:
            main(['--check'], configuration_path=configuration)
            run.assert_not_called()
        (Path(self.config['portal_cert'])).unlink()
        with self.assertRaisesRegex(SystemExit, 'portal.crt'):
            main(['--check'], configuration_path=configuration)

    def test_portal_tls_symlinks_are_refused_before_permissions_change(self):
        base = self.root/'etc/access-gate'
        outside = self.root/'outside.crt'; outside.write_bytes((base/'portal.crt').read_bytes()); outside.chmod(0o600)
        (base/'portal.crt').unlink(); (base/'portal.crt').symlink_to(outside)
        with self.assertRaises(ValueError): prepare(self.root, gid=os.getgid())
        self.assertEqual(outside.stat().st_mode & 0o777, 0o600)

    def test_cache_is_bounded_and_temporary_private_keys_are_removed(self):
        cache = CertificateCache(self.config, lambda host: True); cache.limit = 2
        first = cache.for_host('one.example')
        self.assertIs(cache.for_host('one.example'), first)
        cache.for_host('two.example'); cache.for_host('three.example')
        self.assertEqual(len(cache.cache), 2)
        self.assertNotIn('one.example', cache.cache)
        self.assertEqual(list(Path(self.config['runtime_dir']).iterdir()), [])

    def test_live_policy_exact_and_subdomain_boundaries(self):
        store = Store(self.root/'db', 'p'); store.initialize()
        store.add_dns_domains('example.org'); store.add_dns_domains('exact.example', scope='exact')
        for host in ('example.org', 'www.example.org', 'a.b.example.org', 'exact.example'):
            self.assertTrue(store.restricted_host(host))
        for host in ('unrelatedexample.org', 'example.org.evil.test', 'sub.exact.example'):
            self.assertFalse(store.restricted_host(host))
        store.change_dns_domain('example.org', 'disable')
        self.assertFalse(store.restricted_host('www.example.org'))


class GatewayProtocolTests(unittest.TestCase):
    def test_public_dns_answer_validation_blocks_private_cnames_and_malformed_data(self):
        good = {'Status': 0, 'Answer': [{'type': 5, 'data': 'alias.example'}, {'type': 1, 'data': '1.1.1.1'}]}
        self.assertEqual(answer_addresses(good), ['1.1.1.1'])
        for bad in ([], {'Status': 3}, {'Status': 0, 'Answer': []}, {'Status': 0, 'Answer': [None]},
                    {'Status': 0, 'Answer': [{'type': 1, 'data': '10.40.22.5'}]},
                    {'Status': 0, 'Answer': [{'type': 1, 'data': '::1'}]}):
            with self.subTest(answer=bad), self.assertRaises((OSError, ValueError)): answer_addresses(bad)

    def test_private_and_reserved_upstreams_are_rejected(self):
        for address in ('127.0.0.1', '10.40.22.5', '169.254.169.254', '192.168.1.1', '::1', 'fc00::1', '224.0.0.1', '192.0.2.1'):
            with self.subTest(address=address), self.assertRaises(OSError): public_ip(address)
        self.assertEqual(public_ip('1.1.1.1'), '1.1.1.1')

    def test_header_filter_removes_connection_tokens_private_headers_and_quic_hints(self):
        from multidict import CIMultiDict
        headers = CIMultiDict([('Connection', 'X-Remove'), ('X-Remove', 'secret'), ('X-Gate-Key', 'secret'),
            ('X-Forwarded-For', 'spoof'), ('Proxy-Authorization', 'secret'), ('Alt-Svc', 'h3=":443"'),
            ('Set-Cookie', 'one=1'), ('Set-Cookie', 'two=2')])
        filtered = safe_headers(headers)
        self.assertEqual(filtered.getall('Set-Cookie'), ['one=1', 'two=2'])
        for name in ('Connection', 'X-Remove', 'X-Gate-Key', 'X-Forwarded-For', 'Proxy-Authorization', 'Alt-Svc'):
            self.assertNotIn(name, filtered)
        headers.add('Set-Cookie', '__Host-accessgate-site=override; Secure; Path=/')
        self.assertEqual(safe_headers(headers, upstream=True).getall('Set-Cookie'), ['one=1', 'two=2'])


class GatewayResolverTests(unittest.IsolatedAsyncioTestCase):
    async def test_bootstrap_is_independent_of_system_dns_and_doh_preserves_public_answers(self):
        with patch('socket.getaddrinfo', side_effect=AssertionError('System DNS must not be used')):
            bootstrap = await BootstrapResolver().resolve('cloudflare-dns.com', 443)
        self.assertEqual(bootstrap[0]['host'], '1.1.1.1')
        with self.assertRaises(OSError): await BootstrapResolver().resolve('unapproved.example', 443)
        resolver = PublicResolver(); calls = []
        class Content:
            async def iter_chunked(self, amount):
                # Fragmented JSON proves the complete bounded response is collected.
                yield b'{"Status":0,"Answer":['
                yield b'{"type":1,"data":"93.184.216.34"}]}'
        class Response: status = 200; content = Content()
        class Session:
            @asynccontextmanager
            async def get(self, url, **kwargs):
                calls.append((url, kwargs)); yield Response()
            async def close(self): pass
        resolver.session = Session()
        answers = await resolver.resolve('restricted.example', 443)
        self.assertEqual(answers[0]['host'], '93.184.216.34')
        self.assertEqual(calls[0][1]['params'], {'name': 'restricted.example', 'type': 'A'})
        self.assertFalse(calls[0][1]['allow_redirects'])
        await resolver.close()

    async def test_private_doh_answers_fail_closed_at_both_providers(self):
        resolver = PublicResolver(); calls = []
        class Content:
            async def iter_chunked(self, amount): yield b'{"Status":0,"Answer":[{"type":1,"data":"10.40.22.5"}]}'
        class Response: status = 200; content = Content()
        class Session:
            @asynccontextmanager
            async def get(self, url, **kwargs): calls.append(url); yield Response()
            async def close(self): pass
        resolver.session = Session()
        with self.assertRaises(OSError): await resolver.resolve('restricted.example', 443)
        self.assertEqual(len(calls), 2)
        await resolver.close()


class GatewayTLSFlowTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.loop = asyncio.get_running_loop(); self.old_handler = self.loop.get_exception_handler()
        def handler(loop, context):
            if isinstance(context.get('exception'), (ssl.SSLError, ConnectionResetError)): return
            loop.default_exception_handler(context)
        self.loop.set_exception_handler(handler)
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        portal = dict(secret='secret', pepper='pepper', acl_token='gateway-key', admin_hash=generate_password_hash('admin'),
            database=str(self.root/'db'), portal_url='https://portal.example', client_networks=['127.0.0.0/8'])
        self.config = settings(self.root, portal)
        self.flask = create_app(portal); self.flask.config['TESTING'] = True
        self.flask.add_url_rule('/test-large-export','large_test_export',lambda:(b'x'*(5*1024*1024),{'Content-Type':'text/plain'}))
        self.store = self.flask.extensions['store']; self.store.initialize(); self.store.add_dns_domains('restricted.example')
        self.wsgi = make_server('127.0.0.1', 0, self.flask, threaded=True, request_handler=QuietHandler)
        self.thread = threading.Thread(target=self.wsgi.serve_forever, daemon=True); self.thread.start()
        self.config['api_url'] = f'http://127.0.0.1:{self.wsgi.server_port}'
        self.seen = []
        cert, key = ca('Independent test origin CA')
        write_pair(cert, key, self.root/'origin-ca.crt', self.root/'origin-ca.key')
        leaf(cert, key, 'restricted.example', self.root/'origin.crt', self.root/'origin.key')
        origin_app = web.Application(); origin_app.router.add_route('*', '/{path:.*}', self.origin)
        self.origin_runner = web.AppRunner(origin_app, access_log=None); await self.origin_runner.setup()
        origin_site = web.TCPSite(self.origin_runner, '127.0.0.1', 0, ssl_context=server_context(self.root/'origin.crt', self.root/'origin.key'))
        await origin_site.start(); origin_port = origin_site._server.sockets[0].getsockname()[1]
        context = ssl.create_default_context(cafile=str(self.root/'origin-ca.crt'))
        connector = aiohttp.TCPConnector(resolver=LoopbackResolver(), ssl=context)
        self.gateway = Gateway(self.config, upstream_connector=connector, upstream_port=origin_port, poll_interval=0.04)
        self.runner = web.AppRunner(self.gateway.application(), access_log=None, shutdown_timeout=0.1); await self.runner.setup()
        site = web.TCPSite(self.runner, '127.0.0.1', 0, ssl_context=self.gateway.tls.context)
        await site.start(); self.port = site._server.sockets[0].getsockname()[1]
        http_site = web.TCPSite(self.runner, '127.0.0.1', 0); await http_site.start()
        self.http_port = http_site._server.sockets[0].getsockname()[1]
        self.client_context = ssl.create_default_context(cafile=str(self.root/'etc/access-gate/ca/root.crt'))
        self.client = aiohttp.ClientSession(connector=aiohttp.TCPConnector(resolver=LoopbackResolver(), ssl=self.client_context),
            timeout=aiohttp.ClientTimeout(total=5))

    async def test_policy_snapshot_refresh_stale_failure_and_live_authorization(self):
        from dataclasses import replace
        from unittest.mock import patch
        self.assertTrue(self.gateway.is_restricted_sync('restricted.example'))
        with patch('http.client.HTTPConnection',side_effect=AssertionError('No network in SNI')):
            for _ in range(100):self.assertTrue(self.gateway.is_restricted_sync('restricted.example'))
        old=self.gateway.policy
        self.gateway.policy=replace(old,loaded=time.monotonic()-11)
        self.assertFalse(self.gateway.is_restricted_sync('restricted.example'))
        self.assertTrue(await self.gateway.refresh_policy())
        self.store.add_dns_domains('exact.example',scope='exact')
        self.assertFalse(self.gateway.is_restricted_sync('exact.example'))
        await self.gateway.refresh_policy()
        self.assertTrue(self.gateway.is_restricted_sync('exact.example'))
        self.assertFalse(self.gateway.is_restricted_sync('child.exact.example'))
        with patch.object(self.gateway.local,'get',side_effect=OSError('offline')):
            self.assertFalse(await self.gateway.refresh_policy())
        self.assertTrue(self.gateway.policy_status()['last_refresh_failed'])
        self.assertTrue(self.gateway.is_restricted_sync('exact.example'))
        self.gateway.policy=replace(self.gateway.policy,loaded=time.monotonic()-11)
        self.assertFalse(self.gateway.is_restricted_sync('exact.example'))

    async def test_policy_startup_fails_closed_without_authenticated_snapshot(self):
        from unittest.mock import patch,AsyncMock
        other=Gateway(self.config)
        with patch.object(other,'refresh_policy',new=AsyncMock(return_value=False)):
            with self.assertRaisesRegex(OSError,'listener not started'):await other.start(None)
        self.assertTrue(other.local.closed)
        self.assertIsNone(other.policy_task)
        self.assertFalse(other.is_restricted_sync('restricted.example'))

    async def test_slow_policy_refresh_does_not_block_loop_or_warm_lookup(self):
        from unittest.mock import patch
        from access_gate.domain_policy import DomainPolicy
        original=DomainPolicy.parse
        def slow(data):time.sleep(.15);return original(data)
        with patch.object(DomainPolicy,'parse',side_effect=slow):
            task=asyncio.create_task(self.gateway.refresh_policy())
            await asyncio.sleep(.03)
            self.assertFalse(task.done())
            self.assertTrue(self.gateway.is_restricted_sync('restricted.example'))
            await task

    async def test_performance_requires_private_machine_key(self):
        response=await self.get(path='/__access_gate/performance')
        self.assertEqual(response.status,403);await response.read()
        response=await self.client.get(f'https://portal.example:{self.port}/__access_gate/performance',headers={'Host':'portal.example','X-Gate-Metrics-Key':self.config['api_key']})
        self.assertEqual(response.status,200)
        data=await response.json();self.assertEqual(data['format'],1)
        self.assertNotIn('restricted.example',str(data))

    async def test_recovery_upload_streams_through_real_tls_gateway(self):
        jobs=self.flask.extensions['jobs'];jobs.root=self.root/'jobs';(jobs.root/'inbox').mkdir(parents=True)
        form=await self.get(path='/admin/login')
        csrf=re.search(r'name="csrf" value="([^"]+)"',await form.text()).group(1)
        response=await self.get(path='/admin/login',method='POST',data=dict(csrf=csrf,password='admin'))
        self.assertEqual(response.status,302);await response.read()
        form=await self.get(path='/admin/recovery')
        csrf=re.search(r'name="csrf" value="([^"]+)"',await form.text()).group(1)
        data=aiohttp.FormData();data.add_field('csrf',csrf);data.add_field('action','preflight');data.add_field('current_password','admin');data.add_field('passphrase','test-passphrase-1234')
        data.add_field('archive',b'x'*32768,filename='backup.agbackup',content_type='application/octet-stream')
        response=await self.get(path='/admin/recovery',method='POST',data=data)
        self.assertEqual(response.status,303);await response.read()
        self.assertEqual(len(list((jobs.root/'inbox').glob('*.archive'))),1)
        self.assertEqual(next((jobs.root/'inbox').glob('*.archive')).stat().st_size,32768)

    async def asyncTearDown(self):
        await self.client.close(); await self.runner.cleanup(); await self.origin_runner.cleanup()
        await asyncio.to_thread(self.wsgi.shutdown); self.wsgi.server_close(); self.thread.join(timeout=2)
        self.temp.cleanup()
        self.loop.set_exception_handler(self.old_handler)

    async def origin(self, request):
        self.seen.append(dict(request.headers))
        if request.path == '/stream':
            response = web.StreamResponse(headers={'Content-Type': 'text/plain'}); await response.prepare(request)
            try:
                for _ in range(20): await response.write(b'chunk\n'); await asyncio.sleep(0.05)
                await response.write_eof()
            except (ConnectionError, asyncio.CancelledError): pass
            return response
        if request.path == '/ws':
            ws = web.WebSocketResponse(); await ws.prepare(request)
            async for message in ws:
                if message.type == WSMsgType.TEXT: await ws.send_str(message.data)
            return ws
        if request.path == '/echo': return web.Response(body=await request.read())
        return web.Response(text='Origin reached', headers={'Alt-Svc': 'h3=":443"'})

    async def get(self, host='portal.example', path='/', method='GET', data=None, **kwargs):
        return await self.client.request(method, f'https://{host}:{self.port}{path}', headers={'Host': host},
            data=data, allow_redirects=False, **kwargs)

    async def activate(self):
        first = await self.get('restricted.example'); self.assertEqual(first.status, 302)
        entry = first.headers['Location'].split('entry=')[1]; await first.read()
        form = await self.get(path='/?entry='+entry)
        csrf = re.search(r'name="csrf" value="([^"]+)"', await form.text()).group(1)
        _, codes = self.store.create_batch(count=1)
        accepted = await self.get(path='/?entry='+entry, method='POST', data={'csrf': csrf, 'code': codes[0], 'entry': entry})
        self.assertEqual(accepted.status, 303)
        self.assertEqual(accepted.headers['Location'], '/continue?entry='+entry); await accepted.read()
        continued = await self.get(path='/continue?entry='+entry)
        self.assertEqual(continued.status, 200)
        self.assertIn('id="continue-website"', await continued.text())
        self.assertIn("form-action 'self'", continued.headers['Content-Security-Policy'])
        resumed = await self.get(path='/?entry='+entry)
        self.assertEqual(resumed.status, 303)
        callback = resumed.headers['Location'].split('https://restricted.example')[1]; await resumed.read()
        completed = await self.get('restricted.example', callback)
        self.assertEqual(completed.status, 303); await completed.read()
        self.grant = self.store.list_grants()[0]
        return codes[0]

    async def test_real_tls_leaf_matches_deep_hostname_and_unknown_hosts_fail_closed(self):
        reader, writer = await asyncio.open_connection('127.0.0.1', self.port, ssl=self.client_context, server_hostname='a.b.restricted.example')
        cert = writer.get_extra_info('ssl_object').getpeercert()
        self.assertIn(('DNS', 'a.b.restricted.example'), cert['subjectAltName'])
        writer.close(); await writer.wait_closed()
        with self.assertRaises((ssl.SSLError, ConnectionError)):
            await asyncio.open_connection('127.0.0.1', self.port, ssl=self.client_context, server_hostname='unmanaged.example')

    async def test_absolute_proxy_request_targets_are_rejected(self):
        reader, writer = await asyncio.open_connection('127.0.0.1', self.port, ssl=self.client_context, server_hostname='restricted.example')
        writer.write(b'GET https://unmanaged.example/ HTTP/1.1\r\nHost: restricted.example\r\nConnection: close\r\n\r\n')
        await writer.drain()
        self.assertIn(b'400', await reader.readline())
        writer.close(); await writer.wait_closed()
        self.assertEqual(self.seen, [])

    async def test_complete_cookie_code_return_flow_and_private_header_isolation(self):
        await self.activate()
        self.client.cookie_jar.update_cookies({'ordinary': 'keep'}, response_url=aiohttp.client_reqrep.URL('https://restricted.example'))
        response = await self.get('restricted.example')
        self.assertEqual(response.status, 200); self.assertEqual(await response.text(), 'Origin reached')
        self.assertNotIn('Alt-Svc', response.headers)
        self.assertEqual(self.seen[-1].get('Cookie'), 'ordinary=keep')
        self.assertNotIn('X-Gate-Key', self.seen[-1])
        self.assertEqual((await self.get(path='/internal/gateway/domain?host=restricted.example')).status, 404)
        self.assertEqual((await self.get(path='/__access_gate/health')).status, 200)

    async def test_another_browser_on_same_ip_does_not_inherit_gateway_access(self):
        await self.activate()
        other = aiohttp.ClientSession(connector=aiohttp.TCPConnector(resolver=LoopbackResolver(), ssl=self.client_context))
        try:
            response = await other.get(f'https://restricted.example:{self.port}/', headers={'Host': 'restricted.example'}, allow_redirects=False)
            self.assertEqual(response.status, 302); await response.read()
            self.assertEqual(self.seen, [])
        finally: await other.close()

    async def test_unauthorized_browser_never_reaches_origin_and_host_fronting_is_rejected(self):
        response = await self.get('restricted.example'); await response.read()
        self.assertEqual(response.status, 302); self.assertEqual(self.seen, [])
        response = await self.client.get(f'https://restricted.example:{self.port}/', headers={'Host': 'portal.example'}, allow_redirects=False)
        self.assertEqual(response.status, 421); await response.read()

    async def test_authorized_post_body_survives_proxying(self):
        await self.activate()
        response = await self.get('restricted.example', '/echo', method='POST', data=b'example=request&text=hello')
        self.assertEqual(response.status, 200)
        self.assertEqual(await response.read(), b'example=request&text=hello')

    async def test_large_portal_exports_are_not_truncated(self):
        data = b'x' * (5*1024*1024)
        response = await self.get(path='/test-large-export')
        self.assertEqual(response.status, 200)
        self.assertEqual(await response.read(), data)

    async def test_expiry_closes_real_http_stream_and_portal_keeps_working(self):
        await self.activate()
        with self.store.connect() as db: db.execute('UPDATE grants SET expires=? WHERE session_id=?', (time.time()+0.25, self.grant['session_id']))
        response = await self.get('restricted.example', '/stream'); self.assertEqual(await response.content.readline(), b'chunk\n')
        with self.assertRaises(aiohttp.ClientPayloadError): await asyncio.wait_for(response.read(), 1.5)
        portal = await self.get(); self.assertEqual(portal.status, 200); await portal.read()
        again = await self.get('restricted.example'); self.assertEqual(again.status, 302); await again.read()

    async def test_extension_is_seen_by_stream_watcher(self):
        await self.activate()
        with self.store.connect() as db: db.execute('UPDATE grants SET expires=? WHERE session_id=?', (time.time()+0.35, self.grant['session_id']))
        response = await self.get('restricted.example', '/stream'); await response.content.readline()
        self.store.extend(self.grant['session_id'], '1', 'minutes', secrets.token_hex(16))
        self.assertEqual((await response.read()).count(b'chunk\n'), 19)

    async def admin_activate(self):
        first=await self.get('restricted.example'); self.assertEqual(first.status,302)
        entry=first.headers['Location'].split('entry=')[1]; await first.read()
        form=await self.get(path='/admin/login?portal=1&entry='+entry)
        csrf=re.search(r'name="csrf" value="([^"]+)"',await form.text()).group(1)
        accepted=await self.get(path='/admin/login',method='POST',data=dict(csrf=csrf,password='admin',portal='1',entry=entry))
        self.assertEqual(accepted.status,303); self.assertEqual(accepted.headers['Location'],'/continue?entry='+entry); await accepted.read()
        continued=await self.get(path='/continue?entry='+entry); self.assertEqual(continued.status,200); await continued.read()
        resume=await self.get(path='/?entry='+entry)
        callback=resume.headers['Location'].split('https://restricted.example')[1]; await resume.read()
        completed=await self.get('restricted.example',callback); self.assertEqual(completed.status,303); await completed.read()
        self.assertEqual(self.store.list_batches()['total'],0)

    async def test_code_visit_metadata_reaches_token_history_without_query_or_cookie_data(self):
        await self.activate()
        policy=self.store.activity_settings();self.store.save_activity_settings('pages',30,policy['version'])
        response=await self.client.get(f'https://restricted.example:{self.port}/article?password=NEVER-STORE',headers={'Host':'restricted.example','Accept':'text/html','Sec-Fetch-Dest':'document'},allow_redirects=False)
        self.assertEqual(response.status,200);await response.read()
        await asyncio.wait_for(self.gateway.activity_queue.join(),2)
        pages=self.store.history('pages',code_id=self.grant['code'])['items']
        self.assertEqual(pages[0]['domain'],'restricted.example');self.assertEqual(pages[0]['path'],'/article')
        with self.store.connect() as db:dump=' '.join(db.iterdump())
        self.assertNotIn('NEVER-STORE',dump)
        self.assertEqual(self.gateway.activity_dropped,0)

    async def test_approved_request_returns_through_fresh_tls_handoff_without_code(self):
        first=await self.get('restricted.example');self.assertEqual(first.status,302)
        entry=first.headers['Location'].split('entry=')[1];await first.read()
        form=await self.get(path='/request-access?entry='+entry)
        csrf=re.search(r'name="csrf" value="([^"]+)"',await form.text()).group(1)
        sent=await self.get(path='/request-access',method='POST',data=dict(csrf=csrf,entry=entry,reason='Please approve'))
        self.assertEqual(sent.status,303);rid=sent.headers['Location'].split('request=')[1];await sent.read()
        pending=await self.get(path='/request-access/status?request='+rid)
        self.assertEqual((await pending.json())['state'],'pending')
        # The original five-minute gateway challenge may expire while waiting.
        with self.store.connect() as db:db.execute('UPDATE gateway_entries SET expires=?',(time.time()-10,))
        decision=self.store.decide_request(rid,'approve',15,'minutes')
        status=await self.get(path='/request-access/status?request='+rid);data=await status.json();self.assertTrue(data['active'])
        resume=await self.get(path=data['continue_url']);self.assertEqual(resume.headers['Location'],'https://restricted.example/');await resume.read()
        target=await self.get('restricted.example');self.assertEqual(target.status,302)
        fresh=target.headers['Location'].split('entry=')[1];await target.read()
        handoff=await self.get(path='/?entry='+fresh);self.assertEqual(handoff.status,303)
        callback=handoff.headers['Location'].split('https://restricted.example')[1];await handoff.read()
        completed=await self.get('restricted.example',callback);self.assertEqual(completed.status,303);await completed.read()
        website=await self.get('restricted.example');self.assertEqual(website.status,200);await website.read()
        await self.gateway.activity_queue.join()
        self.assertEqual(self.store.history('domains',code_id=decision['code_id'])['items'][0]['domain'],'restricted.example')
        self.assertEqual(self.store.code_detail(decision['code_id'])['hint'],'AUTO')

    async def test_visit_delivery_failure_does_not_interrupt_authorized_browsing(self):
        await self.activate()
        with patch.object(self.gateway,'activity_post',side_effect=OSError('Metadata unavailable')):
            response=await self.get('restricted.example');self.assertEqual(response.status,200);await response.read()
            await asyncio.wait_for(self.gateway.activity_queue.join(),2)
        self.assertEqual(self.gateway.activity_dropped,1)
        health=await self.get(path='/__access_gate/health');self.assertEqual((await health.json())['activity_dropped'],1)

    async def test_removed_batch_stops_existing_restricted_stream(self):
        await self.activate()
        response=await self.get('restricted.example','/stream');await response.content.readline()
        batch=self.store.code_detail(self.grant['code'])['batch_id']
        self.store.remove_batches([batch])
        with self.assertRaises(aiohttp.ClientPayloadError):await asyncio.wait_for(response.read(),1.5)
        denied=await self.get('restricted.example');self.assertEqual(denied.status,302);await denied.read()
        self.assertEqual(self.store.list_batches(view='removed')['total'],1)

    async def test_administrator_and_ip_exclusions_are_not_attributed_to_a_code(self):
        await self.admin_activate()
        response=await self.get('restricted.example');self.assertEqual(response.status,200);await response.read()
        await self.gateway.activity_queue.join()
        self.assertEqual(self.store.history('domains')['total'],0)
        self.store.save_admin_security(dict(secret='secret',admin_hash='bootstrap'),exclusions=['127.0.0.1/32'])
        response=await self.get('restricted.example');self.assertEqual(response.status,200);await response.read()
        self.assertEqual(self.store.history('domains')['total'],0)

    async def test_admin_login_bypasses_code_and_logout_closes_real_stream(self):
        await self.admin_activate()
        origin=await self.get('restricted.example'); self.assertEqual(origin.status,200); await origin.read()
        for headers in self.seen:
            self.assertNotIn('__Host-accessgate-admin',headers.get('Cookie',''))
            self.assertNotIn('__Host-accessgate-site',headers.get('Cookie',''))
        response=await self.get('restricted.example','/stream'); await response.content.readline()
        form=await self.get(); csrf=re.search(r'name="csrf" value="([^"]+)"',await form.text()).group(1)
        logout=await self.get(path='/logout',method='POST',data=dict(csrf=csrf)); self.assertEqual(logout.status,302); await logout.read()
        with self.assertRaises(aiohttp.ClientPayloadError):await asyncio.wait_for(response.read(),1.5)
        denied=await self.get('restricted.example');self.assertEqual(denied.status,302);await denied.read()

    async def test_admin_website_use_renews_login_but_passive_stream_watcher_expires(self):
        await self.admin_activate()
        with self.store.connect() as db:db.execute('UPDATE admin_logins SET expires=?',(time.time()+100,))
        allowed=await self.get('restricted.example');self.assertEqual(allowed.status,200);await allowed.read()
        with self.store.connect() as db:self.assertGreater(db.execute('SELECT expires FROM admin_logins').fetchone()[0],time.time()+6*86400)
        response=await self.get('restricted.example','/stream');await response.content.readline()
        with self.store.connect() as db:db.execute('UPDATE admin_logins SET expires=?',(time.time()+0.2,))
        with self.assertRaises(aiohttp.ClientPayloadError):await asyncio.wait_for(response.read(),1.5)
        denied=await self.get('restricted.example');self.assertEqual(denied.status,302);await denied.read()

    async def test_ip_exclusion_forwards_without_cookie_and_removal_closes_stream(self):
        policy=dict(secret='secret',admin_hash='bootstrap')
        self.store.save_admin_security(policy,exclusions=['127.0.0.1/32'])
        allowed=await self.get('restricted.example');self.assertEqual(allowed.status,200);await allowed.read()
        self.assertEqual(self.store.list_batches()['total'],0)
        response=await self.get('restricted.example','/stream');await response.content.readline()
        self.store.save_admin_security(policy,exclusions=[])
        with self.assertRaises(aiohttp.ClientPayloadError):await asyncio.wait_for(response.read(),1.5)
        denied=await self.get('restricted.example');self.assertEqual(denied.status,302);await denied.read()

    async def test_client_cannot_spoof_excluded_address_to_gateway(self):
        self.store.save_admin_security(dict(secret='secret',admin_hash='bootstrap'),exclusions=['127.0.0.2/32'])
        response=await self.client.get(f'https://restricted.example:{self.port}/',headers={'Host':'restricted.example','X-Gate-Client-IP':'127.0.0.2','X-Real-IP':'127.0.0.2','X-Forwarded-For':'127.0.0.2'},allow_redirects=False)
        self.assertEqual(response.status,302);await response.read()
        self.assertEqual(self.seen,[])

    async def test_health_probe_verifies_actual_tls_listener_and_certificate_metadata(self):
        provider=Health(dict(portal_url='https://portal.example'),self.store,
            ca_file=str(self.root/'etc/access-gate/ca/root.crt'),gateway_address=('127.0.0.1',self.port))
        checks=await asyncio.to_thread(provider.gateway,time.time())
        self.assertEqual([c['state'] for c in checks],['healthy','healthy','warning','healthy','healthy'])
        self.assertIn('Gateway issuing certificate',[c['name'] for c in checks])
        provider.config['portal_url']='https://wrong.example'
        with self.assertRaises((ssl.SSLError,ConnectionError,OSError)):
            await asyncio.to_thread(provider.gateway,time.time())

    async def test_session_termination_closes_stream_without_revoking_code_or_portal(self):
        await self.activate()
        response=await self.get('restricted.example','/stream'); await response.content.readline()
        self.store.terminate_session(self.grant['session_id'])
        with self.assertRaises(aiohttp.ClientPayloadError): await asyncio.wait_for(response.read(),1.5)
        denied=await self.get('restricted.example'); self.assertEqual(denied.status,302); await denied.read()
        portal=await self.get(); self.assertEqual(portal.status,200); await portal.read()
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT revoked FROM codes WHERE id=?',(self.grant['code'],)).fetchone()[0],0)

    async def test_revocation_closes_real_websocket(self):
        await self.activate()
        async with self.client.ws_connect(f'https://restricted.example:{self.port}/ws', headers={'Host': 'restricted.example'}) as ws:
            await ws.send_str('hello'); self.assertEqual((await ws.receive()).data, 'hello')
            self.store.revoke(self.grant['code'])
            message = await asyncio.wait_for(ws.receive(), 1.5)
            self.assertIn(message.type, (WSMsgType.CLOSED, WSMsgType.CLOSE, WSMsgType.ERROR))

    async def test_policy_removal_and_authorization_failure_close_existing_streams(self):
        await self.activate()
        response = await self.get('restricted.example', '/stream'); await response.content.readline()
        self.store.change_dns_domain('restricted.example', 'disable')
        with self.assertRaises(aiohttp.ClientPayloadError): await asyncio.wait_for(response.read(), 1.5)

    async def test_authorization_service_failure_closes_existing_stream(self):
        await self.activate()
        response = await self.get('restricted.example', '/stream'); await response.content.readline()
        self.gateway.key = 'unavailable-key'
        with self.assertRaises(aiohttp.ClientPayloadError): await asyncio.wait_for(response.read(), 1.5)
        self.assertGreater(self.store.list_grants()[0]['expires'], time.time())

    async def test_untrusted_upstream_certificate_is_rejected(self):
        await self.activate()
        await self.gateway.upstream.close()
        self.gateway.upstream = aiohttp.ClientSession(connector=aiohttp.TCPConnector(resolver=LoopbackResolver(), ssl=ssl.create_default_context()), cookie_jar=aiohttp.DummyCookieJar())
        response = await self.get('restricted.example')
        self.assertEqual(response.status, 502); await response.read()
        self.assertEqual(self.seen, [])

    async def test_http_entry_redirect_and_untrusted_forwarded_address(self):
        response = await self.client.get(f'http://127.0.0.1:{self.http_port}/', headers={'Host': 'restricted.example', 'X-Real-IP': '127.0.0.1'}, allow_redirects=False)
        self.assertEqual(response.status, 308); self.assertEqual(response.headers['Location'], 'https://restricted.example/'); await response.read()
        response = await self.client.get(f'http://127.0.0.1:{self.http_port}/', headers={'Host': 'restricted.example', 'X-Real-IP': '192.0.2.1'}, allow_redirects=False)
        self.assertEqual(response.status, 403); await response.read()


if __name__ == '__main__': unittest.main()
