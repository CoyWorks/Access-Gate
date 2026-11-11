import asyncio,contextlib,datetime as dt,http.client,ipaddress,json,os,ssl,tempfile,threading,time,unittest
from pathlib import Path
from unittest.mock import patch
import aiohttp
from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from werkzeug.serving import make_server,WSGIRequestHandler
from access_gate.core import Store
from access_gate.web import create_app
from access_gate.gateway import Gateway
from access_gate.public_deploy import enrollment,validate_tls
from gateway_fixtures import settings,write_pair,leaf
from test_gateway import LoopbackResolver
from test_deployment_settings import profile


class Quiet(WSGIRequestHandler):
    def log(self,*args,**kwargs):pass


class RemoteGatewayTLS(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.c=dict(profile(),portal_url='https://portal.example',secret='s',pepper='p',admin_hash='h',acl_token='t',database=str(self.root/'db'),client_networks=['127.0.0.0/8'])
        self.store=Store(self.c['database'],'p');self.store.initialize();self.store.add_dns_domains('restricted.example')
        self.app=create_app(dict(self.c,public_portal=True));self.server=make_server('127.0.0.1',0,self.app,threaded=True,request_handler=Quiet)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        authority_root=self.root/'authority';config=settings(authority_root,self.c,ca_name='Test public authority root')
        peer=enrollment(self.store,self.c,'Private gateway',base=authority_root/'etc/access-gate',gid=os.getgid());self.peer=peer
        # The real HTTPS test authority uses its own trusted test CA, with DNS and IP SANs.
        base=authority_root/'etc/access-gate';ca=x509.load_pem_x509_certificate((base/'ca/root.crt').read_bytes());key=serialization.load_pem_private_key((base/'ca/root.key').read_bytes(),password=None)
        leafkey=ec.generate_private_key(ec.SECP256R1());now=dt.datetime.now(dt.timezone.utc)
        cert=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'portal.example')])).issuer_name(ca.subject).public_key(leafkey.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-dt.timedelta(minutes=1)).not_valid_after(now+dt.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('portal.example'),x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),False)
            .add_extension(x509.BasicConstraints(ca=False,path_length=None),True).sign(key,hashes.SHA256()))
        write_pair(cert,leafkey,config['portal_cert'],config['portal_key'])
        config.update(api_url='http://127.0.0.1:'+str(self.server.server_port),public_portal=True,gateway_client_ca=str(base/'authority/ca.crt'),portal_hosts=['portal.example','127.0.0.1'])
        self.authority=Gateway(config)
        self.authority_loop=asyncio.new_event_loop();ready=threading.Event()
        async def start_authority():
            self.runner=web.AppRunner(self.authority.application(),access_log=None);await self.runner.setup()
            self.site=web.TCPSite(self.runner,'127.0.0.1',0,ssl_context=self.authority.tls.context);await self.site.start()
            self.port=self.site._server.sockets[0].getsockname()[1];ready.set()
        def run_authority():
            asyncio.set_event_loop(self.authority_loop);self.authority_loop.run_until_complete(start_authority());self.authority_loop.run_forever();self.authority_loop.close()
        self.authority_thread=threading.Thread(target=run_authority,daemon=True);self.authority_thread.start()
        if not ready.wait(5):raise RuntimeError('Test authority did not start.')
        self.api='https://127.0.0.1:'+str(self.port)
        (self.root/'client.crt').write_text(peer['cert']);(self.root/'client.key').write_text(peer['private_key'])
        self.ctx=ssl.create_default_context(cafile=str(base/'ca/root.crt'));self.ctx.load_cert_chain(self.root/'client.crt',self.root/'client.key')
        self.client=aiohttp.ClientSession(headers={'Host':'127.0.0.1'},connector=aiohttp.TCPConnector(ssl=self.ctx),trust_env=False,cookie_jar=aiohttp.DummyCookieJar())
        async with self.client.post(self.api+'/gateway/v1/activate',headers={'X-Gateway-Key':peer['key']}) as response:self.assertEqual(response.status,200,await response.text())
        private=settings(self.root/'private',dict(self.c,portal_url='https://gateway.example'))
        private.update(remote_gateway=True,api_url=self.api,api_key=peer['key'],api_client_cert=str(self.root/'client.crt'),api_client_key=str(self.root/'client.key'),api_ca_file=str(base/'ca/root.crt'),portal_url='https://portal.example')
        # Separate verified origin server, reached only through an injected loopback test resolver.
        privatebase=self.root/'private/etc/access-gate'
        origin_ca=x509.load_pem_x509_certificate((privatebase/'ca/root.crt').read_bytes());origin_key=serialization.load_pem_private_key((privatebase/'ca/root.key').read_bytes(),password=None)
        leaf(origin_ca,origin_key,'restricted.example',self.root/'origin.crt',self.root/'origin.key')
        originctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);originctx.load_cert_chain(self.root/'origin.crt',self.root/'origin.key')
        origin=web.Application();origin.router.add_get('/',lambda request:web.Response(text='Verified remote grant reached the origin.'))
        self.origin_runner=web.AppRunner(origin,access_log=None);await self.origin_runner.setup()
        origin_site=web.TCPSite(self.origin_runner,'127.0.0.1',0,ssl_context=originctx);await origin_site.start();origin_port=origin_site._server.sockets[0].getsockname()[1]
        origintrust=ssl.create_default_context(cafile=str(privatebase/'ca/root.crt'))
        self.private=Gateway(private,upstream_connector=aiohttp.TCPConnector(ssl=origintrust,resolver=LoopbackResolver()),upstream_port=origin_port);self.private_runner=web.AppRunner(self.private.application(),access_log=None);await self.private_runner.setup()
        self.private_site=web.TCPSite(self.private_runner,'127.0.0.1',0,ssl_context=self.private.tls.context);await self.private_site.start();self.private_port=self.private_site._server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        await self.private_runner.cleanup();await self.origin_runner.cleanup();await self.client.close();await self.cleanup_authority()
        self.authority_loop.call_soon_threadsafe(self.authority_loop.stop);self.authority_thread.join()
        await asyncio.to_thread(self.server.shutdown);self.server.server_close();self.thread.join();self.temp.cleanup()

    async def cleanup_authority(self):
        await asyncio.wrap_future(asyncio.run_coroutine_threadsafe(self.runner.cleanup(),self.authority_loop))

    async def test_actual_mtls_domain_handoff_authorization_and_revocation(self):
        self.assertTrue(await asyncio.to_thread(self.private.is_restricted_sync,'restricted.example'))
        self.assertFalse(await asyncio.to_thread(self.private.is_restricted_sync,'other.example'))
        status,headers,data=await self.private.rpc('/internal/start','restricted.example')
        self.assertEqual(status,302);entry=headers['Location'].split('entry=')[1]
        from http.cookies import SimpleCookie
        cookies=SimpleCookie();cookies.load(headers['Set-Cookie']);nonce=cookies['__Host-accessgate-challenge'].value
        bid,codes=self.store.create_batch(count=1);self.store.redeem(codes[0],'127.0.0.1',browser_token='a'*64)
        _,ticket=self.store.issue_handoff(entry,'a'*64)
        status,headers,data=await self.private.rpc('/internal/finish?ticket='+ticket,'restricted.example','__Host-accessgate-challenge='+nonce)
        self.assertEqual(status,303);cookies=SimpleCookie();cookies.load(headers.getall('Set-Cookie')[0]);token=cookies['__Host-accessgate-site'].value
        active,_,_=await self.private.allowed('restricted.example','__Host-accessgate-site='+token);self.assertTrue(active)
        self.store.revoke_batch(bid)
        active,_,_=await self.private.allowed('restricted.example','__Host-accessgate-site='+token);self.assertFalse(active)
        self.store.revoke_gateway(self.peer['id'])
        self.assertFalse(await self.private.refresh_policy())
        self.assertFalse(await asyncio.to_thread(self.private.is_restricted_sync,'restricted.example'))

    async def test_no_client_certificate_or_forged_transport_headers_cannot_call_api(self):
        context=ssl.create_default_context(cafile=str(self.root/'authority/etc/access-gate/ca/root.crt'))
        async with aiohttp.ClientSession(headers={'Host':'127.0.0.1'},connector=aiohttp.TCPConnector(ssl=context)) as client:
            async with client.get(self.api+'/gateway/v1/health',headers={'X-Gateway-Key':self.peer['key'],'X-Gate-Peer-Fingerprint':'f'*64,'X-Gate-Key':'t'}) as response:self.assertEqual(response.status,403)
        async with self.client.get(self.api+'/gateway/v1/health',headers={'X-Gateway-Key':'x'*64}) as response:self.assertEqual(response.status,403)
        async with self.client.get(self.api+'/internal/check',headers={'X-Gate-Key':'t'}) as response:self.assertEqual(response.status,404)
        async with self.client.get(self.api+'/gateway/v1/%2e%2e/%2e%2e/internal/check',headers={'X-Gateway-Key':self.peer['key']}) as response:self.assertIn(response.status,(403,404))

    async def test_authority_outage_is_fail_closed(self):
        await self.cleanup_authority()
        with self.assertRaises((OSError,aiohttp.ClientError,asyncio.TimeoutError)):
            await self.private.allowed('restricted.example','__Host-accessgate-site='+'a'*64)

    async def test_verified_rules_export_and_offline_certificate_validation(self):
        async with self.client.get(self.api+'/gateway/v1/rules',headers={'X-Gateway-Key':self.peer['key']}) as response:
            self.assertEqual(response.status,200);payload=await response.json();self.assertEqual(payload['domains'],[dict(domain='restricted.example',include_subdomains=True)])
        base=self.root/'authority/etc/access-gate'
        validate_tls((base/'portal.crt').read_bytes(),(base/'portal.key').read_bytes(),'portal.example',cafile=base/'ca/root.crt')
        with self.assertRaises(ValueError):validate_tls((base/'portal.crt').read_bytes(),(base/'portal.key').read_bytes(),'wrong.example',cafile=base/'ca/root.crt')

    async def test_full_visitor_code_and_approved_request_flows_through_private_https(self):
        import re
        context=ssl.create_default_context(cafile=str(self.root/'authority/etc/access-gate/ca/root.crt'))
        context.load_verify_locations(cafile=str(self.root/'private/etc/access-gate/ca/root.crt'))
        connector=aiohttp.TCPConnector(ssl=context,resolver=LoopbackResolver())
        for mode in ('code','request'):
            async with aiohttp.ClientSession(connector=connector,connector_owner=False,trust_env=False) as browser:
                private='https://restricted.example:'+str(self.private_port)
                public='https://portal.example:'+str(self.port)
                async with browser.get(private+'/',headers={'Host':'restricted.example'},allow_redirects=False) as response:
                    self.assertEqual(response.status,302);entry=response.headers['Location'].split('entry=')[1]
                async with browser.get(public+'/?entry='+entry,headers={'Host':'portal.example'},allow_redirects=False) as response:
                    self.assertEqual(response.status,200);body=await response.text()
                if mode=='code':
                    _,codes=self.store.create_batch(count=1)
                    csrf=re.search(r'name="csrf" value="([^"]+)"',body).group(1)
                    async with browser.post(public+'/',headers={'Host':'portal.example'},data=dict(code=codes[0],csrf=csrf,entry=entry),allow_redirects=False) as response:self.assertEqual(response.status,303)
                else:
                    token=browser.cookie_jar.filter_cookies('https://portal.example')['__Host-accessgate-browser'].value
                    rid,_=self.store.submit_request(token,'127.0.0.1','restricted.example','Test device','Test approval')
                    self.store.decide_request(rid,'approve','15','minutes')
                async with browser.get(public+'/?entry='+entry,headers={'Host':'portal.example'},allow_redirects=False) as response:
                    self.assertEqual(response.status,303);destination=response.headers['Location'].split('restricted.example',1)[1]
                async with browser.get(private+destination,headers={'Host':'restricted.example'},allow_redirects=False) as response:self.assertEqual(response.status,303)
                async with browser.get(private+'/',headers={'Host':'restricted.example'}) as response:
                    self.assertEqual(response.status,200);self.assertIn('Verified remote grant',await response.text())
        await connector.close()

    async def test_live_certificate_check_verifies_expected_fingerprint(self):
        from access_gate.public_deploy import verify_live_certificate
        c=dict(self.c,listen_ipv4='127.0.0.1');base=self.root/'authority/etc/access-gate'
        await asyncio.to_thread(verify_live_certificate,c,(base/'portal.crt').read_bytes(),port=self.port,cafile=base/'ca/root.crt')
        with self.assertRaises(ValueError):
            await asyncio.to_thread(verify_live_certificate,c,(self.root/'origin.crt').read_bytes(),port=self.port,cafile=base/'ca/root.crt')
