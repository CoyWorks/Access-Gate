import asyncio,datetime as dt,json,ssl,tempfile,time,unittest
from pathlib import Path
from access_gate.domain_policy import DomainPolicy
from access_gate.gateway_tls import CertificateCache
from access_gate.performance import Metrics
from access_gate.public_suffix import PublicSuffix
from test_gateway import settings


class WildcardPolicyTests(unittest.TestCase):
    def test_groups_scopes_suffixes_idna_and_overlap(self):
        suffixes=PublicSuffix()
        rules=DomainPolicy.parse({'domains':[
            {'domain':'example.co.uk','include_subdomains':True},
            {'domain':'api.example.co.uk','include_subdomains':True},
            {'domain':'only.example','include_subdomains':False},
            {'domain':'BÜCHER.de','include_subdomains':True},
            {'domain':'alice.github.io','include_subdomains':True}]})
        cases={'example.co.uk':'example.co.uk','www.example.co.uk':'example.co.uk',
               'api.example.co.uk':'api.example.co.uk','a.api.example.co.uk':'api.example.co.uk',
               'x.y.api.example.co.uk':'y.api.example.co.uk','only.example':'only.example',
               'www.xn--bcher-kva.de':'xn--bcher-kva.de','x.alice.github.io':'alice.github.io'}
        for host,group in cases.items():self.assertEqual(rules.certificate_group(host,suffixes),group)
        for host in ('child.only.example','bob.github.io','badexample.co.uk'):
            self.assertIsNone(rules.certificate_group(host,suffixes))
        for domain in ('co.uk','github.io','blogspot.com','com','127.0.0.1'):
            with self.assertRaises(Exception):suffixes.safe_base(domain)
        with self.assertRaisesRegex(ValueError,'too long'):
            suffixes.safe_base('.'.join(['a'*63]*3+['b'*57,'com']))
        unsafe=DomainPolicy.parse({'domains':[{'domain':'co.uk','include_subdomains':True}]})
        with self.assertRaises(ValueError):unsafe.certificate_group('tenant.co.uk',suffixes)


class WildcardTLSValidationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        config=settings(self.root,dict(portal_url='https://portal.example',client_networks=['127.0.0.0/8'],acl_token='key'))
        self.config=config
        self.policy=DomainPolicy.parse({'domains':[{'domain':'example.com','include_subdomains':True},{'domain':'exact.example','include_subdomains':False},{'domain':'xn--bcher-kva.de','include_subdomains':True}]})
        self.metrics=Metrics()
        self.cache=CertificateCache(config,lambda name:bool(self.policy.match(name)),self.metrics,lambda name:self.policy.certificate_group(name,self.cache.suffixes))
        async def connection(reader,writer):
            try:await reader.read(1)
            finally:writer.close()
        self.server=await asyncio.start_server(connection,'127.0.0.1',0,ssl=self.cache.context)
        self.port=self.server.sockets[0].getsockname()[1]
        self.trust=ssl.create_default_context(cafile=str(self.root/'etc/access-gate/ca/root.crt'))
        self.loop=asyncio.get_running_loop();self.previous=self.loop.get_exception_handler()
        self.loop.set_exception_handler(lambda loop,context:None if isinstance(context.get('exception'),(ssl.SSLError,ConnectionResetError)) else loop.default_exception_handler(context))

    async def asyncTearDown(self):
        self.server.close();await self.server.wait_closed();await self.cache.close()
        self.loop.set_exception_handler(self.previous);self.temp.cleanup()

    async def certificate(self,name):
        reader,writer=await asyncio.open_connection('127.0.0.1',self.port,ssl=self.trust,server_hostname=name)
        tls=writer.get_extra_info('ssl_object');result=(tls.getpeercert(binary_form=True),tls.getpeercert())
        writer.close();await writer.wait_closed();return result

    async def test_real_hostname_validation_apex_siblings_deep_and_idna(self):
        apex,fields=await self.certificate('example.com')
        self.assertEqual(set(fields['subjectAltName']),{('DNS','example.com'),('DNS','*.example.com')})
        start=time.perf_counter()
        results=await asyncio.gather(*(self.certificate(f'host{i}.example.com') for i in range(10)))
        elapsed=(time.perf_counter()-start)*1000
        self.assertTrue(all(cert==apex for cert,fields in results))
        self.assertEqual(self.metrics.snapshot()['stages']['certificate_generate']['count'],1)
        print('Local wildcard TLS batch:',json.dumps({'connections':10,'elapsed_ms':elapsed,'certificates_generated':1}))
        deep,fields=await self.certificate('images.api.example.com')
        self.assertNotEqual(deep,apex)
        self.assertEqual(set(fields['subjectAltName']),{('DNS','api.example.com'),('DNS','*.api.example.com')})
        self.assertEqual((await self.certificate('other.api.example.com'))[0],deep)
        await self.certificate('www.xn--bcher-kva.de')

    async def test_cached_wildcard_never_enables_unmanaged_name_or_host_scope(self):
        await self.certificate('exact.example')
        for host in ('child.exact.example','other.example'):
            with self.assertRaises((ssl.SSLError,ConnectionError)):await self.certificate(host)
        await self.certificate('www.example.com')
        self.policy=DomainPolicy.parse({'domains':[]})
        with self.assertRaises((ssl.SSLError,ConnectionError)):await self.certificate('www.example.com')

    async def test_one_label_wildcard_does_not_verify_deeper_host_by_itself(self):
        # Pin the first group's context as a standalone server: TLS validation must reject deep SNI.
        context=self.cache.for_host('www.example.com')
        server=await asyncio.start_server(lambda r,w:w.close(),'127.0.0.1',0,ssl=context)
        try:
            port=server.sockets[0].getsockname()[1]
            with self.assertRaises(ssl.SSLCertVerificationError):
                await asyncio.open_connection('127.0.0.1',port,ssl=self.trust,server_hostname='images.api.example.com')
        finally:server.close();await server.wait_closed()


    async def test_sibling_signing_reduction_against_per_hostname_cache(self):
        exact_metrics=Metrics()
        per_host=CertificateCache(self.config,lambda name:True,exact_metrics)
        start=time.perf_counter()
        for i in range(10):per_host.for_host(f'sibling{i}.example.com')
        per_host_ms=1000*(time.perf_counter()-start)
        start=time.perf_counter()
        for i in range(10):self.cache.for_host(f'sibling{i}.example.com')
        grouped_ms=1000*(time.perf_counter()-start)
        self.assertEqual(exact_metrics.snapshot()['stages']['certificate_generate']['count'],10)
        self.assertEqual(self.metrics.snapshot()['stages']['certificate_generate']['count'],1)
        print('Local sibling callback comparison:',json.dumps({'hosts':10,'per_hostname_ms':per_host_ms,'grouped_ms':grouped_ms,'signing_operations_before':10,'signing_operations_after':1}))
        await per_host.close()
