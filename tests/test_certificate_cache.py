import asyncio,datetime as dt,ssl,tempfile,threading,time,unittest
from pathlib import Path
from unittest.mock import patch
from cryptography import x509
from access_gate.gateway_tls import CertificateCache,expires
from access_gate.performance import Metrics
from test_gateway import settings


class CertificateCacheTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.config=settings(self.root,dict(portal_url='https://portal.example',client_networks=['127.0.0.0/8'],acl_token='key'))
        self.metrics=Metrics();self.cache=CertificateCache(self.config,lambda name:True,self.metrics)
        self.wall=dt.datetime.now(dt.timezone.utc);self.tick=100.
        self.cache.utcnow=lambda:self.wall;self.cache.clock=lambda:self.tick

    async def asyncTearDown(self):
        await self.cache.close();self.temp.cleanup()

    async def test_actual_leaf_dates_fixed_cache_age_lru_and_restart(self):
        import access_gate.gateway_tls as module
        original=module.server_context;seen=[]
        def capture(path,*args):seen.append(x509.load_pem_x509_certificate(Path(path).read_bytes()));return original(path,*args)
        with patch.object(module,'server_context',side_effect=capture):first=self.cache.for_host('one.example')
        self.assertAlmostEqual((expires(seen[0])-self.wall).total_seconds(),48*3600,delta=1)
        self.assertLess(seen[0].not_valid_before.replace(tzinfo=dt.timezone.utc),self.wall)
        self.assertEqual(list(Path(self.config['runtime_dir']).iterdir()),[])
        born=self.cache.cache['one.example'].created
        self.tick+=86300;self.assertIs(self.cache.for_host('one.example'),first)
        self.assertEqual(self.cache.cache['one.example'].created,born)
        self.tick=born+86701
        self.assertIsNot(self.cache.for_host('one.example'),first)
        self.cache.limit=2;self.cache.for_host('two.example');self.cache.for_host('three.example')
        self.assertEqual(len(self.cache.cache),2);self.assertNotIn('one.example',self.cache.cache)
        other=CertificateCache(self.config,lambda name:True);self.assertFalse(other.cache);await other.close()

    async def test_background_renewal_atomic_singleflight_and_responsive_hits(self):
        first=self.cache.for_host('one.example');self.tick+=86300
        self.cache.start();original=self.cache.generate;entered=threading.Event();release=threading.Event()
        def slow(name):entered.set();release.wait(2);return original(name)
        with patch.object(self.cache,'generate',side_effect=slow) as generate:
            task=asyncio.create_task(self.cache.renew_due())
            await asyncio.to_thread(entered.wait,1)
            self.assertTrue(entered.is_set())
            await self.cache.renew_due()
            for _ in range(10):self.assertIs(self.cache.for_host('one.example'),first)
            self.assertEqual(generate.call_count,1)
            release.set();await task
        self.assertIsNot(self.cache.for_host('one.example'),first)
        self.assertEqual(self.cache.cache['one.example'].created,self.tick)
        self.assertEqual(self.metrics.snapshot()['stages']['certificate_renew']['count'],1)
        self.assertFalse(self.cache.pending)
        await self.cache.close();self.assertTrue(self.cache.renew_task.done());self.assertFalse(self.cache.cache)

    async def test_renew_failure_grace_expiry_and_insufficient_issuer_lifetime(self):
        first=self.cache.for_host('one.example');self.tick+=86410;self.cache.start()
        with patch.object(self.cache,'generate',side_effect=ValueError('synthetic signing error')):
            await self.cache.renew_due();self.assertIs(self.cache.for_host('one.example'),first)
            self.tick+=301
            with self.assertRaises(ValueError):self.cache.for_host('one.example')
        self.assertEqual(self.metrics.snapshot()['counters']['renew_error'],1)
        self.wall=expires(self.cache.issuer)-dt.timedelta(hours=47)
        with self.assertRaisesRegex(ValueError,'full 48-hour'):self.cache.for_host('new.example')
        self.wall=expires(self.cache.issuer)+dt.timedelta(seconds=1)
        with self.assertRaisesRegex(ValueError,'full 48-hour'):self.cache.for_host('new.example')

    async def test_cryptographic_expiry_never_reuses_context_and_eviction_during_renewal(self):
        first=self.cache.for_host('one.example')
        self.wall=first.access_gate_not_after+dt.timedelta(seconds=1)
        self.assertIsNot(self.cache.for_host('one.example'),first)
        self.tick+=86300;self.cache.start();original=self.cache.generate
        entered=threading.Event();release=threading.Event()
        def slow(name):entered.set();release.wait(2);return original(name)
        with patch.object(self.cache,'generate',side_effect=slow):
            task=asyncio.create_task(self.cache.renew_due());await asyncio.to_thread(entered.wait,1)
            self.cache.cache.pop('one.example');release.set();await task
        self.assertNotIn('one.example',self.cache.cache)

    async def test_concurrent_cold_creation_and_shutdown_during_worker(self):
        original=self.cache.generate
        with patch.object(self.cache,'generate',wraps=original) as generate:
            contexts=await asyncio.gather(*(asyncio.to_thread(self.cache.for_host,'same.example') for _ in range(8)))
        self.assertEqual(generate.call_count,1);self.assertTrue(all(c is contexts[0] for c in contexts))
        self.tick+=86300;self.cache.start();entered=threading.Event();release=threading.Event()
        def slow(name):entered.set();release.wait(2);return original(name)
        with patch.object(self.cache,'generate',side_effect=slow):
            self.cache.renew_task.cancel()
            try:await self.cache.renew_task
            except asyncio.CancelledError:pass
            self.cache.renew_task=asyncio.create_task(self.cache.renew_due())
            await asyncio.to_thread(entered.wait,1)
            closing=asyncio.create_task(self.cache.close());await asyncio.sleep(.02)
            self.assertFalse(closing.done());release.set();await closing
        self.assertFalse(self.cache.cache);self.assertFalse(self.cache.pending)
        self.assertEqual(list(Path(self.config['runtime_dir']).iterdir()),[])
