import unittest
from access_gate.domain_policy import DomainPolicy


class DomainPolicyTests(unittest.TestCase):
    def test_exact_deep_scope_disabled_deleted_and_fixed_age(self):
        rows={'domains':[{'domain':'example.co.uk','include_subdomains':True},{'domain':'exact.example','include_subdomains':False}]}
        snapshot=DomainPolicy.parse(rows,lambda:100.)
        self.assertEqual(snapshot.match('a.b.example.co.uk',lambda:109.),('example.co.uk',True))
        self.assertEqual(snapshot.match('exact.example',lambda:101.),('exact.example',False))
        for name in ('evil-example.co.uk','child.exact.example','other.example'):
            self.assertIsNone(snapshot.match(name,lambda:101.))
        self.assertIsNone(snapshot.match('example.co.uk',lambda:110.))
        replacement=DomainPolicy.parse({'domains':[]},lambda:102.)
        self.assertIsNone(replacement.match('example.co.uk',lambda:103.))
        self.assertTrue(snapshot.fresh(lambda:105.))

    def test_malformed_snapshot_is_rejected_and_idna_is_normalized(self):
        for payload in ({},{'domains':None},{'domains':[{'domain':'example.com','include_subdomains':'yes'}]},{'domains':[{'domain':'https://example.com','include_subdomains':True}]}):
            with self.assertRaises(ValueError):DomainPolicy.parse(payload)
        result=DomainPolicy.parse({'domains':[{'domain':'BÜCHER.de','include_subdomains':True}]})
        self.assertTrue(result.match('www.xn--bcher-kva.de'))


class PolicyRefreshTests(unittest.IsolatedAsyncioTestCase):
    async def test_concurrent_refresh_malformed_and_authentication_rejection(self):
        import asyncio,json
        from access_gate.gateway import Gateway
        from access_gate.performance import Metrics
        class Content:
            async def iter_chunked(self,n):yield json.dumps(payload).encode()
        class Response:
            content=Content()
            @property
            def status(self):return status
            async def __aenter__(self):
                nonlocal running,maximum
                running+=1;maximum=max(maximum,running);await asyncio.sleep(.01);return self
            async def __aexit__(self,*args):
                nonlocal running
                running-=1
        class Session:
            def get(self,*args,**kwargs):return Response()
        gateway=Gateway.__new__(Gateway);gateway.policy=None;gateway.policy_lock=asyncio.Lock();gateway.performance=Metrics();gateway.local=Session();gateway.remote=False;gateway.api_url='http://127.0.0.1';gateway.key='test';gateway.policy_last_error=False
        payload={'domains':[{'domain':'example.com','include_subdomains':True}]};status=200;running=maximum=0
        self.assertTrue(all(await asyncio.gather(*(gateway.refresh_policy() for _ in range(4)))))
        self.assertEqual(maximum,1);old=gateway.policy
        payload={'domains':[{'domain':'bad','include_subdomains':True}]}
        self.assertFalse(await gateway.refresh_policy());self.assertIs(gateway.policy,old)
        status=403
        self.assertFalse(await gateway.refresh_policy());self.assertIsNone(gateway.policy)
