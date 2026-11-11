import json,socket,struct,tempfile,threading,time
from pathlib import Path
import unittest
from unittest.mock import Mock,patch
import dns.flags,dns.message,dns.query,dns.rcode,dns.rrset
from access_gate.dns_service import Rules,Resolver,servers
from access_gate.dns_publisher import publish
from access_gate.core import Store
from access_gate.deployment import normalize
from test_deployment_settings import profile


class DNSTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.path=Path(self.temp.name)/'rules.json'
        self.write([dict(domain='restricted.example',include_subdomains=True),dict(domain='single.example',include_subdomains=False)])
        self.forward=Mock(side_effect=lambda q:dns.message.make_response(q))
        self.config=dict(listen_ipv4='127.0.0.1',client_networks=['127.0.0.0/8'],portal_names=['portal.example'],dns_target_ipv4='192.168.10.20',dns_upstreams=['1.1.1.1'])
        self.resolver=Resolver(self.config,Rules(self.path),forward=self.forward)
    def tearDown(self):self.temp.cleanup()
    def write(self,rows):self.path.write_text(json.dumps(dict(domains=rows)))
    def query(self,name,kind='A',peer='127.0.0.1'):
        q=dns.message.make_query(name,kind);wire=self.resolver.answer(q.to_wire(),peer)
        return dns.message.from_wire(wire) if wire else None

    def test_exact_and_subdomains_and_portal_stay_local_for_all_record_types(self):
        for name in ('restricted.example','a.b.restricted.example','single.example','portal.example'):
            for kind in ('A','AAAA','HTTPS','SVCB','TXT'):
                with self.subTest(name=name,kind=kind):
                    r=self.query(name,kind);self.assertEqual(r.rcode(),dns.rcode.NOERROR)
                    self.assertEqual(bool(r.answer),kind=='A')
        self.forward.assert_not_called()
        self.query('child.single.example');self.forward.assert_called_once()

    def test_client_acl_malformed_and_upstream_failure(self):
        self.assertIsNone(self.query('restricted.example',peer='192.168.99.1'))
        self.assertIsNone(self.resolver.answer(b'invalid','127.0.0.1'))
        self.forward.side_effect=TimeoutError()
        self.assertEqual(self.query('ordinary.example').rcode(),dns.rcode.SERVFAIL)

    def test_reload_add_remove_and_invalid_snapshot_retains_previous_rules(self):
        self.write([dict(domain='added.example',include_subdomains=False)])
        self.query('added.example');self.forward.assert_not_called()
        self.query('restricted.example');self.forward.assert_called_once()
        self.path.write_text('invalid snapshot');self.forward.reset_mock()
        self.query('added.example');self.forward.assert_not_called()

    def test_forward_preserves_unrelated_answers_and_uses_tcp_fallback_library(self):
        def forward(q):
            r=dns.message.make_response(q);r.answer.append(dns.rrset.from_text(q.question[0].name,14400,'IN','AAAA','2001:4860:4860::8888'));return r
        self.forward.side_effect=forward
        r=self.query('ordinary.example','AAAA');self.assertEqual(r.answer[0].ttl,14400)
        self.assertEqual(r.answer[0][0].address,'2001:4860:4860::8888')
        self.resolver.forward=self.resolver.upstream
        with patch('dns.query.udp_with_fallback',side_effect=[TimeoutError(),(forward(dns.message.make_query('ordinary.example','AAAA')),True)]) as call:
            self.resolver.config['dns_upstreams']=['1.1.1.1','9.9.9.9'];r=self.query('ordinary.example','AAAA');self.assertEqual(len(r.answer),1);self.assertEqual(call.call_count,2)

    def test_actual_udp_and_tcp_queries_share_same_rules_and_survive_restarts(self):
        for _ in range(2):
            udp,tcp=servers(self.config,self.resolver,port=0)
            threads=[threading.Thread(target=s.serve_forever,daemon=True) for s in (udp,tcp)]
            for thread in threads:thread.start()
            try:
                q=dns.message.make_query('restricted.example','A');port=udp.server_address[1]
                for send in (dns.query.udp,dns.query.tcp):
                    r=send(q,'127.0.0.1',port=port,timeout=2);self.assertEqual(r.answer[0][0].address,'192.168.10.20')
            finally:
                for s in (udp,tcp):s.shutdown();s.server_close()
                for thread in threads:thread.join()

    def test_publisher_tracks_enabled_rules_and_keeps_good_file_on_db_failure(self):
        c=normalize(dict(profile(),secret='s',pepper='p',acl_token='t',admin_hash='h',database=str(Path(self.temp.name)/'db')))
        store=Store(c['database'],'p');store.initialize();store.add_dns_domains('new.example')
        publish(c,Path(self.temp.name));rules=Rules(self.path);self.assertTrue(rules.restricted('www.new.example'))
        store.change_dns_domain('new.example','disable');publish(c,Path(self.temp.name));rules.reload();self.assertFalse(rules.restricted('new.example'))
        before=self.path.read_bytes();c['database']='/nonexistent/invalid/db'
        with self.assertRaises(Exception):publish(c,Path(self.temp.name))
        self.assertEqual(self.path.read_bytes(),before)

    def test_upstream_configuration_rejects_direct_loops(self):
        for upstream in ('192.168.10.20','127.0.0.53','0.0.0.0','224.0.0.1'):
            with self.subTest(upstream=upstream),self.assertRaises(ValueError):normalize(dict(profile(),dns_mode='builtin',dns_upstreams=[upstream]))

    def test_dns_runtime_configuration_contains_no_portal_secrets(self):
        from access_gate.dns_setup import public_config
        c=normalize(dict(profile(),dns_mode='builtin',dns_upstreams=['1.1.1.1'],secret='private',pepper='private',acl_token='private',admin_hash='private',database='/private/db'))
        safe=public_config(c)
        for key in ('secret','pepper','acl_token','admin_hash','database'):self.assertNotIn(key,safe)
        self.assertEqual(safe['portal_names'],['192.168.10.20','access.example.net','alternate.example.net'])
