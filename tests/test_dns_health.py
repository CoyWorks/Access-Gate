import json,tempfile,threading,time,unittest
from pathlib import Path
from unittest.mock import patch
import dns.exception,dns.message,dns.rrset
from access_gate.dns_health import DNSMonitor
from access_gate.dns_health_view import read_health
from access_gate.deployment import normalize
from access_gate.dns_setup import public_config
from access_gate.dns_service import Rules,Resolver,servers
from test_browser_portal import BrowserWebFixture


class DNSHealthTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.wall=1000.;self.tick=100.
        self.config=normalize(dict(portal_url='https://portal.example',dns_mode='builtin',dns_upstreams=['1.1.1.1','9.9.9.9']))
        self.monitor=DNSMonitor(public_config(self.config),self.root,clock=lambda:self.tick,wall=lambda:self.wall)
        self.status()
    def tearDown(self):self.temp.cleanup()
    def status(self,state='healthy'): (self.root/'status.json').write_text(json.dumps(dict(state=state,updated=self.wall)))
    def cycle(self,local=True,upstream=True):
        def probe(value):
            self.tick+=.025
            if isinstance(value,Exception):raise value
            return value
        with patch.object(self.monitor,'probe_local',side_effect=lambda kind:probe(local(kind) if callable(local) else local)),patch.object(self.monitor,'probe_upstream',side_effect=lambda address:probe(upstream(address) if callable(upstream) else upstream)):
            self.monitor.cycle()
        return read_health(self.config,self.root/'health.json',self.wall)

    def test_healthy_degraded_all_failed_local_failed_and_publisher_stale(self):
        self.assertEqual(self.cycle()['state'],'healthy')
        result=self.cycle(upstream=lambda address:address=='1.1.1.1');self.assertEqual(result['state'],'degraded')
        self.assertEqual(self.cycle(upstream=False)['state'],'failed')
        self.assertEqual(self.cycle(local=lambda kind:kind=='UDP')['state'],'failed')
        self.wall+=16;self.assertEqual(self.cycle()['state'],'unknown')
        self.status('failed');self.assertEqual(self.cycle()['state'],'failed')

    def test_timeouts_latency_last_success_bounded_history_and_no_query_names(self):
        self.cycle();self.wall+=1;self.cycle(upstream=dns.exception.Timeout())
        data=self.monitor.snapshot();row=data['upstreams']['1.1.1.1']
        self.assertEqual(row['count'],2);self.assertEqual(row['success'],1);self.assertEqual(row['failure'],1);self.assertEqual(row['reason'],'Timeout');self.assertEqual(row['last_success'],1000.)
        self.assertAlmostEqual(row['mean_ms'],25.)
        for _ in range(80):self.status();self.cycle()
        data=self.monitor.snapshot();self.assertEqual(len(data['history']),72)
        for secret in ('portal.example','query[A]','cookies','code','10.40.134.100'):self.assertNotIn(secret,json.dumps(data))

    def test_restart_zero_samples_stale_missing_malformed_symlink_and_configuration_change(self):
        self.monitor.publish();self.assertEqual(read_health(self.config,self.root/'health.json',self.wall)['state'],'unknown')
        self.cycle();self.assertEqual(read_health(self.config,self.root/'health.json',self.wall+31)['state'],'unknown')
        other=DNSMonitor(public_config(self.config),self.root,wall=lambda:self.wall)
        self.assertNotEqual(other.boot_id,self.monitor.boot_id);self.assertEqual(other.snapshot()['local']['UDP']['count'],0)
        changed=dict(self.config,dns_upstreams=['8.8.8.8']);self.assertEqual(read_health(changed,self.root/'health.json',self.wall)['state'],'unknown')
        path=self.root/'health.json';data=json.loads(path.read_text());del data['local'];path.write_text(json.dumps(data));self.assertEqual(read_health(self.config,path,self.wall)['state'],'unknown')
        path.unlink();path.symlink_to(self.root/'status.json');self.assertEqual(read_health(self.config,path,self.wall)['state'],'unknown')
        self.assertEqual(read_health(dict(self.config,dns_mode='external'),path,self.wall)['state'],'not configured')

    def test_real_udp_tcp_local_probes_and_invalid_upstream_rcode(self):
        runtime=dict(public_config(self.config),listen_ipv4='127.0.0.1',client_networks=['127.0.0.0/8'])
        path=self.root/'rules.json';path.write_text('{"domains":[]}')
        resolver=Resolver(runtime,Rules(path));udp,tcp=servers(runtime,resolver,port=0)
        workers=[threading.Thread(target=server.serve_forever,daemon=True) for server in (udp,tcp)]
        for worker in workers:worker.start()
        try:
            monitor=DNSMonitor(runtime,self.root,port=udp.server_address[1])
            self.assertTrue(monitor.probe_local('UDP'));self.assertTrue(monitor.probe_local('TCP'))
            query=dns.message.make_query('.','NS');response=dns.message.make_response(query)
            response.answer.append(dns.rrset.from_text('.',30,'IN','NS','a.root-servers.net.'))
            with patch('dns.query.udp_with_fallback',return_value=(response,False)) as send:
                self.assertTrue(monitor.probe_upstream('1.1.1.1'));self.assertEqual(send.call_args.kwargs['timeout'],1)
            response.set_rcode(dns.rcode.SERVFAIL)
            with patch('dns.query.udp_with_fallback',return_value=(response,False)):self.assertFalse(monitor.probe_upstream('1.1.1.1'))
        finally:
            for server in (udp,tcp):server.shutdown();server.server_close()
            for worker in workers:worker.join()


class DNSHealthWebTests(BrowserWebFixture,unittest.TestCase):
    def test_admin_only_read_only_not_configured_and_snapshot(self):
        self.assertEqual(self.request('/admin/api/dns-health').status_code,302)
        self.request('/admin/login','POST',dict(csrf=self.csrf(),password='admin'))
        result=self.request('/admin/api/dns-health');self.assertEqual(result.status_code,200);self.assertEqual(result.json['state'],'not configured')
        with patch('access_gate.dns_health_view.read_health',return_value=dict(state='unknown',stale=True,snapshot=None,message='No recent samples')):
            page=self.request('/admin/dns-health');self.assertEqual(page.status_code,200);self.assertIn(b'No recent samples',page.data)


    def test_complete_snapshot_renders_without_triggering_network_work(self):
        self.request('/admin/login','POST',dict(csrf=self.csrf(),password='admin'))
        config=normalize(dict(self.config,dns_mode='builtin',dns_upstreams=['1.1.1.1']))
        monitor=DNSMonitor(public_config(config),self.root)
        (self.root/'status.json').write_text(json.dumps(dict(state='healthy',updated=time.time())))
        with patch.object(monitor,'probe_local',return_value=True),patch.object(monitor,'probe_upstream',return_value=True):monitor.cycle()
        result=read_health(config,self.root/'health.json')
        self.assertEqual(result['state'],'healthy')
        with patch('access_gate.dns_health_view.read_health',return_value=result),patch.object(DNSMonitor,'cycle',side_effect=AssertionError('No probe during portal request')):
            page=self.request('/admin/dns-health');self.assertEqual(page.status_code,200)
            self.assertIn(b'Configured upstream probes',page.data);self.assertIn(b'1.1.1.1',page.data)
            self.assertEqual(self.request('/admin/api/dns-health').json['state'],'healthy')
