import json,time,unittest
from unittest.mock import patch
from access_gate.performance import Metrics,STAGES
from test_browser_portal import BrowserWebFixture


class PerformanceTests(unittest.TestCase):
    def test_attribution_histogram_failures_and_fixed_memory(self):
        ticks=iter([10.,10.02,20.,20.1]);metrics=Metrics(clock=lambda:next(ticks))
        with metrics.measure('certificate_generate'):pass
        with self.assertRaises(ValueError):
            with metrics.measure('authorization'):raise ValueError('synthetic')
        for _ in range(10000):metrics.observe('certificate_hit',.0001)
        result=metrics.snapshot();self.assertEqual(result['stages']['certificate_hit']['count'],10000)
        self.assertAlmostEqual(result['stages']['certificate_generate']['mean_ms'],20)
        self.assertEqual(result['stages']['authorization']['failed'],1)
        self.assertEqual(result['stages']['certificate_generate']['p95_upper_ms'],25)
        self.assertEqual(set(result['stages']),set(STAGES))
        with self.assertRaises(ValueError):metrics.observe('private.example',1)
        self.assertNotIn('synthetic',json.dumps(result));self.assertEqual(sum(len(r['buckets']) for r in metrics.data.values()),140)

    def test_contended_writer_drops_without_waiting_and_restart_is_distinct(self):
        metrics=Metrics();metrics.lock.acquire()
        try:metrics.observe('policy_lookup',1)
        finally:metrics.lock.release()
        self.assertEqual(metrics.snapshot()['dropped'],1);self.assertEqual(metrics.snapshot()['stages']['policy_lookup']['count'],0)
        self.assertNotEqual(metrics.boot_id,Metrics().boot_id)


class PerformanceWebTests(BrowserWebFixture,unittest.TestCase):
    def test_admin_only_snapshot_and_unavailable_state(self):
        self.assertEqual(self.request('/admin/api/performance').status_code,302)
        self.request('/admin/login','POST',dict(csrf=self.csrf(),password='admin'))
        metrics=Metrics().snapshot()
        with patch.object(self.app.extensions['health'],'performance',return_value=metrics):
            self.assertEqual(self.request('/admin/api/performance').json['format'],1)
            self.assertIn(b'Gateway performance',self.request('/admin/performance').data)
        with patch.object(self.app.extensions['health'],'performance',side_effect=OSError()):self.assertEqual(self.request('/admin/api/performance').status_code,503)


class BenchmarkTests(unittest.TestCase):
    def test_real_local_policy_and_cold_warm_callback(self):
        import tempfile,threading
        from pathlib import Path
        from werkzeug.serving import make_server
        from access_gate.web import create_app
        from access_gate.benchmark_tls import benchmark
        from test_gateway import settings,QuietHandler
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            portal=dict(secret='secret',pepper='pepper',acl_token='key',admin_hash='unused',database=str(root/'db'),portal_url='https://portal.example',client_networks=['127.0.0.0/8'])
            app=create_app(portal);app.extensions['store'].initialize();app.extensions['store'].add_dns_domains('restricted.example')
            server=make_server('127.0.0.1',0,app,threaded=True,request_handler=QuietHandler)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                config=settings(root,portal);config['api_url']=f'http://127.0.0.1:{server.server_port}'
                result=benchmark(config,'restricted.example',10)
                self.assertEqual(result['metrics']['stages']['certificate_generate']['count'],1)
                self.assertEqual(result['metrics']['stages']['certificate_hit']['count'],10)
                print('Local callback benchmark:',json.dumps({k:v for k,v in result.items() if k!='metrics'}))
            finally:server.shutdown();server.server_close();thread.join()
