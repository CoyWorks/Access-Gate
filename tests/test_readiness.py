import ssl
import unittest
import urllib.error
from unittest.mock import Mock,patch

from access_gate.readiness import NoRedirect,ReadinessError,https_probe,wait_for_portal


class Clock:
    def __init__(self): self.value=0; self.delays=[]
    def now(self): return self.value
    def sleep(self,seconds): self.delays.append(seconds); self.value+=seconds


class ReadinessTests(unittest.TestCase):
    def test_transient_502_and_refused_connection_recover(self):
        clock=Clock()
        probe=Mock(side_effect=[urllib.error.URLError(ConnectionRefusedError('starting')),urllib.error.HTTPError('https://portal/',502,'Bad Gateway',{},None),200])
        wait_for_portal(probe,clock=clock.now,sleep=clock.sleep)
        self.assertEqual(probe.call_count,3)
        self.assertEqual(clock.delays,[1,1])

    def test_persistent_502_fails_with_last_status_without_false_success(self):
        clock=Clock(); probe=Mock(return_value=502)
        with self.assertRaisesRegex(ReadinessError,'Last result: HTTP 502'):
            wait_for_portal(probe,timeout=3,clock=clock.now,sleep=clock.sleep)
        self.assertEqual(clock.value,3)

    def test_slow_requests_stay_inside_remaining_budget(self):
        clock=Clock(); timeouts=[]
        def probe(timeout):
            timeouts.append(timeout); clock.value+=timeout
            raise TimeoutError('backend not responding')
        with self.assertRaisesRegex(ReadinessError,'backend not responding'):
            wait_for_portal(probe,timeout=5,clock=clock.now,sleep=clock.sleep)
        self.assertEqual(timeouts,[3,1]); self.assertEqual(clock.value,5)

    def test_tls_verification_failure_is_not_retried_or_ignored(self):
        clock=Clock(); probe=Mock(side_effect=urllib.error.URLError(ssl.SSLCertVerificationError('untrusted')))
        with self.assertRaisesRegex(ReadinessError,'TLS certificate verification failed'):
            wait_for_portal(probe,clock=clock.now,sleep=clock.sleep)
        self.assertEqual(probe.call_count,1); self.assertEqual(clock.delays,[])

    def test_redirect_is_not_mistaken_for_ready_portal(self):
        self.assertIsNone(NoRedirect().redirect_request(None,None,302,'redirect',{},'https://elsewhere/'))
        clock=Clock()
        with self.assertRaisesRegex(ReadinessError,'HTTP 302'):
            wait_for_portal(Mock(return_value=302),timeout=1,clock=clock.now,sleep=clock.sleep)

    def test_local_probe_uses_verified_tls_and_explicitly_disables_proxies(self):
        response=Mock(); response.status=200
        response.__enter__=Mock(return_value=response); response.__exit__=Mock(return_value=False)
        opener=Mock(); opener.open.return_value=response
        with patch('access_gate.readiness.ssl.create_default_context') as context,patch('access_gate.readiness.urllib.request.build_opener',return_value=opener) as build,patch('access_gate.readiness.urllib.request.HTTPSHandler') as https,patch('access_gate.readiness.urllib.request.ProxyHandler') as proxies:
            self.assertEqual(https_probe('/retained/ca.crt')(2),200)
            context.assert_called_once_with(cafile='/retained/ca.crt')
            proxies.assert_called_once_with({})
            https.assert_called_once_with(context=context.return_value)
            self.assertEqual(opener.open.call_args.kwargs['timeout'],2)


if __name__=='__main__': unittest.main()
