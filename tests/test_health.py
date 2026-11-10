import subprocess
import threading
import time
import unittest
from unittest.mock import patch
from access_gate.health import Health
from test_browser_portal import BrowserWebFixture


class HealthTests(BrowserWebFixture,unittest.TestCase):
    def provider(self):return Health(self.config,self.store)
    def commands(self,args):return 'yes' if args[0]=='timedatectl' else 'active'
    def test_healthy_is_not_reported_when_gateway_or_clock_unknown(self):
        provider=self.provider()
        with patch.object(provider,'command',side_effect=OSError()),patch.object(provider,'gateway',side_effect=FileNotFoundError()):result=provider.collect()
        self.assertEqual(result['state'],'warning')
        self.assertTrue(any(c['name']=='Gateway HTTPS' and c['state']=='unknown' for c in result['checks']))
        self.assertTrue(any(c['name']=='Clock synchronization' and c['state']=='unknown' for c in result['checks']))
    def test_failed_service_or_tls_probe_is_visible_without_raw_error_details(self):
        provider=self.provider()
        def command(args):return 'failed' if args[2]=='access-gate-gateway.service' else self.commands(args)
        with patch.object(provider,'command',side_effect=command),patch.object(provider,'gateway',side_effect=OSError('SECRET-PATH')):result=provider.collect()
        self.assertEqual(result['state'],'failed');self.assertNotIn('SECRET-PATH',str(result))
        self.assertTrue(any(c['name']=='access-gate-gateway' and c['state']=='failed' for c in result['checks']))
    def test_timeouts_and_unsynchronized_clock_have_useful_states(self):
        provider=self.provider()
        with patch.object(provider,'command',side_effect=subprocess.TimeoutExpired('systemctl',1)),patch.object(provider,'gateway',return_value=[]):result=provider.collect()
        self.assertEqual(result['state'],'warning')
        with patch.object(provider,'command',side_effect=lambda args:'no' if args[0]=='timedatectl' else 'active'),patch.object(provider,'gateway',return_value=[]):result=provider.collect()
        self.assertTrue(any(c['name']=='Clock synchronization' and c['state']=='warning' for c in result['checks']))
    def test_expiry_threshold_and_cache_staleness(self):
        provider=self.provider();now=time.time()
        self.assertEqual(provider.certificate('CA',now-1,now)['state'],'failed')
        self.assertEqual(provider.certificate('CA',now+86400,now)['state'],'warning')
        self.assertEqual(provider.certificate('CA',now+60*86400,now)['state'],'healthy')
        with patch.object(provider,'collect',return_value=dict(state='healthy',checks=[])) as collect:
            provider.snapshot();provider.snapshot();self.assertEqual(collect.call_count,1)
        provider.checked=0;provider.lock.acquire()
        try:self.assertTrue(provider.snapshot()['stale'])
        finally:provider.lock.release()
        provider.cached=None;provider.lock.acquire()
        try:self.assertEqual(provider.snapshot()['state'],'unknown')
        finally:provider.lock.release()
    def test_status_commands_have_fixed_timeout(self):
        with patch('access_gate.health.subprocess.run',side_effect=subprocess.TimeoutExpired('systemctl',1)) as run:
            with self.assertRaises(subprocess.TimeoutExpired):Health.command(['systemctl','show','nginx.service','--property=ActiveState','--value'])
            self.assertEqual(run.call_args.kwargs['timeout'],1)
