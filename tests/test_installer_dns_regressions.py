"""Regression coverage for the built-in DNS installation path."""
import unittest
from unittest.mock import patch

import dns.exception
import dns.message
import dns.query
import dns.rrset

from access_gate.deployment import normalize
from access_gate.dns_service import DNSReadinessError,wait_for_dns
from access_gate.installer import preflight,profile


class Clock:
    def __init__(self):self.value=0;self.delays=[]
    def now(self):return self.value
    def sleep(self,seconds):self.delays.append(seconds);self.value+=seconds


class InstallerDNSRegressions(unittest.TestCase):
    def config(self):
        return profile(dict(deployment_version=1,server_ipv4='10.40.22.6',
                            listen_ipv4='10.40.22.6',dns_target_ipv4='10.40.22.6',
                            portal_url='https://10.40.22.6',portal_aliases=[],
                            client_networks=['10.40.22.0/24','127.0.0.1/32','::1/128'],
                            admin_networks=['10.40.22.0/24'],dns_mode='builtin',
                            dns_upstreams=['10.40.22.10']))

    def runtime(self):
        return dict(listen_ipv4='10.40.22.6',dns_target_ipv4='10.40.22.6',
                    portal_names=['10.40.22.6'])

    def answer(self,address='10.40.22.6'):
        query=dns.message.make_query('10.40.22.6','A')
        response=dns.message.make_response(query)
        response.answer.append(dns.rrset.from_text(query.question[0].name,30,'IN','A',address))
        return response

    def test_dedicated_dns_port_only_conflicts_at_selected_address(self):
        c=self.config()
        preflight(c,addresses=['10.40.22.6'],listeners=['127.0.0.54:53','10.40.22.10:53'])
        for listener in ('0.0.0.0:53','[::]:53','*:53','10.40.22.6:53',
                         '[::ffff:10.40.22.6]:53','unknown:53'):
            with self.subTest(listener=listener),self.assertRaisesRegex(ValueError,'occupied'):
                preflight(c,addresses=['10.40.22.6'],listeners=[listener])
        with self.assertRaisesRegex(ValueError,'occupied'):
            preflight(c,addresses=['10.40.22.6'],listeners=['127.0.0.1:443'])

    def test_explicit_client_network_survives_normalization(self):
        c=self.config()
        self.assertEqual(c['client_networks'],['10.40.22.0/24','127.0.0.1/32','::1/128'])
        self.assertEqual(normalize(c)['client_networks'],c['client_networks'])
        legacy=normalize(dict(portal_url='https://10.40.22.5'))
        self.assertIn('10.40.0.0/16',legacy['client_networks'])

    def test_transient_timeout_recovers_and_checks_both_transports(self):
        clock=Clock();calls=[];good=self.answer()
        def udp(*args,**kwargs):
            calls.append(('udp',kwargs['timeout']))
            if len(calls)==1:raise dns.exception.Timeout()
            return good
        def tcp(*args,**kwargs):calls.append(('tcp',kwargs['timeout']));return good
        with patch('dns.query.udp',udp),patch('dns.query.tcp',tcp):
            wait_for_dns(self.runtime(),clock=clock.now,sleep=clock.sleep)
        self.assertEqual([kind for kind,_ in calls],['udp','udp','tcp'])
        self.assertEqual(clock.delays,[1])

    def test_timeout_has_one_budget_and_reports_last_failure(self):
        clock=Clock()
        def udp(*args,**kwargs):
            clock.value+=kwargs['timeout']
            raise dns.exception.Timeout()
        with patch('dns.query.udp',udp),patch('dns.query.tcp') as tcp:
            with self.assertRaisesRegex(DNSReadinessError,'timed out'):
                wait_for_dns(self.runtime(),timeout=5,clock=clock.now,sleep=clock.sleep)
            tcp.assert_not_called()
        self.assertEqual(clock.value,5)

    def test_wrong_answer_fails_immediately(self):
        clock=Clock()
        with patch('dns.query.udp',return_value=self.answer('10.40.22.99')) as udp,patch('dns.query.tcp') as tcp:
            with self.assertRaisesRegex(DNSReadinessError,'unexpected answer'):
                wait_for_dns(self.runtime(),clock=clock.now,sleep=clock.sleep)
            self.assertEqual(udp.call_count,1);tcp.assert_not_called()
        self.assertEqual(clock.delays,[])

    def test_udp_success_does_not_hide_tcp_failure(self):
        clock=Clock()
        def tcp(*args,**kwargs):
            clock.value+=kwargs['timeout']
            raise dns.exception.Timeout()
        with patch('dns.query.udp',return_value=self.answer()),patch('dns.query.tcp',tcp):
            with self.assertRaisesRegex(DNSReadinessError,'TCP'):
                wait_for_dns(self.runtime(),timeout=5,clock=clock.now,sleep=clock.sleep)
        self.assertEqual(clock.value,5)


if __name__=='__main__':unittest.main()
