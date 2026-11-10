import io
import socket
import ssl
import unittest
from unittest.mock import Mock, patch

from access_gate.blocklist import (PublicHTTPSConnection, download_blocklist, parse_blocklist,
                                   public_addresses, source_url)
from access_gate.core import GateError
from test_browser_portal import BrowserWebFixture


class BlocklistParserTests(unittest.TestCase):
    def test_hosts_plain_idn_aliases_comments_and_simple_abp(self):
        result = parse_blocklist('''# Example hosts file
127.0.0.1 localhost localhost.localdomain
::1 ip6-localhost
0.0.0.0 0.0.0.0
0.0.0.0 Example.COM www.example.com # comment
:: example.com
198.51.100.1 another.example
BÜCHER.de
*.wildcard.example
||abp.example^
! Source comment
[Adblock Plus 2.0]
@@||allowed.example^
||unsupported.example^$third-party
https://not-a-domain.example/path
''')
        self.assertEqual(result['domains'], {'example.com', 'www.example.com', 'another.example',
            'xn--bcher-kva.de', 'wildcard.example', 'abp.example'})
        self.assertEqual(result['duplicates'], 1)
        self.assertEqual(result['skipped'], 7)

    def test_empty_html_binary_and_unsupported_input_are_rejected(self):
        for value in ('', '# comments only', '<!DOCTYPE html>\nexample.com', '<html>example.com</html>',
                      'example.com\x00', '@@||exception.example^', 'localhost.localdomain'):
            with self.subTest(value=value), self.assertRaises(GateError): parse_blocklist(value)

    def test_exact_scope_does_not_turn_star_rules_into_exact_hosts(self):
        result = parse_blocklist('*.wildcard.example\nplain.example', 'exact')
        self.assertEqual(result['domains'], {'plain.example'})
        self.assertEqual(result['skipped'], 1)
        with self.assertRaises(GateError): parse_blocklist('example.com', 'invalid')

    def test_size_and_unique_limits_do_not_return_partial_results(self):
        with patch('access_gate.blocklist.MAX_BYTES', 10):
            with self.assertRaises(GateError): parse_blocklist('example.com\n')
        with patch('access_gate.blocklist.MAX_DOMAINS', 2):
            with self.assertRaises(GateError): parse_blocklist('one.example\ntwo.example\nthree.example')


class FakeResponse:
    def __init__(self, text=b'0.0.0.0 example.com\n', status=200, headers=None):
        self.body = io.BytesIO(text); self.status = status
        self.headers = headers or {}
    def getheader(self, name, default=None): return self.headers.get(name, default)
    def read1(self, amount): return self.body.read1(amount)
    def close(self): self.body.close()


class BlocklistDownloadTests(unittest.TestCase):
    def fetch(self, responses, url='https://lists.example/hosts'):
        connections = []
        def make(host, address, timeout):
            connection = Mock(); connection.getresponse.return_value = responses[len(connections)]
            connections.append(connection); return connection
        with patch('access_gate.blocklist.public_addresses', return_value=['93.184.216.34']), \
             patch('access_gate.blocklist.PublicHTTPSConnection', side_effect=make) as factory:
            result = download_blocklist(url)
        return result, connections, factory

    def test_url_validation(self):
        self.assertEqual(source_url('https://LISTS.example/hosts?raw=1'), ('lists.example', '/hosts?raw=1'))
        for url in ('http://lists.example/hosts', 'file:///etc/passwd', 'https://user:pass@lists.example/hosts',
                    'https://lists.example:8443/hosts', 'https://127.0.0.1/', 'https://10.40.22.5/',
                    'https://[::1]/', 'https://lists.example/#fragment', 'https://lis\nts.example/',
                    'https://lists.local/hosts', 'https://lists.example/\r\nInjected: value'):
            with self.subTest(url=url), self.assertRaises(GateError): source_url(url)

    def test_resolver_rejects_any_private_or_special_address(self):
        for address in ('127.0.0.1', '10.40.22.5', '169.254.169.254', '192.168.1.1', '::1',
                        'fc00::1', 'fe80::1', '224.0.0.1', '0.0.0.0', '192.0.2.1'):
            answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 443)),
                       (socket.AF_INET, socket.SOCK_STREAM, 6, '', (address, 443))]
            with self.subTest(address=address), patch('access_gate.blocklist.socket.getaddrinfo', return_value=answers), self.assertRaises(GateError):
                public_addresses('lists.example')
        with patch('access_gate.blocklist.socket.getaddrinfo', return_value=[]), self.assertRaises(GateError):
            public_addresses('lists.example')

    def test_pinned_connection_keeps_verified_hostname_and_closes_failed_tls_socket(self):
        context = ssl.create_default_context(); raw = Mock(); wrapped = Mock()
        with patch('access_gate.blocklist.ssl.create_default_context', return_value=context), \
             patch('access_gate.blocklist.socket.create_connection', return_value=raw) as connect, \
             patch.object(context, 'wrap_socket', return_value=wrapped) as wrap:
            connection = PublicHTTPSConnection('lists.example', '93.184.216.34', 2)
            connection.connect()
            connect.assert_called_once_with(('93.184.216.34', 443), timeout=2)
            wrap.assert_called_once_with(raw, server_hostname='lists.example')
            self.assertTrue(context.check_hostname)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertIs(connection.sock, wrapped)
        with patch('access_gate.blocklist.socket.create_connection', return_value=raw), \
             patch.object(connection._context, 'wrap_socket', side_effect=ssl.SSLError('bad certificate')):
            with self.assertRaises(ssl.SSLError): connection.connect()
            raw.close.assert_called_once()

    def test_success_and_relative_redirect_use_plain_bytes_and_no_proxy_environment(self):
        result, connections, factory = self.fetch([FakeResponse(status=302, headers={'Location': '/raw'}),
                                                   FakeResponse(text=b'\xef\xbb\xbfexample.com\n')])
        self.assertEqual(result, 'example.com\n')
        self.assertEqual(factory.call_args_list[1].args[:2], ('lists.example', '93.184.216.34'))
        self.assertEqual(connections[1].request.call_args.args, ('GET', '/raw'))
        self.assertEqual(connections[1].request.call_args.kwargs['headers']['Accept-Encoding'], 'identity')
        for connection in connections: connection.close.assert_called_once()

    def test_redirect_to_private_host_is_rejected_before_second_connection(self):
        connection = Mock(); connection.getresponse.return_value = FakeResponse(status=302, headers={'Location': 'https://private.example/raw'})
        def resolve(host, *args, **kwargs):
            address = '10.40.22.5' if host == 'private.example' else '93.184.216.34'
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (address, 443))]
        with patch('access_gate.blocklist.socket.getaddrinfo', side_effect=resolve), \
             patch('access_gate.blocklist.PublicHTTPSConnection', return_value=connection) as factory:
            with self.assertRaises(GateError): download_blocklist('https://lists.example/raw')
            factory.assert_called_once()
            connection.close.assert_called_once()

    def test_http_errors_html_compression_invalid_utf8_and_truncated_content_fail(self):
        cases = [FakeResponse(status=404), FakeResponse(headers={'Content-Type': 'text/html; charset=utf-8'}),
                 FakeResponse(headers={'Content-Encoding': 'gzip'}), FakeResponse(text=b'\xff'),
                 FakeResponse(headers={'Content-Length': '999'}), FakeResponse(headers={'Content-Length': 'invalid'})]
        for response in cases:
            with self.subTest(response=response), self.assertRaises(GateError): self.fetch([response])

    def test_redirect_loop_downgrade_and_download_size_limits(self):
        with self.assertRaises(GateError): self.fetch([FakeResponse(status=302, headers={'Location': '/again'}) for _ in range(4)])
        with self.assertRaises(GateError): self.fetch([FakeResponse(status=302, headers={'Location': 'http://lists.example/raw'})])
        for response in (FakeResponse(text=b'example.com\n', headers={'Content-Length': '12'}), FakeResponse(text=b'example.com\n')):
            with patch('access_gate.blocklist.MAX_BYTES', 5), self.assertRaises(GateError): self.fetch([response])

    def test_download_deadline_and_socket_errors_are_bounded_failures(self):
        with patch('access_gate.blocklist.time.monotonic', side_effect=[0, 20]), self.assertRaises(GateError):
            self.fetch([FakeResponse()])
        with patch('access_gate.blocklist.public_addresses', return_value=['93.184.216.34']), \
             patch('access_gate.blocklist.PublicHTTPSConnection', side_effect=TimeoutError('timed out')), self.assertRaises(GateError):
            download_blocklist('https://lists.example/raw')


class BlocklistImportWebTests(BrowserWebFixture, unittest.TestCase):
    def login(self): self.request('/admin/login', 'POST', dict(csrf=self.csrf(), password='admin'))
    def import_url(self, scope='subdomains', csrf=True):
        data = dict(url='https://lists.example/hosts', scope=scope)
        if csrf: data['csrf'] = self.csrf()
        return self.request('/admin/dns-domains/import', 'POST', data)

    def test_admin_and_csrf_are_required_before_fetching(self):
        with patch('access_gate.web.download_blocklist') as fetch:
            self.assertEqual(self.import_url().status_code, 302)
            self.login()
            self.assertEqual(self.import_url(csrf=False).status_code, 400)
            self.assertEqual(self.import_url(scope='invalid').status_code, 400)
            fetch.assert_not_called()
        self.assertEqual(self.store.list_dns_domains(), [])

    def test_import_counts_uses_fixed_target_and_preserves_existing_rules_and_grants(self):
        self.activate(); self.login()
        browser=self.client.get_cookie('__Host-accessgate-browser',domain='10.40.22.5').value
        deadline = self.store.browser_grant(browser)['expires']
        self.store.add_dns_domains('existing.example', scope='exact')
        self.store.change_dns_domain('existing.example', 'disable')
        source = '0.0.0.0 new.example existing.example\n:: new.example\n127.0.0.1 localhost\n'
        with patch('access_gate.web.download_blocklist', return_value=source) as fetch:
            response = self.import_url()
            fetch.assert_called_once_with('https://lists.example/hosts')
        self.assertEqual(response.status_code, 302)
        page = self.request('/admin/dns-domains')
        self.assertIn(b'Imported 1 new domains; 1 already listed', page.data)
        self.assertIn(b'1 source duplicates and 1 unsupported/local entries', page.data)
        rows = self.store.list_dns_domains()
        self.assertEqual(rows[0]['enabled'], 0); self.assertEqual(rows[0]['include_subdomains'], 0)
        self.assertIn('address=/new.example/10.40.22.5', self.store.export_dns_domains('dnsmasq'))
        self.assertEqual(self.store.browser_grant(browser)['expires'], deadline)

    def test_failed_fetch_parse_or_cap_preserves_every_existing_row(self):
        self.login(); self.store.add_dns_domains('existing.example')
        before = self.store.list_dns_domains()
        with patch('access_gate.web.download_blocklist', side_effect=GateError('Download failed.')):
            self.assertEqual(self.import_url().status_code, 400)
        with patch('access_gate.web.download_blocklist', return_value='<html>broken</html>'):
            self.assertEqual(self.import_url().status_code, 400)
        with patch('access_gate.web.download_blocklist', return_value='new.example\nother.example'), patch('access_gate.dns_export.MAX_DOMAINS', 2):
            self.assertEqual(self.import_url().status_code, 400)
        self.assertEqual(self.store.list_dns_domains(), before)

    def test_import_is_additive_and_not_a_source_subscription(self):
        self.login()
        for source in ('first.example\nsecond.example', 'second.example\nthird.example'):
            with patch('access_gate.web.download_blocklist', return_value=source): self.import_url(scope='exact')
        self.assertEqual([r['domain'] for r in self.store.list_dns_domains()], ['first.example', 'second.example', 'third.example'])
        with patch('access_gate.web.download_blocklist') as fetch:
            self.request('/admin/dns-domains'); self.request('/domains.txt')
            fetch.assert_not_called()

    def test_large_import_pagination_search_preview_and_complete_feeds(self):
        self.login()
        source = ''.join(f'0.0.0.0 site{i:05}.example\n' for i in range(80000))
        with patch('access_gate.web.download_blocklist', return_value=source):
            self.assertEqual(self.import_url().status_code, 302)
        self.assertEqual(self.store.dns_summary()['total'], 80000)
        page = self.request('/admin/dns-domains')
        self.assertIn(b'80000 enabled of 80000', page.data)
        self.assertIn(b'Page 1 of 800', page.data)
        self.assertNotIn(b'site79999.example', page.data)
        self.assertLess(len(page.data), 150000)
        searched = self.request('/admin/dns-domains?q=site79999&page=999')
        self.assertIn(b'site79999.example', searched.data)
        self.assertIn(b'Page 1 of 1', searched.data)
        second = self.store.dns_domain_page(page=2)
        self.assertEqual(second['items'][0]['domain'], 'site00100.example')
        self.assertEqual(len(second['items']), 100)
        self.assertEqual(self.store.export_dns_domains('dnsmasq', limit=50).count('address='), 50)
        self.assertIn(b'10.40.22.5 site79999.example', self.request('/domains.txt').data)
        self.assertIn(b'address=/site79999.example/10.40.22.5', self.request('/pihole.conf').data)


if __name__ == '__main__': unittest.main()
