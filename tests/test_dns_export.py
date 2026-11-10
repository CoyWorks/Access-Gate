import concurrent.futures
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from access_gate.core import Store, GateError
from access_gate.dns_export import hostname
from test_browser_portal import BrowserWebFixture


class DNSExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name)/'db'
        self.store = Store(self.path, 'pepper')
        self.store.initialize()

    def tearDown(self): self.temp.cleanup()

    def test_normalization_duplicate_and_disabled_entry_behavior(self):
        self.assertEqual(self.store.add_dns_domains('Example.COM.\nexample.com\nBÜCHER.de\n# comment\n'), (2, 0))
        self.assertEqual([r['domain'] for r in self.store.list_dns_domains()], ['example.com', 'xn--bcher-kva.de'])
        self.store.change_dns_domain('example.com', 'disable')
        self.assertEqual(self.store.add_dns_domains('EXAMPLE.COM\nnew.example'), (1, 1))
        self.assertEqual(self.store.list_dns_domains()[0]['enabled'], 0)

    def test_reject_urls_ips_wildcards_config_injection_and_bad_hostnames(self):
        for value in ('https://example.com', 'example.com/path', '*.example.com', 'example.com:443',
                      '1.1.1.1', 'localhost', 'test..com', 'a..', '-bad.example', 'bad_.example',
                      'example.com,1.1.1.1', 'example.com\x00', 'a'*64+'.com', 'bad name.com',
                      'example.com/#', 'example.com\tother.com', 'example.com\nconf-script=evil'):
            with self.subTest(value=value), self.assertRaises(GateError): hostname(value)

    def test_invalid_bulk_add_is_atomic_and_reports_line(self):
        self.store.add_dns_domains('existing.example')
        with self.assertRaisesRegex(GateError, 'Line 2:'):
            self.store.add_dns_domains('valid.example\nhttps://invalid.example')
        self.assertEqual([r['domain'] for r in self.store.list_dns_domains()], ['existing.example'])
        for text in ('', '\n# nothing\n', 'x'*12001):
            with self.assertRaises(GateError): self.store.add_dns_domains(text)

    def test_formats_export_only_enabled_exact_sorted_hosts(self):
        self.store.add_dns_domains('www.example.com\nexample.com\nignored.example', scope='exact')
        self.store.change_dns_domain('ignored.example', 'disable')
        def records(kind): return [s for s in self.store.export_dns_domains(kind).splitlines() if not s.startswith('#')]
        self.assertEqual(records('hosts'), ['10.40.22.5 example.com', '10.40.22.5 www.example.com'])
        self.assertEqual(records('dnsmasq'), ['host-record=example.com,10.40.22.5', 'host-record=www.example.com,10.40.22.5'])
        self.store.change_dns_domain('example.com', 'delete')
        self.store.change_dns_domain('ignored.example', 'enable')
        self.assertEqual(records('hosts'), ['10.40.22.5 ignored.example', '10.40.22.5 www.example.com'])
        with self.assertRaises(GateError): self.store.export_dns_domains('shell')

    def test_empty_export_is_valid_comment_only_and_unknown_actions_do_not_mutate(self):
        self.assertTrue(all(line.startswith('#') for line in self.store.export_dns_domains('dnsmasq').splitlines()))
        self.store.add_dns_domains('example.com')
        for name, action in (('example.com', 'toggle'), ('missing.example', 'disable')):
            with self.assertRaises(GateError): self.store.change_dns_domain(name, action)
        self.assertEqual(self.store.list_dns_domains()[0]['enabled'], 1)

    def test_wildcard_default_covers_apex_and_subdomains_without_aaaa_upstream(self):
        self.assertEqual(self.store.add_dns_domains('example.com\n*.example.com\n*.BÜCHER.de'), (2, 0))
        self.assertTrue(all(r['include_subdomains'] for r in self.store.list_dns_domains()))
        records = [s for s in self.store.export_dns_domains('dnsmasq').splitlines() if not s.startswith('#')]
        self.assertEqual(records, ['address=/example.com/10.40.22.5', 'local=/example.com/',
                                   'address=/xn--bcher-kva.de/10.40.22.5', 'local=/xn--bcher-kva.de/'])
        with self.assertRaisesRegex(GateError, 'cannot represent subdomain'):
            self.store.export_dns_domains('hosts')

    def test_match_scope_changes_and_duplicates_do_not_silently_broaden_rules(self):
        self.store.add_dns_domains('example.com', scope='exact')
        self.store.add_dns_domains('*.example.com')
        self.assertFalse(self.store.list_dns_domains()[0]['include_subdomains'])
        self.store.change_dns_domain('example.com', 'subdomains')
        self.assertIn('address=/example.com/10.40.22.5', self.store.export_dns_domains('dnsmasq'))
        self.store.change_dns_domain('example.com', 'exact')
        self.assertIn('host-record=example.com,10.40.22.5', self.store.export_dns_domains('dnsmasq'))
        self.assertIn('10.40.22.5 example.com', self.store.export_dns_domains('hosts'))
        with self.assertRaises(GateError): self.store.add_dns_domains('*.other.example', scope='exact')
        with self.assertRaises(GateError): self.store.add_dns_domains('other.example', scope='anything')

    def test_limit_rejects_entire_batch(self):
        with patch('access_gate.dns_export.MAX_DOMAINS', 2):
            self.store.add_dns_domains('first.example')
            with self.assertRaises(GateError): self.store.add_dns_domains('second.example\nthird.example')
        self.assertEqual(len(self.store.list_dns_domains()), 1)

    def test_concurrent_bulk_add_does_not_duplicate(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(self.store.add_dns_domains, ['example.com', 'EXAMPLE.COM']))
        self.assertEqual(sum(r[0] for r in results), 1)
        self.assertEqual(len(self.store.list_dns_domains()), 1)

    def test_schema_three_upgrade_preserves_browser_codes_and_no_legacy_domain_activation(self):
        _, codes = self.store.create_batch(count=2, now=1000)
        self.store.redeem(codes[0], '10.40.22.99', 1000, browser_token='a'*64)
        end = self.store.browser_grant('a'*64, 1000)['expires']
        with self.store.connect() as db:
            db.execute('DROP TABLE dns_export_domains')
            db.execute('CREATE TABLE domain_rules(domain TEXT)')
            db.execute("INSERT INTO domain_rules VALUES('archived.example')")
            db.execute('PRAGMA user_version=3')
        self.store.initialize()
        self.assertEqual(self.store.list_dns_domains(), [])
        self.assertEqual(self.store.browser_grant('a'*64, 1001)['expires'], end)
        with self.assertRaises(GateError): self.store.redeem(codes[0], '10.40.22.100', 1001, browser_token='b'*64)
        self.store.add_dns_domains('example.com')
        restarted = Store(self.path, 'pepper'); restarted.initialize(); restarted.initialize()
        self.assertEqual(restarted.list_dns_domains()[0]['domain'], 'example.com')
        restarted.redeem(codes[1], '10.40.22.100', 1001, browser_token='b'*64)
        with restarted.connect() as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 4)
            self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(), [])
            self.assertEqual(db.execute('SELECT domain FROM domain_rules').fetchone()[0], 'archived.example')


class DNSExportWebTests(BrowserWebFixture, unittest.TestCase):
    def login(self):
        self.request('/admin/login', 'POST', dict(csrf=self.csrf(), password='admin'))

    def test_list_exports_and_mutations_require_administrator(self):
        for path in ('/admin/dns-domains', '/admin/dns-domains/export/hosts', '/admin/dns-domains/export/dnsmasq'):
            response = self.request(path)
            self.assertEqual(response.status_code, 302)
            self.assertTrue(response.headers['Location'].endswith('/admin/login'))
        for path, data in (('/admin/dns-domains', dict(domains='example.com')),
                           ('/admin/dns-domains/change', dict(domain='example.com', action='delete'))):
            self.assertEqual(self.request(path, 'POST', dict(data, csrf=self.csrf())).status_code, 302)
        self.assertEqual(self.store.list_dns_domains(), [])
        self.assertNotIn(b'DNS domains', self.request().data)

    def test_csrf_is_required_for_add_enable_disable_delete(self):
        self.login(); self.store.add_dns_domains('example.com')
        self.assertEqual(self.request('/admin/dns-domains', 'POST', dict(domains='new.example')).status_code, 400)
        for action in ('disable', 'enable', 'delete', 'exact', 'subdomains'):
            self.assertEqual(self.request('/admin/dns-domains/change', 'POST', dict(domain='example.com', action=action)).status_code, 400)
        self.assertEqual(self.store.list_dns_domains()[0]['enabled'], 1)

    def test_administrator_bulk_add_preview_export_disable_delete(self):
        self.login()
        self.assertEqual(self.request('/admin/dns-domains', 'POST', dict(csrf=self.csrf(), domains='Example.COM\nwww.example.com', scope='exact')).status_code, 302)
        page = self.request('/admin/dns-domains')
        self.assertIn(b'DNS domains', page.data)
        self.assertIn(b'2 enabled of 2', page.data)
        self.assertIn(b'host-record=example.com,10.40.22.5', page.data)
        for kind, filename in (('hosts', 'access-gate.hosts'), ('dnsmasq', '99-access-gate.conf')):
            response = self.request('/admin/dns-domains/export/'+kind)
            self.assertEqual(response.status_code, 200)
            self.assertIn('text/plain', response.content_type)
            self.assertIn(filename, response.headers['Content-Disposition'])
            self.assertEqual(response.headers['Cache-Control'], 'no-store')
            self.assertIn(b'10.40.22.5', response.data)
        for name, action in (('example.com', 'disable'), ('www.example.com', 'delete')):
            self.assertEqual(self.request('/admin/dns-domains/change', 'POST', dict(csrf=self.csrf(), domain=name, action=action)).status_code, 302)
        response = self.request('/admin/dns-domains/export/hosts')
        self.assertNotIn(b'10.40.22.5 example.com', response.data)
        self.assertNotIn(b'www.example.com', response.data)

    def test_invalid_form_preserves_input_escapes_html_and_leaves_list_unchanged(self):
        self.login()
        response = self.request('/admin/dns-domains', 'POST', dict(csrf=self.csrf(), domains='valid.example\n<script>alert(1)</script>'))
        self.assertEqual(response.status_code, 400)
        self.assertIn(b'Line 2:', response.data)
        self.assertIn(b'&lt;script&gt;', response.data)
        self.assertNotIn(b'<script>alert', response.data)
        self.assertEqual(self.store.list_dns_domains(), [])
        self.assertEqual(self.request('/admin/dns-domains/export/shell').status_code, 404)

    def test_wildcard_web_default_preview_and_scope_switch(self):
        self.login()
        self.request('/admin/dns-domains', 'POST', dict(csrf=self.csrf(), domains='*.example.com'))
        page = self.request('/admin/dns-domains')
        self.assertIn(b'Domain + all subdomains', page.data)
        self.assertIn(b'address=/example.com/10.40.22.5', page.data)
        self.assertIn(b'local=/example.com/', page.data)
        self.assertNotIn(b'Download hosts list', page.data)
        self.assertEqual(self.request('/admin/dns-domains/export/hosts').status_code, 400)
        self.assertEqual(self.request('/admin/dns-domains/change', 'POST', dict(csrf=self.csrf(), domain='example.com', action='exact')).status_code, 302)
        self.assertIn(b'Download hosts list', self.request('/admin/dns-domains').data)
        self.assertEqual(self.request('/admin/dns-domains/export/hosts').status_code, 200)


if __name__ == '__main__': unittest.main()
