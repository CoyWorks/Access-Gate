import json,tempfile,unittest
from pathlib import Path
from access_gate.core import Store
from access_gate.domain_policy import DomainPolicy
from access_gate.dns_service import Rules
from access_gate.deployment import normalize
from test_browser_portal import BrowserWebFixture


class PolicyPreviewTests(unittest.TestCase):
    def test_preview_matches_gateway_dns_and_rule_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            store=Store(Path(directory)/'db','pepper');store.initialize()
            store.add_dns_domains('example.co.uk');store.add_dns_domains('exact.example',scope='exact')
            store.add_dns_domains('api.example.co.uk');store.change_dns_domain('api.example.co.uk','disable')
            rows=[dict(domain=r['domain'],include_subdomains=bool(r['include_subdomains'])) for r in store.list_dns_domains() if r['enabled']]
            policy=DomainPolicy.parse({'domains':rows});path=Path(directory)/'rules';path.write_text(json.dumps({'domains':rows}));dns=Rules(path)
            config=normalize({'portal_url':'https://portal.example','dns_mode':'builtin','dns_upstreams':['1.1.1.1']})
            for host in ('example.co.uk','www.example.co.uk','x.api.example.co.uk','exact.example','child.exact.example','no.example','badexample.co.uk'):
                result=store.policy_preview(host,config)
                self.assertEqual(result['restricted'],bool(policy.match(host)));self.assertEqual(result['restricted'],dns.restricted(host))
            result=store.policy_preview('x.api.example.co.uk',config)
            self.assertEqual(result['match']['domain'],'example.co.uk');self.assertEqual(result['ignored'][0]['reason'],'Disabled')
            self.assertEqual(result['builtin_records']['AAAA'],'NOERROR / NODATA')
            store.change_dns_domain('example.co.uk','delete');self.assertFalse(store.policy_preview('x.api.example.co.uk',config)['restricted'])
            store.add_dns_domains('BÜCHER.de');self.assertEqual(store.domain_decision('WWW.BÜCHER.de')['hostname'],'www.xn--bcher-kva.de')


class PolicyPreviewWebTests(BrowserWebFixture,unittest.TestCase):
    def test_admin_only_read_only_preview_and_invalid_input(self):
        self.assertEqual(self.request('/admin/api/domain-policy?hostname=example.com').status_code,302)
        self.request('/admin/login','POST',dict(csrf=self.csrf(),password='admin'))
        self.store.add_dns_domains('example.com');before=self.store.list_dns_domains()
        result=self.request('/admin/api/domain-policy?hostname=www.example.com');self.assertTrue(result.json['restricted'])
        page=self.request('/admin/domain-policy?hostname=www.example.com');self.assertEqual(page.status_code,200);self.assertIn(b'NOERROR / NODATA',page.data)
        self.assertEqual(self.request('/admin/domain-policy?hostname=https://bad.example').status_code,400)
        self.assertEqual(self.store.list_dns_domains(),before)
