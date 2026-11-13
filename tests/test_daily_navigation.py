import unittest
from html.parser import HTMLParser
from test_browser_portal import BrowserWebFixture

class Forms(HTMLParser):
    def __init__(self,html):super().__init__();self.forms=[];self.current=None;self.feed(html)
    def handle_starttag(self,tag,attrs):
        attrs=dict(attrs)
        if tag=='form':self.current=dict(attrs,inputs=[]);self.forms.append(self.current)
        if tag=='input' and self.current is not None:self.current['inputs'].append(attrs)
    def handle_endtag(self,tag):
        if tag=='form':self.current=None

class DailyNavigationTests(BrowserWebFixture,unittest.TestCase):
    def login(self):self.request('/admin/login','POST',dict(csrf=self.csrf(),password='admin'))
    def test_home_and_more_reuse_safe_search_and_existing_task_destinations(self):
        self.login()
        for path,prefix in [('/admin','home'),('/admin/more','more')]:
            response=self.request(path);self.assertEqual(response.status_code,200)
            forms=Forms(response.data.decode()).forms
            searches=[f for f in forms if f.get('action')=='/admin/dns-domains']
            self.assertEqual(len(searches),1);self.assertEqual(searches[0]['method'],'get')
            field=next(i for i in searches[0]['inputs'] if i.get('name')=='q')
            self.assertEqual(field['id'],prefix+'-domain-search');self.assertEqual(field['maxlength'],'253')
            self.assertIn(('for="'+field['id']+'"').encode(),response.data)
            for link in ('/admin/requests','/admin/sessions','/setup'):
                self.assertIn(('href="'+link+'"').encode(),response.data)
            self.assertIn(b'aria-label="Quick actions"',response.data)
        self.store.add_dns_domains('example.org\nother.example')
        result=self.request('/admin/dns-domains?q=example.org')
        self.assertIn(b'example.org',result.data);self.assertNotIn(b'<td>other.example</td>',result.data)
        self.assertFalse(self.store.list_grants())
    def test_daily_work_precedes_setup_and_health_remains_visible(self):
        self.login();page=self.request('/admin').data
        self.assertLess(page.index(b'Pending requests</h2>'),page.index(b'Setup checklist available'))
        self.assertLess(page.index(b'Active sessions</h2>'),page.index(b'Setup checklist available'))
        self.assertLess(page.index(b'id="dashboard-health"'),page.index(b'Pending requests</h2>'))
        self.assertIn(b'System status has not been checked yet',page)
        self.assertIn(b'Skip to content',page)
    def test_pending_reviews_and_failed_sources_are_not_hidden_in_maintenance(self):
        sid=self.store.create_subscription('Test source','https://example.org/hosts')
        with self.store.connect() as db:db.execute("UPDATE blocklist_sources SET pending='review',status='refresh failed' WHERE id=?",(sid,))
        self.login()
        for path in ('/admin','/admin/more'):
            page=self.request(path).data
            self.assertIn(b'1 pending list reviews',page);self.assertIn(b'1 failed refreshes',page)
            self.assertIn(b'Review blocklist subscriptions',page)
            if path.endswith('more'):self.assertLess(page.index(b'Domain lists need attention'),page.index(b'Deployment &amp; maintenance'))
        with self.store.connect() as db:self.assertEqual(db.execute('SELECT pending FROM blocklist_sources WHERE id=?',(sid,)).fetchone()[0],'review')
    def test_more_keeps_technical_tools_under_native_keyboard_disclosure(self):
        self.login();page=self.request('/admin/more').data
        self.assertIn(b'<summary>Deployment &amp; maintenance</summary>',page)
        for link in ('/admin/server-settings','/admin/updates','/admin/recovery','/admin/support','/admin/client-diagnostics','/admin/setup'):
            self.assertIn(('href="'+link+'"').encode(),page)
