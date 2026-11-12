import io
import time
import unittest
from html.parser import HTMLParser
from test_browser_portal import BrowserWebFixture


class PageStructure(HTMLParser):
    def __init__(self):
        super().__init__();self.sections=[];self.h1=0;self.headers=0;self.navs={};self.nav=None;self.header_position=None;self.nav_positions={};self.position=0;self.ids=[];self.breadcrumb_current=0;self.breadcrumb=False
    def handle_starttag(self,tag,attrs):
        self.position+=1;attrs=dict(attrs)
        if attrs.get('id'):self.ids.append(attrs['id'])
        if 'page-intro' in attrs.get('class','').split():self.sections.append(attrs.get('data-page-section'))
        if tag=='header' and 'page-heading' in attrs.get('class','').split():self.headers+=1;self.header_position=self.position
        if tag=='h1':self.h1+=1
        if tag=='nav':
            self.nav=attrs.get('data-section-navigation');self.breadcrumb=attrs.get('aria-label')=='Breadcrumb'
            if self.nav:self.navs[self.nav]=[];self.nav_positions[self.nav]=self.position
        if tag=='a' and self.nav:self.navs[self.nav].append(attrs)
        if self.breadcrumb and attrs.get('aria-current')=='page':self.breadcrumb_current+=1
    def handle_endtag(self,tag):
        if tag=='nav':self.nav=None;self.breadcrumb=False


class PageHeaderTests(BrowserWebFixture,unittest.TestCase):
    def setUp(self):
        super().setUp();self.request('/admin/login','POST',dict(csrf=self.csrf(),password='admin'))
        self.batch,self.codes=self.store.create_batch(name='<Weekly & friends>',count=2)
        self.schedule=self.store.create_schedule(dict(name='Weekly plan',recurrence='daily',clock='09:00'),'schedule-secret-1234')
        with self.store.connect() as db:self.code=db.execute('SELECT id FROM codes WHERE batch=? LIMIT 1',(self.batch,)).fetchone()[0]
    def structure(self,path,method='GET',data=None,section=None,tabs=None):
        response=self.request(path,method,data);self.assertEqual(response.status_code,200,path)
        parsed=PageStructure();parsed.feed(response.data.decode())
        self.assertEqual(parsed.h1,1,path);self.assertEqual(parsed.headers,1,path);self.assertEqual(len(parsed.sections),1,path)
        if section:self.assertEqual(parsed.sections,[section],path)
        if tabs:
            group,active=tabs;links=parsed.navs[group]
            expected=['/admin/batches','/admin/schedules','/admin/codes'] if group=='codes' else ['/admin/system','/admin/client-diagnostics','/admin/dns-health','/admin/updates','/admin/recovery'] if group=='system' else ['/admin/settings','/admin/app','/admin/server-settings']
            self.assertEqual([x['href'] for x in links],expected,path)
            self.assertEqual([x['href'] for x in links if x.get('aria-current')=='page'],[active],path)
            self.assertLess(parsed.header_position,parsed.nav_positions[group],path)
        self.assertLessEqual(parsed.breadcrumb_current,1,path)
        self.assertNotIn(b'<Weekly & friends>',response.data)
        return response,parsed
    def test_all_codes_pages_share_heading_and_persistent_section_tabs(self):
        cases=[('/admin/batches','/admin/batches'),('/admin/batches/new','/admin/batches'),('/admin/batches/'+self.batch,'/admin/batches'),('/admin/batches/'+self.batch+'/revoke','/admin/batches'),('/admin/batches/'+self.batch+'/remove','/admin/batches'),('/admin/batches/clear-revoked','/admin/batches'),('/admin/codes','/admin/codes'),('/admin/codes/'+self.code,'/admin/codes'),('/admin/schedules','/admin/schedules'),('/admin/schedules/new','/admin/schedules'),('/admin/schedules/'+self.schedule,'/admin/schedules')]
        for path,active in cases:
            with self.subTest(path=path):self.structure(path,section='Codes',tabs=('codes',active))
    def test_generated_and_printable_codes_keep_one_time_output_and_export_controls(self):
        base=dict(csrf=self.csrf(),name='Header export',count='2',validity_value='1',validity_unit='days',access_value='15',access_unit='minutes')
        page,parsed=self.structure('/admin/batch','POST',dict(base,export='text'),section='Codes',tabs=('codes','/admin/batches'))
        self.assertEqual(parsed.ids.count('download'),1);self.assertEqual(parsed.ids.count('codes'),1)
        self.assertIn(b'Save these codes now',page.data)
        page,parsed=self.structure('/admin/batch','POST',dict(base,export='print'),section='Codes',tabs=('codes','/admin/batches'))
        self.assertEqual(parsed.ids.count('print-cards'),1);self.assertIn(b'class="no-print"',page.data)
    def test_validation_error_forms_keep_the_same_page_header_and_tabs(self):
        for path,data,active in [('/admin/batch',dict(csrf=self.csrf(),count='0'),'/admin/batches'),('/admin/schedules/new',dict(csrf=self.csrf(),name='bad',current_password='bad'),'/admin/schedules')]:
            page=self.request(path,'POST',data);self.assertEqual(page.status_code,400)
            parsed=PageStructure();parsed.feed(page.data.decode());self.assertEqual(parsed.sections,['Codes']);self.assertEqual(parsed.h1,1)
            self.assertEqual([x['href'] for x in parsed.navs['codes'] if x.get('aria-current')=='page'],[active])
    def test_other_management_groups_use_the_same_header_and_relevant_tabs(self):
        for path in ('/admin','/admin/more','/admin/requests','/admin/sessions','/admin/activity','/admin/dns-domains'):
            with self.subTest(path=path):self.structure(path)
        for path in ('/admin/system','/admin/client-diagnostics','/admin/dns-health','/admin/updates','/admin/recovery'):self.structure(path,section='System',tabs=('system',path))
        for path in ('/admin/settings','/admin/app','/admin/server-settings'):self.structure(path,section='Settings',tabs=('settings',path))
    def test_request_session_and_confirmation_headers_remain_consistent(self):
        rid,_=self.store.submit_request('a'*64,'10.40.40.21','example.org','Alex')
        self.structure('/admin/requests/'+rid,section='Access')
        self.store.decide_request(rid,'approve');sid=self.store.request_detail(rid)['approval_session_id']
        for path in ('/admin/sessions/'+sid,'/admin/access/'+sid+'/extend','/admin/access/'+sid+'/terminate'):self.structure(path,section='Access')
    def test_maintenance_headers_follow_the_job_category(self):
        jobs=self.app.extensions['jobs'];jobs.root=self.root/'jobs';(jobs.root/'results').mkdir(parents=True)
        import json
        for index,action in enumerate(('backup','preflight','restore','update-check','update')):
            jid=str(index+1)*32
            (jobs.root/'results'/(jid+'.json')).write_text(json.dumps(dict(id=jid,action=action,state='complete',message='Done',updated=time.time())))
            self.structure('/admin/maintenance/'+jid,section='System',tabs=('system','/admin/updates' if action.startswith('update') else '/admin/recovery'))
    def test_queued_jobs_keep_their_section_without_exposing_private_inputs(self):
        jobs=self.app.extensions['jobs'];jobs.root=self.root/'queued-jobs';(jobs.root/'inbox').mkdir(parents=True)
        for action in ('update-check','backup'):
            jid=jobs.submit(action,**({'passphrase':'do-not-expose-this-secret'} if action=='backup' else {}))
            response,parsed=self.structure('/admin/maintenance/'+jid,section='System',tabs=('system','/admin/updates' if action=='update-check' else '/admin/recovery'))
            self.assertNotIn(b'do-not-expose-this-secret',response.data)
            self.assertNotIn('passphrase',jobs.status(jid))
    def test_public_portal_does_not_acquire_admin_page_chrome(self):
        page=self.request('/');self.assertNotIn(b'data-page-section=',page.data);self.assertNotIn(b'Codes sections',page.data)
