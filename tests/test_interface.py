import time
import unittest
from html.parser import HTMLParser
from test_browser_portal import BrowserWebFixture


class Links(HTMLParser):
    def __init__(self):super().__init__();self.links=[];self.in_nav=False;self.nav_depth=0;self.primary=[]
    def handle_starttag(self,tag,attrs):
        attrs=dict(attrs)
        if tag=='nav' and attrs.get('class')=='primary-nav':self.in_nav=True
        if tag=='a':
            self.links.append(attrs)
            if self.in_nav:self.primary.append(attrs)
    def handle_endtag(self,tag):
        if tag=='nav':self.in_nav=False


class InterfaceTests(BrowserWebFixture,unittest.TestCase):
    def login(self):self.request('/admin/login','POST',dict(csrf=self.csrf(),password='admin'))
    def new_request(self,owner='a'*64,label='Alex',domain='example.org'):
        return self.store.submit_request(owner,'10.40.40.22',domain,label,'A short break.')[0]
    def test_dashboard_prioritizes_pending_and_omits_code_and_extension_tables(self):
        rid=self.new_request();self.login();page=self.request('/admin');self.assertEqual(page.status_code,200)
        self.assertIn(b'Approve 15 min',page.data);self.assertIn(b'Alex',page.data)
        self.assertLess(page.data.index(b'Pending requests</h2>'),page.data.index(b'Active sessions</h2>'))
        self.assertNotIn(b'Recent access extensions',page.data);self.assertNotIn(b'id="status"',page.data)
        self.assertIn(b'all restricted websites',page.data)
    def test_five_primary_links_and_visitor_shell_has_no_admin_navigation(self):
        self.login();page=self.request('/admin');links=Links();links.feed(page.data.decode())
        self.assertEqual([x['href'] for x in links.primary],['/admin','/admin/requests','/admin/sessions','/admin/batches','/admin/more'])
        self.assertEqual(sum(x.get('aria-current')=='page' for x in links.primary),1)
        portal=self.request('/');self.assertNotIn(b'class="primary-nav"',portal.data);self.assertIn(b'Open administration',portal.data)
        self.assertIn(b'Download CA certificate',portal.data)
    def test_inline_approval_is_csrf_protected_and_redirect_is_allowlisted(self):
        rid=self.new_request();self.login();path='/admin/requests/'+rid
        self.assertEqual(self.request(path,'POST',dict(action='approve',return_to='/admin')).status_code,400)
        response=self.request(path,'POST',dict(csrf=self.csrf(),action='approve',value='30',unit='minutes',return_to='/admin'))
        self.assertEqual(response.status_code,303);self.assertEqual(response.location,'/admin')
        item=self.store.request_detail(rid);self.assertEqual(item['approval_seconds'],1800)
        again=self.request(path,'POST',dict(csrf=self.csrf(),action='approve',value='30',unit='minutes',return_to='https://evil.example/'))
        self.assertEqual(again.location,path);self.assertEqual(self.store.request_detail(rid)['approval_expires'],item['approval_expires'])
    def test_existing_access_preview_says_add_time_and_authoritative_backend_adds_it(self):
        _,codes=self.store.create_batch(count=1);self.store.redeem(codes[0],'10.40.40.22',browser_token='a'*64)
        before=self.store.browser_grant('a'*64)['expires'];rid=self.new_request();self.login()
        page=self.request('/admin/requests');self.assertIn(b'Add 15 min',page.data);self.assertIn(b'Additional time',page.data)
        self.request('/admin/requests/'+rid,'POST',dict(csrf=self.csrf(),action='approve',value='15',unit='minutes',return_to='/admin/requests'))
        self.assertEqual(self.store.browser_grant('a'*64)['expires'],before+900)
    def test_approval_batches_are_not_in_handout_list_but_history_remains(self):
        manual,codes=self.store.create_batch(name='Handout batch',count=2)
        rid=self.new_request();self.store.decide_request(rid,'approve');approval=self.store.request_detail(rid)
        self.assertEqual(self.store.list_batches()['total'],2)
        self.assertEqual(self.store.list_batches(include_approvals=False)['total'],1)
        self.login();page=self.request('/admin/batches')
        self.assertIn(b'Handout batch',page.data);self.assertNotIn(b'Approved request '+rid[:8].encode(),page.data)
        sid=approval['approval_session_id'];detail=self.request('/admin/sessions/'+sid)
        self.assertEqual(detail.status_code,200);self.assertIn(b'Alex',detail.data);self.assertIn(b'example.org',detail.data)
        self.assertIn(('/admin/codes/'+approval['approval_code_id']).encode(),detail.data)
        self.assertNotIn(b'browser_hash',detail.data)
    def test_dashboard_counts_use_real_authorization_and_ready_outputs(self):
        batch,codes=self.store.create_batch(count=3);self.store.redeem(codes[0],'10.40.40.21',browser_token='b'*64)
        self.new_request();sid=self.store.create_schedule(dict(name='Ready schedule',recurrence='daily',clock='09:00',count='2'),'export-password-1234')
        self.store.run_schedule_now(sid,'d'*32)
        home=self.store.ui_home();self.assertEqual(home['pending_count'],1);self.assertEqual(home['active_count'],1);self.assertEqual(home['available_count'],4);self.assertEqual(home['outputs'][0]['ready'],1)
        self.store.revoke_batch(batch);self.assertEqual(self.store.ui_home()['active_count'],0)
    def test_pending_badge_counts_read_requests_too(self):
        rid=self.new_request();self.store.change_request(rid,'read');self.login()
        data=self.request('/admin/api/notifications').json;self.assertEqual(data['pending'],1);self.assertEqual(data['unread'],0)
    def test_session_detail_filters_history_by_its_own_code(self):
        batch,codes=self.store.create_batch(count=2)
        for index,token in enumerate(('a'*64,'b'*64)):
            self.store.redeem(codes[index],'10.40.40.22',browser_token=token);grant=self.store.browser_grant(token)
            self.store.record_visit(dict(id=str(index+1)*32,session_id=grant['session_id'],origin='https://'+('first.example' if index==0 else 'second.example'),status=200))
        sid=self.store.browser_grant('a'*64)['session_id'];self.login();page=self.request('/admin/sessions/'+sid)
        self.assertIn(b'first.example',page.data);self.assertNotIn(b'second.example',page.data)
        self.store.terminate_session(sid);self.assertIn(b'Access has ended',self.request('/admin/sessions/'+sid).data)
    def test_management_destinations_and_secondary_forms_remain_reachable(self):
        self.login();links=Links();links.feed(self.request('/admin/more').data.decode())
        for path in ('/admin/activity','/admin/dns-domains','/admin/settings','/admin/system','/admin/updates','/admin/recovery','/admin/app'):
            self.assertTrue(any(x['href'].split('#')[0]==path for x in links.links));self.assertEqual(self.request(path).status_code,200,path)
        self.assertEqual(self.request('/admin/codes').status_code,200)
        self.assertEqual(self.request('/admin/schedules').status_code,200)
        self.assertEqual(self.request('/admin/batches/new').status_code,200)
    def test_new_admin_routes_require_login_and_management_network(self):
        for path in ('/admin/more','/admin/codes','/admin/sessions/'+'a'*32):self.assertEqual(self.request(path).status_code,302)
    def test_pending_order_is_oldest_first_and_visitor_history_stays_private(self):
        now=time.time();first=self.store.submit_request('a'*64,'10.40.40.20','first.example',now=now-100)[0]
        second=self.store.submit_request('b'*64,'10.40.40.21','second.example',now=now-50)[0]
        self.assertEqual(self.store.requests_page(state='pending')['items'][0]['id'],first)
        self.assertEqual(self.store.requests_page('a'*64)['total'],1)

    def test_restored_admin_login_gets_csrf_for_inline_forms(self):
        self.new_request();self.login()
        with self.client.session_transaction(base_url='https://10.40.22.5') as state:state.pop('csrf',None)
        page=self.request('/admin/requests');self.assertEqual(page.status_code,200)
        with self.client.session_transaction(base_url='https://10.40.22.5') as state:token=state['csrf']
        self.assertIn(('name="csrf" value="'+token+'"').encode(),page.data)
    def test_stale_inline_action_returns_to_inbox_without_changing_decision(self):
        rid=self.new_request();self.login();self.store.decide_request(rid,'deny')
        response=self.request('/admin/requests/'+rid,'POST',dict(csrf=self.csrf(),action='approve',value='30',unit='minutes',return_to='/admin/requests'))
        self.assertEqual(response.status_code,303);self.assertEqual(response.location,'/admin/requests')
        self.assertEqual(self.store.request_detail(rid)['status'],'denied');self.assertIsNone(self.store.browser_grant('a'*64))
    def test_extension_returns_to_its_session_and_keeps_one_time_code_used(self):
        batch,codes=self.store.create_batch(count=1);self.store.redeem(codes[0],'10.40.40.22',browser_token='a'*64)
        grant=self.store.browser_grant('a'*64);self.login()
        response=self.request('/admin/access/'+grant['session_id']+'/extend','POST',dict(csrf=self.csrf(),request_id='e'*32,value='15',unit='minutes'))
        self.assertEqual(response.location,'/admin/sessions/'+grant['session_id'])
        self.assertEqual(self.store.browser_grant('a'*64)['expires'],grant['expires']+900)
        self.assertEqual(self.store.list_codes(batch)['items'][0]['status'],'redeemed')
