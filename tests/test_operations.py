import concurrent.futures
import datetime as dt
import json
from pathlib import Path
import secrets
import time
import unittest
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from access_gate.core import GateError
from access_gate.operations import page_path
from gateway_fixtures import ca
from test_browser_portal import BrowserWebFixture


class OperationsStoreTests(BrowserWebFixture,unittest.TestCase):
    def grant(self,count=1):
        batch,codes=self.store.create_batch(count=count)
        self.store.redeem(codes[0],'10.40.135.11',browser_token='a'*64)
        return batch,codes,self.store.browser_grant('a'*64)
    def record(self,grant,**kwargs):
        data=dict(id=secrets.token_hex(16),session_id=grant['session_id'],origin='https://example.org',path='/page?secret=SHOULD-NOT-LOG#fragment',navigation=True,status=200)
        data.update(kwargs);return data
    def test_domain_default_and_explicit_page_logging_strip_queries_and_fragments(self):
        batch,codes,grant=self.grant();record=self.record(grant)
        self.store.record_visit(record)
        self.assertEqual(self.store.history('domains',code_id=grant['code'])['total'],1)
        self.assertEqual(self.store.history('pages',code_id=grant['code'])['total'],0)
        with self.store.connect() as db:self.assertIsNone(db.execute('SELECT path FROM website_visits').fetchone()[0])
        policy=self.store.activity_settings();self.store.save_activity_settings('pages',30,policy['version'])
        self.store.record_visit(self.record(grant))
        pages=self.store.history('pages',code_id=grant['code'])['items'];self.assertEqual(pages[0]['path'],'/page')
        with self.store.connect() as db:dump=' '.join(db.iterdump())
        for secret in ('SHOULD-NOT-LOG','fragment',codes[0],codes[0].replace('-',''),'a'*64):self.assertNotIn(secret,dump)
    def test_visits_are_code_scoped_idempotent_and_off_stops_new_records(self):
        batch,codes,grant=self.grant();record=self.record(grant)
        self.assertTrue(self.store.record_visit(record));self.assertFalse(self.store.record_visit(record))
        _,other=self.store.create_batch(count=1)
        with self.store.connect() as db:other_id=db.execute('SELECT id FROM codes WHERE digest=?',(self.store.digest(other[0]),)).fetchone()[0]
        self.assertEqual(self.store.history('domains',code_id=other_id)['total'],0)
        policy=self.store.activity_settings();self.store.save_activity_settings('off',30,policy['version'])
        self.assertFalse(self.store.record_visit(self.record(grant,origin='https://other.org')))
        self.assertEqual(self.store.history('domains',code_id=grant['code'])['items'][0]['requests'],1)
    def test_page_scope_excludes_resources_callbacks_and_existing_paths_when_disabled(self):
        _,_,grant=self.grant();policy=self.store.activity_settings();self.store.save_activity_settings('pages',30,policy['version'])
        self.store.record_visit(self.record(grant,path='/one',navigation=True))
        self.store.record_visit(self.record(grant,path='/script.js',navigation=False))
        self.store.record_visit(self.record(grant,path='/__access_gate/complete?ticket=secret',navigation=True))
        self.assertEqual(self.store.history('pages',code_id=grant['code'])['total'],1)
        policy=self.store.activity_settings();self.store.save_activity_settings('domains',30,policy['version'])
        self.assertEqual(self.store.history('pages',code_id=grant['code'])['total'],0)
    def test_activity_events_track_code_lifecycle_and_filters(self):
        batch,codes,grant=self.grant();self.store.extend(grant['session_id'],1,'hours','b'*32)
        self.store.revoke(grant['code']);self.store.clear_revoked()
        events=self.store.history(code_id=grant['code'])['items']
        self.assertTrue({'code.activated','session.extended','code.revoked'}<={r['event'] for r in events})
        self.assertEqual(self.store.history(code_id=grant['code'],event='session.extended')['total'],1)
        self.assertEqual(self.store.history(batch_id=batch,event='session.extended')['total'],1)
        self.assertEqual(self.store.history(code_id=grant['code'],actor='Visitor')['items'][0]['event'],'code.activated')
        self.assertEqual(self.store.code_detail(grant['code'])['hint'],codes[0][-4:])
    def test_retention_cleanup_preserves_consumption_revocation_and_marks_expiry_once(self):
        batch,codes,grant=self.grant()
        old=time.time()-40*86400
        self.store.record_visit(self.record(grant),now=old)
        self.store.audit('code.failed',actor='Visitor',now=old)
        with self.store.connect() as db:db.execute('UPDATE grants SET expires=? WHERE session_id=?',(time.time()-10,grant['session_id']))
        self.store.cleanup_activity(force=True);self.store.cleanup_activity(force=True)
        self.assertEqual(self.store.history('domains',code_id=grant['code'])['total'],0)
        self.assertEqual(self.store.history(code_id=grant['code'],event='session.expired')['total'],1)
        with self.store.connect() as db:self.assertIsNotNone(db.execute('SELECT used FROM codes WHERE id=?',(grant['code'],)).fetchone()[0])
        with self.assertRaises(GateError):self.store.redeem(codes[0],'10.40.135.12',browser_token='c'*64)
    def test_visit_delivery_uses_original_response_time_not_queue_delay(self):
        _,_,grant=self.grant();stamp=time.time()-120
        self.store.record_visit(self.record(grant,created=stamp))
        self.assertEqual(self.store.history('domains',code_id=grant['code'])['items'][0]['last_seen'],stamp)
        with self.assertRaises(GateError):self.store.record_visit(self.record(grant,created=float('nan')))

    def test_policy_validation_and_stale_save_preserve_settings(self):
        before=self.store.activity_settings()
        for mode,days,version in (('bad',30,before['version']),('pages',0,before['version']),('pages',366,before['version']),('pages',30,'stale')):
            with self.assertRaises(GateError):self.store.save_activity_settings(mode,days,version)
            self.assertEqual(self.store.activity_settings(),before)
    def test_remove_batch_revokes_access_and_retains_hidden_code_history(self):
        batch,codes,grant=self.grant()
        self.store.record_visit(self.record(grant))
        self.assertEqual(self.store.remove_batches([batch]),1)
        self.assertIsNone(self.store.browser_grant('a'*64))
        self.assertEqual(self.store.list_batches()['total'],0)
        self.assertEqual(self.store.list_codes()['total'],0)
        self.assertEqual(self.store.list_batches(view='removed')['total'],1)
        self.assertEqual(self.store.remove_batches([batch]),0)
        self.assertTrue(self.store.code_detail(grant['code'])['revoked'])
        self.assertEqual(self.store.history('domains',code_id=grant['code'])['total'],1)
        self.store.initialize()
        with self.assertRaises(GateError):self.store.redeem(codes[0],'10.40.135.12',browser_token='c'*64)
    def test_bulk_removal_only_removes_reviewed_revoked_batches_and_rolls_back_errors(self):
        first,_=self.store.create_batch();second,_=self.store.create_batch();active,_=self.store.create_batch()
        self.store.revoke_batch(first);reviewed=[r['id'] for r in self.store.removable_batches()]
        self.store.revoke_batch(second)
        self.assertEqual(self.store.remove_batches(reviewed+[active],revoked_only=True),1)
        self.assertIsNone(self.store.batch_detail(second)['removed_at'])
        self.assertFalse(self.store.batch_detail(active)['revoked'])
        with self.assertRaises(GateError):self.store.remove_batches([active,'f'*16])
        self.assertFalse(self.store.batch_detail(active)['revoked'])
    def test_request_is_browser_owned_deduplicated_and_persistent(self):
        rid,created=self.store.submit_request('a'*64,'10.40.22.99','example.org','Visitor','Please')
        self.assertTrue(created)
        same,created=self.store.submit_request('a'*64,'10.40.22.100','example.org','Other','Different')
        self.assertEqual(same,rid);self.assertFalse(created)
        self.assertEqual(self.store.requests_page('b'*64)['total'],0)
        self.store.initialize();self.assertEqual(self.store.notifications()['unread'],1)
        self.assertEqual(self.store.requests_page('a'*64)['items'][0]['id'],rid)
        self.assertIsNone(self.store.browser_grant('a'*64))
    def test_concurrent_duplicate_request_creates_one_notification(self):
        def submit(_):return self.store.submit_request('a'*64,'10.40.22.99','example.org')
        with concurrent.futures.ThreadPoolExecutor(2) as pool:results=list(pool.map(submit,range(2)))
        self.assertEqual(len({r[0] for r in results}),1);self.assertEqual(sum(r[1] for r in results),1)
    def test_request_rate_limits_validation_read_resolve_and_expiry(self):
        for i in range(3):self.store.submit_request('a'*64,'10.40.22.99',f'site{i}.org')
        with self.assertRaises(GateError):self.store.submit_request('a'*64,'10.40.22.99','four.org')
        for i in range(2):self.store.submit_request(secrets.token_hex(32),'10.40.22.99',f'other{i}.org')
        with self.assertRaises(GateError):self.store.submit_request('f'*64,'10.40.22.99','six.org')
        rid=self.store.requests_page('a'*64)['items'][0]['id']
        self.assertTrue(self.store.change_request(rid,'read'));self.assertFalse(self.store.change_request(rid,'read'))
        self.assertTrue(self.store.change_request(rid,'resolve'));self.assertFalse(self.store.change_request(rid,'dismiss'))
        self.assertEqual(self.store.requests_page('a'*64,state='resolved')['total'],1)
        self.store.cleanup_activity(now=time.time()+86401,force=True)
        self.assertEqual(self.store.notifications()['unread'],0)
        self.assertIsNone(self.store.browser_grant('a'*64))
        with self.assertRaises(GateError):self.store.submit_request('b'*64,'10.40.22.100',reason='x'*501)
    def test_history_time_domain_pagination_and_bulk_web_preview_are_bounded(self):
        batch,codes,grant=self.grant()
        for i in range(105):self.store.record_visit(self.record(grant,origin=f'https://site{i}.org'))
        first=self.store.history('domains',code_id=grant['code']);second=self.store.history('domains',code_id=grant['code'],page=2)
        self.assertEqual((first['total'],len(first['items']),len(second['items'])),(105,100,5))
        self.assertEqual(self.store.history('domains',code_id=grant['code'],domain='site104')['total'],1)
        self.assertEqual(self.store.history('domains',code_id=grant['code'],since=time.time()+60)['total'],0)
        self.store.remove_batches([batch]);self.assertEqual(self.store.revoked_visible(),0)
        self.assertGreater(self.store.revoked_visible(batch),0)

    def test_failed_mutation_does_not_leave_success_activity(self):
        batch,codes,grant=self.grant()
        before=self.store.history(event='batch.removed')['total']
        with self.assertRaises(GateError):self.store.remove_batches([batch,'f'*16])
        self.assertEqual(self.store.history(event='batch.removed')['total'],before)
        self.assertFalse(self.store.batch_detail(batch)['revoked'])

    def test_migration_keeps_policy_grants_and_codes(self):
        batch,codes,grant=self.grant();self.store.save_admin_security(self.config,exclusions=['10.40.32.20/32'])
        with self.store.connect() as db:
            for table in ('website_visits','access_requests','activity_events','activity_policy','session_end_events'):db.execute('DROP TABLE '+table)
            db.execute('ALTER TABLE batches DROP COLUMN removed_at');db.execute('PRAGMA user_version=6')
        self.store.initialize()
        self.assertEqual(self.store.admin_security(self.config)['exclusions'],['10.40.32.20/32'])
        self.assertEqual(self.store.browser_grant('a'*64)['expires'],grant['expires'])
        self.assertEqual(self.store.activity_settings()['mode'],'domains')
        self.assertEqual(self.store.code_detail(grant['code'])['hint'],codes[0][-4:])
    def test_path_and_visit_validation(self):
        self.assertEqual(page_path('/path?q=secret#x'),'/path')
        for value in ('https://evil.org','//evil.org/path','/internal/check','/bad\npath',None):self.assertIsNone(page_path(value))
        _,_,grant=self.grant()
        for data in (self.record(grant,id=1),self.record(grant,session_id=None),self.record(grant,status=True),self.record(grant,origin='https://127.0.0.1')):
            with self.assertRaises(GateError):self.store.record_visit(data)


class OperationsWebTests(BrowserWebFixture,unittest.TestCase):
    def login(self):return self.request('/admin/login','POST',dict(csrf=self.csrf(),password='admin'))
    def test_new_admin_routes_and_mutations_require_authentication_csrf(self):
        for path in ('/admin/activity','/admin/requests','/admin/api/notifications'):
            self.assertEqual(self.request(path).status_code,302)
        batch,codes=self.store.create_batch()
        self.assertEqual(self.request('/admin/batches/'+batch+'/remove').status_code,302)
        self.login()
        for path in ('/admin/activity/settings','/admin/batches/'+batch+'/remove','/admin/batches/clear-revoked'):
            self.assertEqual(self.request(path,'POST',{}).status_code,400)
    def test_portal_requests_use_validated_entry_and_isolate_same_ip_browsers(self):
        nonce='d'*64;entry=self.store.new_entry('https://example.org',nonce)
        result=self.request('/request-access?entry='+entry,'POST',dict(csrf=self.csrf(),entry=entry,label='<script>x</script>',reason='A reason',domain='evil.org'))
        self.assertEqual(result.status_code,303)
        page=self.request('/request-access');self.assertIn(b'example.org',page.data);self.assertNotIn(b'<script>x</script>',page.data)
        self.assertNotIn(b'evil.org',page.data)
        self.assertNotIn(b'example.org',self.request('/request-access',client=self.app.test_client()).data)
        self.assertFalse(self.request('/status').json['active'])
        self.assertEqual(self.request('/request-access','POST',dict(label='Visitor')).status_code,400)
        self.assertEqual(self.request('/request-access?entry=missing').status_code,400)
    def test_notifications_inbox_and_actions_do_not_grant_access(self):
        rid,_=self.store.submit_request('a'*64,'10.40.22.99','example.org')
        self.login();self.assertEqual(self.request('/admin/api/notifications').json['unread'],1)
        self.assertIn(b'example.org',self.request('/admin/requests').data)
        path='/admin/requests/'+rid
        self.assertIn(b'No code or access is issued automatically',self.request(path).data)
        self.assertEqual(self.request(path,'POST',dict(csrf=self.csrf(),action='resolve')).status_code,302)
        self.assertEqual(self.request('/admin/api/notifications').json['unread'],0)
        self.assertEqual(self.store.requests_page('a'*64)['items'][0]['state'],'resolved')
        self.assertIsNone(self.store.browser_grant('a'*64))
    def test_code_links_history_and_retained_removed_batch_views(self):
        batch,codes=self.store.create_batch();self.store.redeem(codes[0],'10.40.22.99',browser_token='a'*64)
        grant=self.store.browser_grant('a'*64)
        self.store.record_visit(dict(id='f'*32,session_id=grant['session_id'],origin='https://example.org',status=200))
        self.login()
        self.assertIn(('/admin/codes/'+grant['code']).encode(),self.request('/admin/batches/'+batch).data)
        self.assertIn(b'example.org',self.request('/admin/codes/'+grant['code']).data)
        self.assertIn(b'Activity log',self.request('/admin/activity').data)
        self.assertEqual(self.request('/admin/codes/'+grant['code']+'?view=events').status_code,200)
        self.assertEqual(self.request('/admin/activity?until=9999-12-31').status_code,400)
        self.assertEqual(self.request('/admin/batches/'+batch+'/remove','POST',dict(csrf=self.csrf())).status_code,302)
        self.assertIn(b'Removed',self.request('/admin/batches?view=removed').data)
        self.assertIn(b'example.org',self.request('/admin/codes/'+grant['code']).data)
    def test_multiple_administrators_see_consistent_request_read_state(self):
        rid,_=self.store.submit_request('a'*64,'10.40.22.99','example.org')
        self.login();other=self.app.test_client()
        self.request('/admin/login','POST',dict(csrf=self.csrf(other),password='admin'),client=other)
        self.assertEqual(self.request('/admin/api/notifications',client=other).json['unread'],1)
        self.request('/admin/requests/'+rid,'POST',dict(csrf=self.csrf(),action='read'))
        self.assertEqual(self.request('/admin/api/notifications',client=other).json['unread'],0)
        self.assertEqual(self.request('/admin/batches/clear-revoked').status_code,200)

    def test_cleared_codes_remain_discoverable_in_removed_batch_history(self):
        batch,codes=self.store.create_batch(count=1)
        with self.store.connect() as db:code_id=db.execute('SELECT id FROM codes WHERE batch=?',(batch,)).fetchone()[0]
        self.store.revoke_batch(batch);self.store.clear_revoked(batch);self.store.remove_batches([batch])
        self.login()
        page=self.request('/admin/batches/'+batch)
        self.assertIn(('/admin/codes/'+code_id).encode(),page.data)
        self.assertIn(b'Cleared from normal list',page.data)
        self.assertEqual(self.request('/admin/activity?since=2026-11-11&until=2026-11-10').status_code,400)

    def test_history_settings_require_current_password_and_store_page_mode(self):
        self.login();policy=self.store.activity_settings()
        data=dict(csrf=self.csrf(),mode='pages',retention_days='7',version=policy['version'],current_password='bad')
        self.assertEqual(self.request('/admin/activity/settings','POST',data).status_code,400)
        data['current_password']='admin'
        self.assertEqual(self.request('/admin/activity/settings','POST',data).status_code,302)
        self.assertEqual(self.store.activity_settings()['mode'],'pages')
        self.assertEqual(self.store.activity_settings()['retention_days'],7)
    def test_ca_link_and_public_download_for_code_active_and_excluded_visitors(self):
        certificate,key=ca('Public test root')
        path=self.root/'public.crt';path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        self.assertIn(b'href="/ca.crt"',self.request().data)
        self.activate();self.assertIn(b'href="/ca.crt"',self.request().data)
        self.login();self.assertIn(b'href="/ca.crt"',self.request().data)
        with patch('access_gate.web.PUBLIC_CA',path):
            response=self.request('/ca.crt',client=self.app.test_client())
            self.assertEqual(response.status_code,200)
            self.assertEqual(x509.load_pem_x509_certificate(response.data).serial_number,certificate.serial_number)
            self.assertIn('attachment',response.headers['Content-Disposition']);self.assertNotIn(b'PRIVATE KEY',response.data)
            response.close()
    def test_visit_and_cleanup_api_are_private(self):
        for path in ('/internal/activity/visit','/internal/activity/cleanup'):
            self.assertEqual(self.rpc(path,{},key='wrong').status_code,403)
        self.assertEqual(self.rpc('/internal/activity/visit',{}).status_code,400)
        self.assertEqual(self.rpc('/internal/activity/cleanup',{}).status_code,200)
