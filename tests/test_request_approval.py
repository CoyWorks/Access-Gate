import concurrent.futures
import secrets
import time
import unittest
from access_gate.core import GateError
from test_browser_portal import BrowserWebFixture


class RequestApprovalStoreTests(BrowserWebFixture,unittest.TestCase):
    def pending(self,token='a'*64,now=None):return self.store.submit_request(token,'10.40.22.99','example.org',now=now)[0]
    def test_approve_creates_direct_browser_grant_and_history_without_redeemable_code(self):
        rid=self.pending();now=time.time()
        result=self.store.decide_request(rid,'approve',15,'minutes',now)
        grant=self.store.browser_grant('a'*64,now)
        self.assertEqual(grant['session_id'],result['session_id']);self.assertEqual(grant['expires'],now+900)
        self.assertIsNone(self.store.browser_grant('b'*64,now))
        self.assertEqual(self.store.own_request_status(rid,'a'*64,now)['state'],'approved')
        self.assertEqual(self.store.notifications(now)['unread'],0)
        code=self.store.code_detail(result['code_id']);self.assertIsNotNone(code['used']);self.assertEqual(code['hint'],'AUTO')
        self.assertEqual(self.store.history(code_id=result['code_id'],event='request.approved',now=now)['total'],1)
        self.assertEqual(self.store.request_detail(rid)['approval_code_id'],result['code_id'])
    def test_deny_is_terminal_and_does_not_grant_or_revoke_unrelated_access(self):
        rid=self.pending();self.store.decide_request(rid,'deny')
        self.assertEqual(self.store.own_request_status(rid,'a'*64)['state'],'denied')
        self.assertIsNone(self.store.browser_grant('a'*64));self.assertEqual(self.store.list_batches()['total'],0)
        with self.assertRaises(GateError):self.store.decide_request(rid,'approve')
        self.assertFalse(self.store.decide_request(rid,'deny')['changed'])
    def test_duplicate_approval_does_not_extend_or_revive_expired_access(self):
        rid=self.pending();first=self.store.decide_request(rid,'approve',15,'minutes')
        second=self.store.decide_request(rid,'approve',15,'minutes')
        self.assertFalse(second['changed']);self.assertEqual(first['expires'],second['expires'])
        self.assertEqual(self.store.list_batches()['total'],1)
        with self.assertRaises(GateError):self.store.decide_request(rid,'approve',1,'hours')
        self.store.terminate_session(first['session_id'])
        self.store.decide_request(rid,'approve',15,'minutes')
        self.assertFalse(self.store.own_request_status(rid,'a'*64)['active'])
    def test_existing_access_is_extended_once_and_deny_preserves_it(self):
        _,codes=self.store.create_batch(count=1);self.store.redeem(codes[0],'10.40.22.99',browser_token='a'*64)
        before=self.store.browser_grant('a'*64);rid=self.pending()
        result=self.store.decide_request(rid,'approve',1,'hours')
        self.assertEqual(result['session_id'],before['session_id']);self.assertEqual(result['expires'],before['expires']+3600)
        self.store.decide_request(rid,'approve',1,'hours');self.assertEqual(len(self.store.extension_history()),1)
        second=self.pending();self.store.decide_request(second,'deny')
        self.assertEqual(self.store.browser_grant('a'*64)['expires'],result['expires'])
    def test_expired_requests_and_invalid_durations_cannot_grant_access(self):
        rid=self.pending(now=time.time()-86401)
        with self.assertRaises(GateError):self.store.decide_request(rid,'approve')
        fresh=self.pending('b'*64)
        for value,unit in ((0,'minutes'),(169,'hours'),(1,'days')):
            with self.assertRaises(GateError):self.store.decide_request(fresh,'approve',value,unit)
        self.assertIsNone(self.store.browser_grant('a'*64));self.assertIsNone(self.store.browser_grant('b'*64))
    def test_approval_deny_race_has_one_atomic_outcome(self):
        rid=self.pending()
        def decide(action):
            try:return self.store.decide_request(rid,action)['changed']
            except GateError:return False
        with concurrent.futures.ThreadPoolExecutor(2) as pool:outcomes=list(pool.map(decide,['approve','deny']))
        self.assertEqual(sum(outcomes),1)
        state=self.store.own_request_status(rid,'a'*64)
        self.assertEqual(bool(self.store.browser_grant('a'*64)),state['state']=='approved')
    def test_two_administrators_cannot_double_approve_and_state_survives_restart(self):
        rid=self.pending()
        with concurrent.futures.ThreadPoolExecutor(2) as pool:results=list(pool.map(lambda _:self.store.decide_request(rid,'approve'),range(2)))
        self.assertEqual(sum(r['changed'] for r in results),1)
        self.store.initialize();self.assertTrue(self.store.own_request_status(rid,'a'*64)['active'])
        self.assertEqual(self.store.list_batches()['total'],1)
    def test_same_ip_or_request_id_is_not_enough_to_claim_approved_session(self):
        rid=self.pending();self.store.decide_request(rid,'approve')
        with self.assertRaises(GateError):self.store.own_request_status(rid,'b'*64)
        self.assertIsNone(self.store.browser_grant('b'*64))
        item=self.store.request_detail(rid);self.store.revoke(item['approval_code_id'])
        self.assertFalse(self.store.own_request_status(rid,'a'*64)['active'])
    def test_reapproval_of_new_request_uses_fresh_token_after_revocation(self):
        rid=self.pending();first=self.store.decide_request(rid,'approve')
        self.store.revoke(first['code_id']);other=self.pending();second=self.store.decide_request(other,'approve')
        self.assertNotEqual(first['code_id'],second['code_id']);self.assertTrue(self.store.own_request_status(other,'a'*64)['active'])
        self.assertFalse(self.store.own_request_status(rid,'a'*64)['active'])


class RequestApprovalWebTests(BrowserWebFixture,unittest.TestCase):
    def login(self,client=None):return self.request('/admin/login','POST',dict(csrf=self.csrf(client),password='admin'),client=client)
    def submit(self,domain='example.org'):
        nonce='d'*64;entry=self.store.new_entry('https://'+domain,nonce)
        response=self.request('/request-access','POST',dict(csrf=self.csrf(),entry=entry))
        self.assertEqual(response.status_code,303)
        return response.headers['Location'].split('request=')[1]
    def decide(self,rid,action='approve',client=None,**kwargs):
        data=dict(csrf=self.csrf(client),action=action,value='15',unit='minutes');data.update(kwargs)
        return self.request('/admin/requests/'+rid,'POST',data,client=client)
    def test_admin_approval_unlocks_requesting_browser_and_continue_is_safe(self):
        rid=self.submit();admin=self.app.test_client();self.login(admin)
        self.assertEqual(self.decide(rid,client=admin).status_code,302)
        result=self.request('/request-access/status?request='+rid).json
        self.assertTrue(result['active']);self.assertEqual(result['state'],'approved')
        self.assertNotIn('browser_hash',str(result));self.assertNotIn('code_id',result)
        continued=self.request(result['continue_url']+'?next=https://evil.org')
        self.assertEqual(continued.headers['Location'],'https://example.org/')
        self.assertEqual(self.request('/admin').status_code,302)
        self.assertTrue(self.request('/request-access/status?request='+rid,ip='10.40.135.99').json['active'])
    def test_unauthorized_csrf_and_cross_browser_requests_cannot_approve_or_claim(self):
        rid=self.submit();self.assertEqual(self.decide(rid).status_code,302)
        self.assertFalse(self.request('/status').json['active'])
        admin=self.app.test_client();self.login(admin)
        self.assertEqual(self.decide(rid,client=admin,csrf='invalid').status_code,400)
        self.assertEqual(self.decide(rid,action='resolve',client=admin).status_code,400)
        self.assertEqual(self.store.request_detail(rid)['status'],'pending')
        self.decide(rid,client=admin)
        other=self.app.test_client()
        self.assertEqual(self.request('/request-access/status?request='+rid,client=other).status_code,400)
        self.assertEqual(self.request('/request-access/'+rid+'/continue',client=other).status_code,400)
    def test_deny_is_visible_without_unlocking_and_re_request_keeps_owned_domain(self):
        rid=self.submit();admin=self.app.test_client();self.login(admin)
        self.decide(rid,'deny',client=admin)
        result=self.request('/request-access/status?request='+rid).json
        self.assertEqual(result['state'],'denied');self.assertFalse(result['active']);self.assertIsNone(result['continue_url'])
        page=self.request('/request-access?request='+rid);self.assertIn(b'data-request-id',page.data)
        response=self.request('/request-access','POST',dict(csrf=self.csrf(),previous_request=rid,domain='evil.org'))
        new_id=response.headers['Location'].split('request=')[1]
        self.assertEqual(self.store.request_detail(new_id)['domain'],'example.org')
    def test_approved_request_links_to_token_history_and_revocation_controls(self):
        rid=self.submit();admin=self.app.test_client();self.login(admin);self.decide(rid,client=admin)
        page=self.request('/admin/requests/'+rid,client=admin)
        item=self.store.request_detail(rid)
        self.assertIn(('/admin/codes/'+item['approval_code_id']).encode(),page.data)
        self.assertIn(b'Stop access',page.data)
        self.assertIn(b'Approved access token',self.request('/admin/codes/'+item['approval_code_id'],client=admin).data)
        self.store.terminate_session(item['approval_session_id'])
        self.assertFalse(self.request('/request-access/status?request='+rid).json['active'])
    def test_status_polls_do_not_extend_approved_deadline(self):
        rid=self.submit();admin=self.app.test_client();self.login(admin);self.decide(rid,client=admin)
        expires=self.request('/request-access/status?request='+rid).json['expires']
        for _ in range(3):self.assertEqual(self.request('/request-access/status?request='+rid).json['expires'],expires)
