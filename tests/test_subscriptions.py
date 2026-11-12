import tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
from access_gate.core import Store,GateError
from test_browser_portal import BrowserWebFixture


class SubscriptionFixture:
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.store=Store(Path(self.temp.name)/'db','pepper');self.store.initialize();self.now=1000.
    def tearDown(self):self.temp.cleanup()
    def source(self,name='Test',text='one.example\ntwo.example',scope='subdomains'):
        sid=self.store.create_subscription(name,'https://lists.example/'+name,scope,3600,now=self.now)
        self.store.refresh_subscription(sid,fetcher=lambda _:text,now=self.now)
        return sid
    def approve(self,sid):
        item=self.store.subscription_detail(sid);self.store.subscription_action(sid,'approve',item['pending'],now=self.now)
    def names(self):return {r['domain']:r for r in self.store.list_dns_domains()}

class SubscriptionTests(SubscriptionFixture,unittest.TestCase):
    def test_initial_review_manual_ownership_and_overlap_survive_removal(self):
        self.store.add_dns_domains('manual.example',scope='exact');sid=self.source(text='manual.example\none.example')
        self.assertEqual(set(self.names()),{'manual.example'})
        self.approve(sid);self.assertFalse(self.names()['manual.example']['include_subdomains'])
        other=self.source('Other',text='one.example\nother.example',scope='exact');self.approve(other)
        self.store.add_dns_domains('one.example') # explicit manual claim of an existing source domain
        self.store.subscription_action(sid,'remove',now=self.now)
        self.assertEqual(set(self.names()),{'manual.example','one.example','other.example'})
        self.store.subscription_action(other,'remove',now=self.now)
        self.assertEqual(set(self.names()),{'manual.example','one.example'})

    def test_manual_disable_exact_delete_are_not_overwritten_by_refresh(self):
        sid=self.source();self.approve(sid)
        self.store.change_dns_domain('one.example','disable');self.store.change_dns_domain('two.example','delete')
        self.store.refresh_subscription(sid,fetcher=lambda _:'one.example\ntwo.example\nthree.example',now=1001);self.approve(sid)
        self.assertFalse(self.names()['one.example']['enabled']);self.assertNotIn('two.example',self.names())
        self.store.add_dns_domains('two.example',scope='exact');self.assertFalse(self.names()['two.example']['include_subdomains'])

    def test_small_scheduled_refresh_large_change_review_rollback_pause_and_restart(self):
        initial='\n'.join(f'host{i}.example' for i in range(20));sid=self.source(text=initial);self.approve(sid)
        self.assertTrue(self.store.refresh_due_subscriptions(now=4600,fetcher=lambda _:initial+'\nnew.example'))
        applied=self.store.subscription_detail(sid)['applied'];self.assertIn('new.example',self.names())
        self.store.initialize() # must not turn subscription domains into manual ownership
        self.store.refresh_due_subscriptions(now=8200,fetcher=lambda _:'replacement.example')
        self.assertIsNotNone(self.store.subscription_detail(sid)['pending']);self.assertIn('new.example',self.names())
        self.store.subscription_action(sid,'rollback',applied,now=8201)
        self.assertNotIn('new.example',self.names());self.assertTrue(self.store.subscription_detail(sid)['paused'])
        self.assertFalse(self.store.refresh_due_subscriptions(now=20000,fetcher=lambda _:self.fail('Paused source fetched')))
        self.store.subscription_action(sid,'resume',now=20000)
        self.assertTrue(self.store.refresh_due_subscriptions(now=20001,fetcher=lambda _:initial))

    def test_failed_empty_oversized_fetch_preserves_effective_state_and_pending_review_is_pinned(self):
        sid=self.source();self.approve(sid);before=self.names()
        for fetcher in (lambda _:'',lambda _:'<html>bad</html>',lambda _:(_ for _ in ()).throw(TimeoutError())):
            with self.assertRaises(GateError):self.store.refresh_subscription(sid,fetcher=fetcher,now=1001)
            self.assertEqual(self.names(),before);self.assertEqual(self.store.subscription_detail(sid)['status'],'refresh failed')
        self.store.refresh_subscription(sid,fetcher=lambda _:'changed.example',now=1002)
        with self.assertRaises(GateError):self.store.refresh_subscription(sid,fetcher=lambda _:'other.example',now=1003)
        with self.assertRaises(GateError):self.store.subscription_action(sid,'approve','wrong',now=1003)
        self.assertEqual(self.names(),before)

    def test_expired_lease_restart_and_pause_during_fetch(self):
        sid=self.source();self.approve(sid)
        with self.store.connect() as db:db.execute('UPDATE blocklist_sources SET lease=?,lease_until=?,next_due=? WHERE id=?',('interrupted',1100,1000,sid))
        self.assertFalse(self.store.refresh_due_subscriptions(now=1099,fetcher=lambda _:self.fail('Live lease fetched')))
        self.assertTrue(self.store.refresh_due_subscriptions(now=1101,fetcher=lambda _:'one.example\ntwo.example'))
        def pause(_):self.store.subscription_action(sid,'pause',now=5000);return 'bad.example'
        self.store.refresh_subscription(sid,fetcher=pause,now=5000)
        self.assertNotIn('bad.example',self.names())

    def test_legacy_migration_preserves_manual_disabled_rules(self):
        self.store.add_dns_domains('legacy.example',scope='exact');self.store.change_dns_domain('legacy.example','disable')
        with self.store.connect() as db:
            db.execute('DELETE FROM domain_manual');db.execute('PRAGMA user_version=11')
        self.store.initialize()
        sid=self.source(text='legacy.example\nnew.example');self.approve(sid);self.store.subscription_action(sid,'remove')
        self.assertEqual(set(self.names()),{'legacy.example'});self.assertFalse(self.names()['legacy.example']['enabled'])


class SubscriptionWebTests(BrowserWebFixture,unittest.TestCase):
    def test_admin_csrf_review_flow_and_source_escaping(self):
        self.assertEqual(self.request('/admin/subscriptions').status_code,302)
        self.request('/admin/login','POST',dict(csrf=self.csrf(),password='admin'))
        with patch('access_gate.subscriptions.download_blocklist',return_value='one.example\ntwo.example'):
            result=self.request('/admin/subscriptions','POST',dict(csrf=self.csrf(),name='<Source>',url='https://lists.example/raw'))
        self.assertEqual(result.status_code,303);page=self.request(result.location);self.assertIn(b'&lt;Source&gt;',page.data)
        self.assertNotIn(b'<Source>',page.data);source=self.store.subscriptions()[0];pending=source['pending']
        self.assertFalse(self.store.list_dns_domains())
        self.assertEqual(self.request(result.location,'POST',dict(action='approve',revision=pending)).status_code,400)
        self.assertEqual(self.request(result.location,'POST',dict(csrf=self.csrf(),action='approve',revision=pending)).status_code,303)
        self.assertEqual(len(self.store.list_dns_domains()),2)
        snapshot=self.request(result.location+'/snapshot/'+pending);self.assertEqual(snapshot.status_code,200);self.assertEqual(snapshot.data,b'one.example\ntwo.example\n');snapshot.close()


class SubscriptionSafetyTests(SubscriptionFixture,unittest.TestCase):
    def test_normal_source_removal_duplicate_owner_and_noop_keeps_rollback(self):
        original='\n'.join(f'host{i}.example' for i in range(20));sid=self.source(text=original);self.approve(sid)
        self.store.add_dns_domains('host0.example',scope='exact')
        reduced='\n'.join(f'host{i}.example' for i in range(1,20))
        self.assertTrue(self.store.refresh_due_subscriptions(now=4600,fetcher=lambda _:reduced))
        self.assertIn('host0.example',self.names())
        item=self.store.subscription_detail(sid);previous=item['previous'];applied=item['applied']
        self.store.refresh_due_subscriptions(now=8200,fetcher=lambda _:reduced)
        item=self.store.subscription_detail(sid);self.assertEqual(item['previous'],previous);self.assertEqual(item['applied'],applied)

    def test_combined_limit_rejects_apply_atomically(self):
        self.store.add_dns_domains('manual.example');sid=self.source(text='one.example\ntwo.example')
        with patch('access_gate.subscriptions.MAX_DOMAINS',2):
            with self.assertRaises(GateError):self.approve(sid)
        self.assertEqual(set(self.names()),{'manual.example'});self.assertFalse(self.store.subscription_detail(sid)['enabled'])
        self.assertIsNotNone(self.store.subscription_detail(sid)['pending'])


    def test_simultaneous_refresh_fetches_once_and_retains_pinned_source_state(self):
        import concurrent.futures,threading
        sid=self.source();self.approve(sid);entered=threading.Event();release=threading.Event();calls=[]
        def fetch(_):calls.append(1);entered.set();release.wait(2);return 'one.example\ntwo.example\nnew.example'
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future=pool.submit(self.store.refresh_subscription,sid,fetcher=fetch,now=2000)
            self.assertTrue(entered.wait(1))
            with self.assertRaises(GateError):self.store.refresh_subscription(sid,fetcher=fetch,now=2000)
            release.set();self.assertTrue(future.result())
        self.assertEqual(len(calls),1);self.assertNotIn('new.example',self.names())
