import concurrent.futures
import datetime as dt
import re
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from pathlib import Path

from werkzeug.security import generate_password_hash
from access_gate.core import Store, GateError, TZ
from access_gate.core import expire
from access_gate.web import create_app


class ManagementTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.store=Store(self.root/'gate.sqlite3','unchanged-test-pepper')
        self.store.initialize()
        self.now=dt.datetime(2026,11,10,12,tzinfo=TZ).timestamp()

    def tearDown(self): self.temp.cleanup()

    def batch(self,**kwargs):
        return self.store.create_batch(now=self.now,**kwargs)

    def code_id(self,raw):
        with self.store.connect() as db:
            return db.execute('SELECT id FROM codes WHERE digest=?',(self.store.digest(raw),)).fetchone()[0]

    def grant(self,raw,ip='10.40.135.11'):
        self.store.redeem(raw,ip,self.now)
        return self.store.grant(ip,self.now)

    def test_short_codes_are_unique_unambiguous_and_accept_normalized_input(self):
        _,codes=self.batch(count=1000)
        self.assertEqual(len(set(codes)),1000)
        for code in codes: self.assertRegex(code,r'^[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}-[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}$')
        self.store.redeem(codes[0].lower().replace('-',''),'10.40.135.11',self.now)
        with self.assertRaises(GateError): self.store.redeem(codes[0],'10.40.135.12',self.now)

    def test_existing_twelve_character_codes_remain_redeemable(self):
        _,codes=self.batch(count=1)
        old='ABCD-EFGH-JKLM'
        with self.store.connect() as db:
            db.execute('UPDATE codes SET digest=?,hint=? WHERE digest=?',(self.store.digest(old),'JKLM',self.store.digest(codes[0])))
        self.store.initialize()
        self.assertEqual(self.store.redeem(old.lower(),'10.40.135.11',self.now),self.now+900)

    def test_short_code_collision_retries_instead_of_reusing_a_saved_code(self):
        with patch('access_gate.core.secrets.choice',side_effect=list('AAAAAAAA'+'AAAAAAAA'+'BBBBBBBB')):
            _,first=self.batch(count=1)
            _,second=self.batch(count=1)
        self.assertEqual(first,['AAAA-AAAA']); self.assertEqual(second,['BBBB-BBBB'])

    def test_independent_validity_and_access_units(self):
        batch,codes=self.batch(name='Short validity, long access',count=2,validity_value=2,validity_unit='hours',access_value=3,access_unit='hours')
        detail=self.store.batch_detail(batch,self.now)
        self.assertEqual(detail['ends']-detail['starts'],7200)
        self.assertEqual(detail['access_seconds'],10800)
        self.assertEqual(self.store.redeem(codes[0],'10.40.135.11',self.now),self.now+10800)
        self.assertEqual(len(codes),2)

    def test_validity_days_are_fixed_twenty_four_hours(self):
        now=dt.datetime(2026,3,28,12,tzinfo=TZ).timestamp()
        batch,_=self.store.create_batch(validity_value=1,validity_unit='days',now=now)
        self.assertEqual(self.store.batch_detail(batch,now)['ends']-now,86400)

    def test_full_access_when_activated_just_before_deadline(self):
        batch,codes=self.batch(validity_value=1,validity_unit='hours',access_value=2,access_unit='hours')
        deadline=self.store.batch_detail(batch,self.now)['ends']
        self.assertEqual(self.store.redeem(codes[0],'10.40.135.11',deadline-1),deadline-1+7200)
        with self.assertRaises(GateError): self.store.redeem(codes[1],'10.40.135.12',deadline)

    def test_activation_before_validity_start_fails(self):
        _,codes=self.batch()
        with self.assertRaises(GateError): self.store.redeem(codes[0],'10.40.135.11',self.now-1)

    def test_invalid_batch_inputs_never_partially_create(self):
        for kwargs in ({'count':0},{'count':1001},{'count':'1.5'},{'count':True},{'count':'9'*5000},
                       {'validity_value':0},{'validity_value':366,'validity_unit':'days'},
                       {'validity_unit':'minutes'},{'access_unit':'days'},
                       {'access_value':169,'access_unit':'hours'},{'access_value':-1},
                       {'access_value':'nan'},{'name':'x'*81},{'name':'bad\nname'}):
            with self.subTest(kwargs=kwargs), self.assertRaises(GateError): self.batch(**kwargs)
        self.assertEqual(self.store.list_batches(now=self.now)['total'],0)

    def test_codes_are_still_single_use_after_grant_cleanup(self):
        _,codes=self.batch(count=1,access_value=1)
        self.grant(codes[0])
        expire(self.store,lambda ip:None,self.now+61)
        with self.assertRaises(GateError): self.store.redeem(codes[0],'10.40.135.12',self.now+62)

    def test_clear_revoked_preserves_unused_redeemed_and_expired(self):
        batch,codes=self.batch(count=4,validity_value=1,validity_unit='hours')
        self.grant(codes[0])
        self.store.revoke(self.code_id(codes[1]))
        self.assertEqual(self.store.clear_revoked(now=self.now+1),1)
        rows=self.store.list_codes(now=self.now+3601)['items']
        self.assertEqual(len(rows),3)
        self.assertEqual(sorted(r['status'] for r in rows),['expired','expired','redeemed'])
        with self.assertRaises(GateError): self.store.redeem(codes[1],'10.40.135.12',self.now+2)
        self.assertEqual(self.store.clear_revoked(now=self.now+3),0)

    def test_clear_revoked_handles_pending_grant_without_foreign_key_error(self):
        batch,codes=self.batch(count=1)
        grant=self.grant(codes[0])
        self.store.revoke(grant['code'])
        self.assertEqual(self.store.clear_revoked(now=self.now+1),1)
        self.assertIsNone(self.store.grant(grant['ip'],self.now+1))
        self.assertEqual(len(self.store.list_grants()),1)
        with self.assertRaises(GateError):
            self.store.extend(grant['session_id'],1,'hours','a'*32,now=self.now+1)
        killed=[]
        expire(self.store,killed.append,self.now+1)
        self.assertEqual(killed,[grant['session_id']])
        with self.store.connect() as db: self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(),[])

    def test_clear_revoked_is_scoped_to_batch(self):
        a,ca=self.batch(count=1)
        b,cb=self.batch(count=1)
        self.store.revoke(self.code_id(ca[0])); self.store.revoke(self.code_id(cb[0]))
        self.assertEqual(self.store.clear_revoked(a,self.now),1)
        self.assertEqual(self.store.revoked_visible(b),1)

    def test_extension_adds_to_current_end_and_records_actor(self):
        _,codes=self.batch(count=1,access_value=30)
        grant=self.grant(codes[0])
        event=self.store.extend(grant['session_id'],1,'hours','a'*32,'Administrator (test)',self.now+60)
        self.assertEqual(event['new_expires'],self.now+1800+3600)
        self.assertEqual(event['previous_expires'],self.now+1800)
        self.assertEqual(event['actor'],'Administrator (test)')
        self.assertEqual(self.store.grant(grant['ip'],self.now+2000)['expires'],event['new_expires'])
        with self.assertRaises(GateError): self.store.redeem(codes[0],'10.40.135.12',self.now+61)

    def test_extension_repeat_does_not_add_time_twice(self):
        _,codes=self.batch(count=1)
        grant=self.grant(codes[0])
        first=self.store.extend(grant['session_id'],30,'minutes','b'*32,now=self.now)
        second=self.store.extend(grant['session_id'],30,'minutes','b'*32,now=self.now+10)
        self.assertEqual(first,second)
        self.assertEqual(len(self.store.extension_history()),1)
        with self.assertRaises(GateError): self.store.extend(grant['session_id'],1,'hours','b'*32,now=self.now+11)

    def test_concurrent_duplicate_extension_is_idempotent(self):
        _,codes=self.batch(count=1)
        grant=self.grant(codes[0])
        def extend(_): return self.store.extend(grant['session_id'],1,'hours','c'*32,now=self.now)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(extend,range(2)))
        self.assertEqual(results[0]['new_expires'],results[1]['new_expires'])
        self.assertEqual(self.store.grant(grant['ip'],self.now)['expires'],grant['expires']+3600)

    def test_expired_or_revoked_access_cannot_be_reopened(self):
        _,codes=self.batch(count=2,access_value=1)
        a=self.grant(codes[0])
        b=self.grant(codes[1],'10.40.135.12')
        self.store.revoke(b['code'])
        for grant,now in ((a,self.now+60),(b,self.now)):
            with self.assertRaises(GateError): self.store.extend(grant['session_id'],1,'hours','d'*32,now=now)
        self.assertEqual(self.store.extension_history(),[])

    def test_extension_checks_clock_after_acquiring_writer_lock(self):
        _,codes=self.batch(count=1,access_value=1)
        grant=self.grant(codes[0])
        with patch('access_gate.core.time.time',side_effect=[self.now+59,self.now+61]):
            with self.assertRaises(GateError):
                self.store.extend(grant['session_id'],1,'hours','f'*32)
        self.assertEqual(self.store.extension_history(),[])

    def test_invalid_extension_values_do_not_change_expiry(self):
        _,codes=self.batch(count=1)
        grant=self.grant(codes[0])
        for value,unit,token in ((0,'minutes','a'*32),(1,'days','a'*32),(169,'hours','a'*32),(1,'minutes','bad')):
            with self.assertRaises(GateError): self.store.extend(grant['session_id'],value,unit,token,now=self.now)
        self.assertEqual(self.store.grant(grant['ip'],self.now)['expires'],grant['expires'])

    def test_extension_and_keeper_race_cannot_resurrect_or_kill_extended_access(self):
        for trial in range(6):
            _,codes=self.batch(count=1,access_value=1)
            ip=f'10.40.135.{20+trial}'
            grant=self.grant(codes[0],ip)
            barrier=threading.Barrier(2)
            killed=[]
            def extend():
                barrier.wait()
                try: self.store.extend(grant['session_id'],1,'hours',f'{trial:032x}',now=self.now+59); return True
                except GateError: return False
            def cleanup():
                barrier.wait()
                expire(self.store,killed.append,self.now+61)
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                e=pool.submit(extend); k=pool.submit(cleanup); extended=e.result(); k.result()
            if extended:
                self.assertIsNotNone(self.store.grant(ip,self.now+61))
                self.assertNotIn(grant['session_id'],killed)
                self.store.revoke(grant['code'])
                expire(self.store,lambda ip:None,self.now+62)
            else:
                self.assertIsNone(self.store.grant(ip,self.now+61))
                self.assertIn(grant['session_id'],killed)

    def test_batch_revoke_is_atomic_scoped_and_idempotent(self):
        a,ca=self.batch(count=3)
        b,cb=self.batch(count=1)
        self.grant(ca[0])
        self.grant(cb[0],'10.40.135.12')
        self.assertEqual(self.store.revoke_batch(a,self.now),(3,1))
        self.assertIsNone(self.store.grant('10.40.135.11',self.now))
        self.assertIsNotNone(self.store.grant('10.40.135.12',self.now))
        with self.assertRaises(GateError): self.store.redeem(ca[1],'10.40.135.13',self.now)
        self.assertEqual(self.store.revoke_batch(a,self.now),(0,0))
        self.assertEqual(self.store.batch_detail(b,self.now)['revoked_count'],0)

    def test_batch_revoke_vs_redemption_ends_in_denied_access(self):
        batch,codes=self.batch(count=1)
        barrier=threading.Barrier(2)
        def redeem():
            barrier.wait()
            try: self.store.redeem(codes[0],'10.40.135.11',self.now)
            except GateError: pass
        def revoke(): barrier.wait(); self.store.revoke_batch(batch,self.now)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            a=pool.submit(redeem); b=pool.submit(revoke); a.result(); b.result()
        self.assertIsNone(self.store.grant('10.40.135.11',self.now))
        with self.assertRaises(GateError): self.store.redeem(codes[0],'10.40.135.12',self.now)

    def test_counts_and_pagination_survive_clearing(self):
        batch,codes=self.batch(count=60)
        self.grant(codes[0])
        self.store.revoke(self.code_id(codes[1]))
        self.store.clear_revoked(batch,self.now)
        detail=self.store.batch_detail(batch,self.now)
        self.assertEqual((detail['total'],detail['unused_count'],detail['redeemed_count'],detail['revoked_count'],detail['cleared_count'],detail['active_count']),(60,58,1,1,1,1))
        rows=[self.store.list_codes(batch,page=p,now=self.now) for p in (1,2,3)]
        self.assertEqual([len(r['items']) for r in rows],[25,25,9])
        self.assertEqual(len({c['id'] for r in rows for c in r['items']}),59)
        self.assertEqual(self.store.list_codes(batch,status='redeemed',now=self.now)['total'],1)
        self.assertEqual(self.store.list_codes(batch,status='revoked',now=self.now)['total'],0)

    def test_batch_overview_is_paginated_and_status_filters_validated(self):
        for i in range(12): self.batch(count=1,name=f'Batch {i}')
        first=self.store.list_batches(now=self.now)
        second=self.store.list_batches(page=2,now=self.now)
        self.assertEqual((first['total'],len(first['items']),len(second['items'])),(12,10,2))
        for value in ('bad',"revoked' OR 1=1"):
            with self.assertRaises(GateError): self.store.list_codes(status=value,now=self.now)

    def test_batch_status_counts_at_expiry_boundary(self):
        batch,codes=self.batch(count=3,validity_value=1,validity_unit='hours')
        self.grant(codes[0])
        self.store.revoke(self.code_id(codes[1]))
        detail=self.store.batch_detail(batch,self.now+3600)
        self.assertEqual((detail['unused_count'],detail['redeemed_count'],detail['revoked_count'],detail['expired_count'],detail['active_count']),(0,1,1,1,0))

    def test_legacy_future_status_counts(self):
        batch,_=self.store.new_batch('2026-11-16',count=2,now=self.now)
        detail=self.store.batch_detail(batch,self.now)
        self.assertEqual((detail['future_count'],detail['unused_count'],detail['total']),(2,0,2))

    def test_clear_revoke_and_redemption_race_never_restores_access(self):
        batch,codes=self.batch(count=1)
        barrier=threading.Barrier(3)
        def redeem():
            barrier.wait()
            try: self.store.redeem(codes[0],'10.40.135.11',self.now)
            except GateError: pass
        def revoke(): barrier.wait(); self.store.revoke_batch(batch,self.now)
        def clear(): barrier.wait(); self.store.clear_revoked(batch,self.now)
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            jobs=[pool.submit(fn) for fn in (redeem,revoke,clear)]
            for job in jobs: job.result()
        self.assertIsNone(self.store.grant('10.40.135.11',self.now))
        self.store.clear_revoked(batch,self.now)
        with self.assertRaises(GateError): self.store.redeem(codes[0],'10.40.135.12',self.now)


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.path=Path(self.temp.name)/'legacy.sqlite'
        self.store=Store(self.path,'same-pepper')
        with sqlite3.connect(self.path) as db:
            db.executescript('''
                CREATE TABLE batches(id TEXT PRIMARY KEY,week TEXT NOT NULL,starts REAL NOT NULL,ends REAL NOT NULL,minutes INTEGER NOT NULL,created REAL NOT NULL);
                CREATE TABLE codes(id TEXT PRIMARY KEY,batch TEXT NOT NULL REFERENCES batches(id),digest TEXT UNIQUE NOT NULL,hint TEXT NOT NULL,used REAL,used_ip TEXT,revoked INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE grants(ip TEXT PRIMARY KEY,code TEXT NOT NULL REFERENCES codes(id),expires REAL NOT NULL,revoked INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE attempts(scope TEXT NOT NULL,stamp REAL NOT NULL);
            ''')
            db.execute('INSERT INTO batches VALUES(?,?,?,?,?,?)',('legacy','2026-11-09',100,10000,15,100))
            for code,used,revoked in (('UNUSED',None,0),('USED',200,0),('REVOKED',None,1)):
                db.execute('INSERT INTO codes VALUES(?,?,?,?,?,?,?)',(code,'legacy',self.store.digest(code),code[-4:],used,'10.40.135.11' if used else None,revoked))
            db.execute('INSERT INTO grants VALUES(?,?,?,?)',('10.40.135.11','USED',1100,0))

    def tearDown(self): self.temp.cleanup()

    def test_legacy_migration_preserves_validity_digests_and_used_revoked_state(self):
        self.store.initialize()
        detail=self.store.batch_detail('legacy',300)
        self.assertEqual((detail['name'],detail['starts'],detail['ends'],detail['access_seconds'],detail['timing_mode']),('Week starting 2026-11-09',100,10000,900,'legacy-week'))
        with self.store.connect() as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0],12)
            self.assertEqual(db.execute('SELECT digest FROM codes WHERE id=?',('UNUSED',)).fetchone()[0],self.store.digest('UNUSED'))
            self.assertEqual(db.execute('SELECT used FROM codes WHERE id=?',('USED',)).fetchone()[0],200)
            self.assertEqual(db.execute('SELECT revoked FROM codes WHERE id=?',('REVOKED',)).fetchone()[0],1)
        self.assertEqual(self.store.redeem('UNUSED','10.40.135.12',300),1200)
        with self.assertRaises(GateError): self.store.redeem('USED','10.40.135.13',300)
        with self.assertRaises(GateError): self.store.redeem('REVOKED','10.40.135.14',300)

    def test_repeated_migration_preserves_session_and_extension_event(self):
        self.store.initialize()
        self.assertIsNone(self.store.grant('10.40.135.11',300))
        self.store.redeem('UNUSED','10.40.135.12',300)
        session=self.store.grant('10.40.135.12',300)['session_id']
        self.store.extend(session,1,'hours','e'*32,now=300)
        self.store.initialize(); self.store.initialize()
        self.assertEqual(self.store.grant('10.40.135.12',300)['session_id'],session)
        self.assertEqual(self.store.grant('10.40.135.12',300)['expires'],4800)
        self.assertEqual(len(self.store.extension_history()),1)
        with self.store.connect() as db: self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(),[])

    def test_newer_schema_is_not_modified(self):
        with sqlite3.connect(self.path) as db: db.execute('PRAGMA user_version=99')
        with self.assertRaises(GateError): self.store.initialize()
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0],99)
            self.assertNotIn('name',[r[1] for r in db.execute('PRAGMA table_info(batches)')])

    def test_failed_migration_rolls_back_schema_changes(self):
        # Simulate a damaged legacy database, not a supported prior schema.
        with sqlite3.connect(self.path) as db: db.execute('ALTER TABLE batches RENAME COLUMN minutes TO broken_minutes')
        with self.assertRaises(sqlite3.OperationalError): self.store.initialize()
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0],0)
            self.assertNotIn('name',[r[1] for r in db.execute('PRAGMA table_info(batches)')])


class ManagementWebTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        root=Path(self.temp.name)
        (root/'domains').write_text('example.org\n')
        config=dict(secret='web-test-secret',pepper='web-test-pepper',acl_token='web-acl',
                    database=str(root/'gate.sqlite'),domains=str(root/'domains'),pilot_clients=['10.40.135.11/32'],
                    admin_hash=generate_password_hash('web-test-password'))
        self.app=create_app(config); self.app.config['TESTING']=True
        self.store=self.app.extensions['store']; self.store.initialize()
        self.client=self.app.test_client()
        self.token='csrf-test-token'
        with self.client.session_transaction(base_url='https://10.40.22.5') as sess:
            sess['admin']=True; sess['csrf']=self.token; sess['auth_version']=self.store.admin_security(config)['version']
        login,_=self.store.new_admin_login('a'*64,config)
        self.client.set_cookie('__Host-accessgate-browser','a'*64,domain='10.40.22.5',secure=True)
        self.client.set_cookie('__Host-accessgate-admin',login,domain='10.40.22.5',secure=True)

    def tearDown(self): self.temp.cleanup()

    def request(self,path='/',method='GET',data=None,headers=None):
        return self.client.open(path,method=method,data=data,base_url='https://10.40.22.5',
            environ_overrides={'REMOTE_ADDR':'127.0.0.1'},headers={'X-Real-IP':'10.40.135.11',**(headers or {})})

    def batch(self,**kwargs): return self.store.create_batch(count=2,**kwargs)

    def test_all_management_screens_render(self):
        batch,_=self.batch(name='<script>not executable</script>')
        for path in ('/admin','/admin/batches','/admin/batches/new',f'/admin/batches/{batch}',f'/admin/batches/{batch}/revoke'):
            response=self.request(path)
            self.assertEqual(response.status_code,200,path)
            self.assertNotIn(b'<script>not executable</script>',response.data)

    def test_batch_form_generates_configurable_batch_and_export_metadata(self):
        r=self.request('/admin/batch','POST',dict(csrf=self.token,name='Hours test',count='3',validity_value='4',validity_unit='hours',access_value='2',access_unit='hours'))
        self.assertEqual(r.status_code,200)
        self.assertIn(b'3 codes generated',r.data)
        self.assertIn(b'data-duration="2 hours"',r.data)
        detail=self.store.list_batches()['items'][0]
        self.assertEqual((detail['validity_seconds'],detail['access_seconds'],detail['total']),(14400,7200,3))
        codes=re.findall(rb'[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}',r.data)
        self.assertEqual(len(codes),3)
        self.assertNotIn(codes[0],self.request('/admin').data)
        self.assertNotIn(codes[0],self.request('/admin/batches/'+detail['id']).data)

    def test_invalid_or_stale_generation_form_is_rejected(self):
        for form in ({'count':'-1'},{'access_value':'1.5'},{'week':'2026-11-09'}):
            self.assertEqual(self.request('/admin/batch','POST',dict(csrf=self.token,**form)).status_code,400)
        self.assertEqual(self.store.list_batches()['total'],0)

    def test_clear_revoked_ui_scopes_cleanup(self):
        a,ca=self.batch(); b,cb=self.batch()
        for code in (ca[0],cb[0]):
            with self.store.connect() as db: cid=db.execute('SELECT id FROM codes WHERE digest=?',(self.store.digest(code),)).fetchone()[0]
            self.store.revoke(cid)
        self.assertEqual(self.request('/admin/codes/clear-revoked','POST',{'csrf':self.token,'batch_id':a}).status_code,302)
        self.assertEqual(self.store.revoked_visible(a),0)
        self.assertEqual(self.store.revoked_visible(b),1)

    def test_extension_preview_submit_repeat_and_live_status(self):
        _,codes=self.batch()
        self.request('/')
        browser=self.client.get_cookie('__Host-accessgate-browser',domain='10.40.22.5').value
        self.store.redeem(codes[0],'10.40.135.11',browser_token=browser)
        grant=self.store.browser_grant(browser)
        path='/admin/access/'+grant['session_id']+'/extend'
        preview=self.request(path)
        self.assertEqual(preview.status_code,200)
        token=re.search(rb'name="request_id" value="([a-f0-9]+)"',preview.data)[1].decode()
        form=dict(csrf=self.token,request_id=token,value='1',unit='hours')
        for _ in range(2): self.assertEqual(self.request(path,'POST',form).status_code,302)
        live=self.request('/status').get_json()
        self.assertEqual(live['kind'],'admin')
        self.assertEqual(self.store.browser_grant(browser)['expires'],grant['expires']+3600)
        rows=self.request('/admin/api/sessions').get_json()['items']
        self.assertEqual(next(r['expires'] for r in rows if r['session_id']==grant['session_id']),grant['expires']+3600)
        self.assertEqual(len(self.store.extension_history()),1)
        self.assertIn('Administrator (10.40.135.11)',self.store.extension_history()[0]['actor'])

    def test_expired_extension_and_invalid_durations_are_rejected(self):
        _,codes=self.batch()
        self.store.redeem(codes[0],'10.40.135.11')
        grant=self.store.grant('10.40.135.11'); path='/admin/access/'+grant['session_id']+'/extend'
        self.assertEqual(self.request(path,'POST',dict(csrf=self.token,request_id='f'*32,value='0',unit='hours')).status_code,400)
        with self.store.connect() as db: db.execute('UPDATE grants SET expires=1')
        self.assertEqual(self.request(path).status_code,400)

    def test_batch_revocation_ends_proxy_permission_and_updates_counts(self):
        batch,codes=self.batch()
        self.store.redeem(codes[0],'10.40.135.11')
        self.assertEqual(self.request(f'/admin/batches/{batch}/revoke','POST',dict(csrf=self.token)).status_code,302)
        self.assertEqual(self.request('/internal/check?ip=10.40.135.11',headers={'X-Gate-Key':'web-acl'}).status_code,401)
        self.assertEqual(self.request('/status').get_json()['kind'],'admin')
        self.client.delete_cookie('__Host-accessgate-admin',domain='10.40.22.5')
        self.assertFalse(self.request('/status').get_json()['active'])
        self.assertEqual(self.store.batch_detail(batch)['revoked_count'],2)

    def test_new_mutations_require_admin_and_csrf(self):
        batch,codes=self.batch()
        self.store.redeem(codes[0],'10.40.135.11')
        grant=self.store.grant('10.40.135.11')
        endpoints=[('/admin/batch',{}),('/admin/codes/clear-revoked',{}),
                   (f'/admin/batches/{batch}/revoke',{}),
                   ('/admin/access/'+grant['session_id']+'/extend',{'value':'1','unit':'hours','request_id':'f'*32})]
        for path,data in endpoints: self.assertEqual(self.request(path,'POST',data).status_code,400)
        self.client.delete_cookie('__Host-accessgate-admin',domain='10.40.22.5')
        with self.client.session_transaction(base_url='https://10.40.22.5') as sess: sess.pop('admin',None)
        for path,data in endpoints: self.assertEqual(self.request(path,'POST',dict(csrf=self.token,**data)).status_code,302)
        self.assertIsNotNone(self.store.grant('10.40.135.11'))
        self.assertEqual(self.store.list_batches()['total'],1)

    def test_code_list_filter_and_page_links(self):
        batch,codes=self.store.create_batch(count=30)
        r=self.request(f'/admin/batches/{batch}?status=unused&page=2')
        self.assertEqual(r.status_code,200)
        self.assertIn(b'Page 2 of 2',r.data)
        self.assertEqual(self.request(f'/admin/batches/{batch}?status=invalid').status_code,400)
        self.assertEqual(self.request('/admin/batches/not-found').status_code,400)


if __name__=='__main__': unittest.main()
