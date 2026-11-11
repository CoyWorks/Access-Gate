import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from access_gate.core import Store,GateError
from access_gate.maintenance import Jobs,read_regular
from access_gate.maintenance_worker import Worker
from access_gate.recovery import DATABASE,snapshot,encrypt,decrypt,preflight
from test_browser_portal import BrowserWebFixture
from gateway_fixtures import settings

PASSWORD='test-passphrase-1234'


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        config=dict(secret='secret',pepper='pepper',acl_token='acl',admin_hash='hash',database=DATABASE,portal_url='https://portal.example',client_networks=['10.40.0.0/16'])
        settings(self.root,config)
        (self.root/'etc/access-gate/acl-token').write_text('acl\n')
        (self.root/'opt/access-gate').mkdir(parents=True);(self.root/'opt/access-gate/VERSION').write_text('0.10.0')
        (self.root/'var/lib/access-gate/public').mkdir(parents=True)
        self.database=self.root/DATABASE.lstrip('/');self.database.parent.mkdir(parents=True)
        self.store=Store(self.database,'pepper');self.store.initialize()
        self.batch,self.codes=self.store.create_batch(count=2)
        self.store.redeem(self.codes[0],'10.40.22.40',browser_token='a'*64)
        self.calls=[];self.worker=Worker(self.root,runner=self.calls.append,gid=os.getgid());self.worker.setup();self.jobs=Jobs(self.worker.jobs)
    def tearDown(self):self.temp.cleanup()
    def backup(self):
        job=self.jobs.submit('backup',passphrase=PASSWORD);self.worker.run_once()
        self.assertTrue(self.jobs.status(job)['download'])
        return (self.worker.jobs/'downloads'/(job+'.agbackup')).read_bytes()
    def test_busy_wal_snapshot_contains_committed_data_and_no_plaintext(self):
        with self.store.connect() as db:
            db.execute('BEGIN IMMEDIATE');db.execute("UPDATE batches SET name='Committed live batch' WHERE id=?",(self.batch,));db.commit()
            archive=self.backup()
        for secret in (b'pepper',b'BEGIN PRIVATE KEY',b'Committed live batch'):self.assertNotIn(secret,archive)
        with tempfile.TemporaryDirectory() as tmp:
            result=preflight(archive,PASSWORD,tmp)
            self.assertEqual(result['counts']['codes'],2)
            saved=Store(Path(tmp)/'database','pepper');self.assertEqual(saved.batch_detail(self.batch)['name'],'Committed live batch')
    def test_wrong_password_corruption_and_schema_do_not_replace_state(self):
        data=self.backup();before=self.database.read_bytes()
        for archive,password in ((data,'wrong-password-1234'),(data[:-1]+bytes([data[-1]^1]),PASSWORD),(b'bad',PASSWORD)):
            with tempfile.TemporaryDirectory() as tmp,self.assertRaises(GateError):preflight(archive,password,tmp)
        bundle=json.loads(decrypt(data,PASSWORD));bundle['schema']=999
        with tempfile.TemporaryDirectory() as tmp,self.assertRaises(GateError):preflight(encrypt(json.dumps(bundle).encode(),PASSWORD),PASSWORD,tmp)
        self.assertEqual(self.database.read_bytes(),before);self.assertTrue(self.store.browser_grant('a'*64))
    def test_full_recovery_revokes_old_unused_used_and_newer_access(self):
        schedule=self.store.create_schedule(dict(name='Saved schedule',recurrence='daily',clock='09:00'),PASSWORD)
        run=self.store.run_schedule_now(schedule,'c'*32)
        token,login=self.store.new_admin_login('e'*64,dict(secret='secret',admin_hash='hash',client_networks=['10.40.0.0/16']))
        self.store.save_push('e'*64,login['id'],'https://fcm.googleapis.com/fcm/send/test',dict(secret='secret',admin_hash='hash',client_networks=['10.40.0.0/16']))
        archive=self.backup();new_batch,new_codes=self.store.create_batch(count=1)
        job=self.jobs.submit('preflight',passphrase=PASSWORD,archive=archive);self.worker.run_once()
        self.assertTrue(self.jobs.status(job)['confirm']);self.assertEqual(self.calls,[])
        restore=self.jobs.submit('restore',preview=job);self.worker.run_once()
        self.assertEqual(self.jobs.status(restore)['state'],'complete')
        self.assertTrue(any('access_gate.readiness' in c for c in self.calls))
        self.assertIsNone(self.store.browser_grant('a'*64))
        self.assertFalse(self.store.schedule_detail(schedule)['enabled'])
        self.assertEqual(self.store.schedule_detail(schedule)['runs'][0]['status'],'invalidated')
        for code in self.codes+new_codes:
            with self.assertRaises(GateError):self.store.redeem(code,'10.40.22.41',browser_token='b'*64)
        with self.store.connect() as db:
            self.assertFalse(db.execute('PRAGMA foreign_key_check').fetchall());self.assertEqual(db.execute('PRAGMA integrity_check').fetchone()[0],'ok');self.assertEqual(db.execute('SELECT count(*) FROM push_subscriptions').fetchone()[0],0)
        self.assertFalse((self.worker.private/(job+'.json')).exists())
        self.assertEqual(len(list(self.worker.private.glob('*.rollback'))),1)
    def test_restore_service_failure_attempts_safe_rollback(self):
        archive=self.backup();job=self.jobs.submit('preflight',passphrase=PASSWORD,archive=archive);self.worker.run_once()
        calls=[]
        def runner(args):
            calls.append(args)
            if 'access_gate.readiness' in args:raise GateError('Test readiness failed.')
        self.worker.runner=runner
        restore=self.jobs.submit('restore',preview=job);self.worker.run_once()
        self.assertEqual(self.jobs.status(restore)['state'],'failed')
        self.assertIn('rollback',self.jobs.status(restore)['message'])
        self.assertIsNone(self.store.browser_grant('a'*64))
        self.assertGreaterEqual(sum('restart' in c for c in calls),2)
    def test_worker_rejects_unknown_fields_paths_and_symlinks_without_commands(self):
        job=self.jobs.submit('backup',passphrase=PASSWORD,path='/etc/shadow');self.worker.run_once()
        self.assertEqual(self.jobs.status(job)['state'],'failed');self.assertEqual(self.calls,[])
        link=self.root/'link';link.symlink_to('/etc/passwd')
        with self.assertRaises(OSError):read_regular(link,100000)
        with self.assertRaises(GateError):self.jobs.status('../../etc/passwd')
    def test_duplicate_restore_is_not_replayed_and_secrets_are_removed(self):
        archive=self.backup();job=self.jobs.submit('preflight',passphrase=PASSWORD,archive=archive);self.worker.run_once()
        restore=self.jobs.submit('restore',preview=job);self.worker.run_once()
        second=self.jobs.submit('restore',preview=job);self.worker.run_once()
        self.assertEqual(self.jobs.status(second)['state'],'failed')
        self.assertFalse(list((self.worker.jobs/'inbox').iterdir()))
        for result in (self.worker.jobs/'results').glob('*.json'):self.assertNotIn(PASSWORD,result.read_text())
    def test_crash_marker_reports_failure_without_replaying(self):
        marker=self.worker.private/('f'*32+'.running');marker.write_text('running');self.worker.run_once()
        self.assertEqual(self.jobs.status('f'*32)['state'],'failed');self.assertEqual(self.calls,[])


class RecoveryWebTests(BrowserWebFixture,unittest.TestCase):
    def setUp(self):
        super().setUp();self.jobs=self.app.extensions['jobs'];self.jobs.root=self.root/'jobs'
        (self.jobs.root/'inbox').mkdir(parents=True)
    def login(self):self.request('/admin/login','POST',dict(csrf=self.csrf(),password='admin'))
    def test_auth_csrf_password_and_confirmation_required(self):
        self.assertEqual(self.request('/admin/recovery').status_code,302);self.login()
        self.assertEqual(self.request('/admin/recovery','POST',dict(action='backup')).status_code,400)
        self.assertEqual(self.request('/admin/recovery','POST',dict(csrf=self.csrf(),action='backup',current_password='bad',passphrase=PASSWORD,confirm_passphrase=PASSWORD)).status_code,400)
        self.assertEqual(self.request('/admin/recovery','POST',dict(csrf=self.csrf(),action='backup',current_password='admin',passphrase=PASSWORD,confirm_passphrase=PASSWORD)).status_code,303)
        self.assertEqual(len(list((self.jobs.root/'inbox').glob('*.json'))),1)
    def test_only_admin_can_read_job_or_download(self):
        self.login();job=self.jobs.submit('backup',passphrase=PASSWORD)
        response=self.request('/admin/maintenance/'+job);self.assertEqual(response.status_code,200);self.assertNotIn(PASSWORD.encode(),response.data)
        other=self.app.test_client();self.assertEqual(self.request('/admin/api/maintenance/'+job,client=other).status_code,302)
        self.assertEqual(self.request('/admin/maintenance/'+job+'/download').status_code,400)
