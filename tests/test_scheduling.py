import concurrent.futures
import datetime as dt
import json
import time
import unittest
from unittest.mock import patch
from zoneinfo import ZoneInfo
from access_gate.core import GateError,Store
from access_gate.scheduling import upcoming,latest_due
from test_browser_portal import BrowserWebFixture

PASSWORD='export-passphrase-1234'
SPEC=dict(name='Weekly access',recurrence='weekly',weekday='0',clock='09:00',timezone='Europe/Amsterdam',count='3',validity_value='7',validity_unit='days',access_value='15',access_unit='minutes')
def stamp(value):return dt.datetime.fromisoformat(value).replace(tzinfo=ZoneInfo('Europe/Amsterdam')).timestamp()


class ScheduleTests(BrowserWebFixture,unittest.TestCase):
    def create(self,now=None,**values):return self.store.create_schedule(dict(SPEC,**values),PASSWORD,now=now)
    def test_daily_weekly_timezone_and_dst_gaps_and_folds(self):
        daily=dict(SPEC,recurrence='daily',weekday=0,clock='02:30')
        runs=upcoming(daily,stamp('2026-03-28T03:00:00'),2)
        self.assertEqual(dt.datetime.fromtimestamp(runs[0],ZoneInfo('Europe/Amsterdam')).day,30)
        autumn=upcoming(daily,stamp('2026-10-24T03:00:00'),2)
        first=dt.datetime.fromtimestamp(autumn[0],ZoneInfo('Europe/Amsterdam'))
        self.assertEqual(first.day,25);self.assertEqual(first.fold,0)
        self.assertEqual(dt.datetime.fromtimestamp(autumn[1],ZoneInfo('Europe/Amsterdam')).day,26)
        self.assertEqual(latest_due(daily,autumn[0]+3600),autumn[0])
        weekly=dict(SPEC,weekday=0);self.assertEqual(upcoming(weekly,stamp('2026-11-08T10:00:00'),1)[0],stamp('2026-11-09T09:00:00'))
    def test_duplicate_workers_and_restart_generate_exactly_one_batch(self):
        now=stamp('2026-11-09T08:00:00');schedule=self.create(now)
        with concurrent.futures.ThreadPoolExecutor(4) as pool:list(pool.map(lambda _:self.store.run_schedules(now+7200),range(4)))
        self.store.initialize();self.store.run_schedules(now+7200)
        detail=self.store.schedule_detail(schedule);self.assertEqual(len(detail['runs']),1);self.assertEqual(self.store.list_batches()['total'],1)
        run=detail['runs'][0];batch,codes=self.store.collect_schedule_run(schedule,run['id'],PASSWORD,now+7200)
        self.assertEqual(len(codes),3);info=self.store.batch_detail(batch);self.assertEqual(info['starts'],now+7200);self.assertEqual(info['ends'],now+7200+7*86400);self.assertEqual(info['access_seconds'],900)
    def test_manual_run_is_idempotent_and_does_not_shift_schedule(self):
        schedule=self.create();before=self.store.schedule_detail(schedule)['next_due']
        first=self.store.run_schedule_now(schedule,'a'*32);second=self.store.run_schedule_now(schedule,'a'*32)
        self.assertEqual(first,second);self.assertEqual(self.store.list_batches()['total'],1);self.assertEqual(self.store.schedule_detail(schedule)['next_due'],before)
    def test_pause_resume_skips_paused_occurrences_and_stale_save(self):
        now=stamp('2026-11-09T08:00:00');schedule=self.create(now);version=self.store.schedule_detail(schedule)['version']
        self.store.change_schedule(schedule,False,version,now)
        self.store.run_schedules(now+7200);self.assertEqual(self.store.list_batches()['total'],0)
        with self.assertRaises(GateError):self.store.change_schedule(schedule,True,version,now+7200)
        self.store.change_schedule(schedule,True,self.store.schedule_detail(schedule)['version'],now+7200)
        self.store.run_schedules(now+7200);self.assertEqual(self.store.list_batches()['total'],0)
        self.assertGreater(self.store.schedule_detail(schedule)['next_due'],now+7200)
    def test_downtime_only_latest_recent_occurrence_and_old_weekly_is_skipped(self):
        now=stamp('2026-11-01T08:00:00');schedule=self.create(now,recurrence='daily')
        self.store.run_schedules(stamp('2026-11-09T12:00:00'))
        runs=self.store.schedule_detail(schedule)['runs'];self.assertEqual(len(runs),1);self.assertEqual(runs[0]['due'],stamp('2026-11-09T09:00:00'))
        weekly=self.create(now);self.store.run_schedules(stamp('2026-11-11T12:00:00'))
        self.assertEqual(self.store.schedule_detail(weekly)['runs'][0]['status'],'skipped')
    def test_encryption_no_plaintext_collection_once_wrong_password_keeps_output(self):
        schedule=self.create();run=self.store.run_schedule_now(schedule,'b'*32)
        with self.store.connect() as db:
            row=db.execute('SELECT payload FROM schedule_runs WHERE id=?',(run,)).fetchone();payload=row[0]
            self.assertNotIn(b'codes',payload);self.assertNotIn(PASSWORD,' '.join(db.iterdump()))
        with self.assertRaises(GateError):self.store.collect_schedule_run(schedule,run,'wrong-password-1234')
        batch,codes=self.store.collect_schedule_run(schedule,run,PASSWORD)
        self.assertEqual(len(codes),3)
        with self.store.connect() as db:
            dump=' '.join(db.iterdump());self.assertIsNone(db.execute('SELECT payload FROM schedule_runs WHERE id=?',(run,)).fetchone()[0])
            for code in codes:self.assertNotIn(code,dump)
        with self.assertRaises(GateError):self.store.collect_schedule_run(schedule,run,PASSWORD)
        self.store.redeem(codes[0],'10.40.22.99',browser_token='a'*64);self.assertTrue(self.store.browser_grant('a'*64))
    def test_concurrent_collection_only_one_admin_gets_codes(self):
        schedule=self.create();run=self.store.run_schedule_now(schedule,'c'*32)
        def collect(_):
            try:return self.store.collect_schedule_run(schedule,run,PASSWORD)
            except GateError:return None
        with concurrent.futures.ThreadPoolExecutor(2) as pool:results=list(pool.map(collect,range(2)))
        self.assertEqual(sum(r is not None for r in results),1)
    def test_output_expiry_revokes_uncollected_batch(self):
        now=time.time();schedule=self.create(now,validity_value='1',validity_unit='hours');run=self.store.run_schedule_now(schedule,'d'*32,now)
        self.store.expire_schedule_outputs(now+3600)
        detail=self.store.schedule_detail(schedule);self.assertEqual(detail['runs'][0]['status'],'expired')
        with self.assertRaises(GateError):self.store.collect_schedule_run(schedule,run,PASSWORD,now+3600)
        self.assertTrue(self.store.batch_detail(detail['runs'][0]['batch'])['revoked'])
    def test_failed_encryption_rolls_back_batch_and_records_failure(self):
        now=stamp('2026-11-09T08:00:00');schedule=self.create(now)
        with patch('access_gate.scheduling.seal',side_effect=RuntimeError('SECRET')):self.store.run_schedules(now+7200)
        self.assertEqual(self.store.list_batches()['total'],0)
        detail=self.store.schedule_detail(schedule);self.assertEqual(detail['runs'][0]['status'],'failed');self.assertNotIn('SECRET',str(detail))
        self.store.run_schedules(now+7200);self.assertEqual(self.store.list_batches()['total'],0)
    def test_invalid_schedule_does_not_write_or_store_secrets(self):
        for kwargs in (dict(clock='25:00'),dict(timezone='invalid'),dict(recurrence='hourly'),dict(count='0'),dict(access_value='999999')):
            with self.assertRaises(GateError):self.create(**kwargs)
        self.assertEqual(self.store.schedules_page()['total'],0)


class ScheduleWebTests(BrowserWebFixture,unittest.TestCase):
    def setUp(self):
        super().setUp();self.request('/admin/login','POST',dict(csrf=self.csrf(),password='admin'))
    def test_create_render_run_and_collect_are_authenticated(self):
        response=self.request('/admin/schedules/new','POST',dict(SPEC,csrf=self.csrf(),current_password='admin',export_password=PASSWORD,confirm_export_password=PASSWORD))
        self.assertEqual(response.status_code,303);detail=self.request(response.location);self.assertEqual(detail.status_code,200);self.assertNotIn(PASSWORD.encode(),detail.data)
        self.assertEqual(self.request('/admin/schedules').status_code,200)
        schedule=self.store.schedules_page()['items'][0]['id'];run=self.store.run_schedule_now(schedule,'f'*32)
        path=f'/admin/schedules/{schedule}/collect/{run}'
        self.assertEqual(self.request(path,'POST',dict(csrf=self.csrf(),current_password='admin',export_password='wrong-password-1234')).status_code,400)
        self.assertEqual(self.request(path,'POST',dict(csrf=self.csrf(),current_password='admin',export_password=PASSWORD,export='print')).status_code,200)
        self.assertEqual(self.request(path,'POST',dict(csrf=self.csrf(),current_password='admin',export_password=PASSWORD)).status_code,400)
        other=self.app.test_client();self.assertEqual(self.request('/admin/schedules',client=other).status_code,302)
    def test_run_needs_csrf_and_no_export_secret_in_get(self):
        schedule=self.store.create_schedule(SPEC,PASSWORD)
        self.assertEqual(self.request('/admin/schedules/'+schedule,'POST',dict(action='run',request_id='a'*32)).status_code,400)
        self.assertNotIn(b'private_key',self.request('/admin/schedules/'+schedule).data)
