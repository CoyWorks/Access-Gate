import importlib.util
import json
import os
from pathlib import Path
import secrets
import tempfile
import time
import unittest
from unittest.mock import patch
from access_gate.core import GateError
from access_gate.maintenance import Jobs
from access_gate.updates import Updates,REMOTE,installed
from test_browser_portal import BrowserWebFixture

OLD='a'*40
NEW='b'*40
LATER='c'*40


class UpdateBackendTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        for name in ('opt/access-gate','opt/access-gate-update-src/.git','etc/access-gate','var/lib/access-gate/maintenance'):(self.root/name).mkdir(parents=True,exist_ok=True)
        (self.root/'opt/access-gate/VERSION').write_text('0.12.0')
        self.metadata=dict(version='0.12.0',commit=OLD,deployed_at=1000)
        (self.root/'etc/access-gate/deployment.json').write_text(json.dumps(self.metadata))
        self.head=OLD;self.latest=NEW;self.dirty=False;self.diverged=False;self.remote=REMOTE;self.branch='main';self.calls=[];self.deploys=0
        self.updates=Updates(self.root,runner=self.runner)
    def tearDown(self):self.temp.cleanup()
    def runner(self,args,**kwargs):
        self.calls.append((args,kwargs))
        if args[0]=='/usr/bin/python3':return ''
        command=args[args.index('-C')+2:]
        if command[:2]==['remote','get-url']:return self.remote
        if command[0]=='symbolic-ref':return self.branch
        if command[0]=='status':return ' M VERSION' if self.dirty else ''
        if command[:2]==['rev-parse','HEAD']:return self.head
        if command[:2]==['rev-parse','refs/remotes/origin/main']:return self.latest
        if command[0]=='fetch':return ''
        if command[0]=='merge-base':
            if self.diverged:raise GateError('diverged')
            return ''
        if command[0]=='show':return '0.13.0'
        if command[0]=='log':return 'bbbbbbb Add updates\naaaaaaa Previous release'
        if command[0]=='merge':self.head=command[-1];return ''
        raise AssertionError(command)
    def deploy(self,job_id,log):
        self.deploys+=1;(self.root/'opt/access-gate/VERSION').write_text('0.13.0')
        (self.root/'etc/access-gate/deployment.json').write_text(json.dumps(dict(version='0.13.0',commit=NEW,deployed_at=2000)))
        log.write_text('Existing server state backed up to /root/access-gate-resume.Test123\nPrivate output MUST NOT be returned\n')
    def test_installed_version_comes_from_deployment_not_source_clone(self):
        (self.root/'opt/access-gate-update-src/VERSION').write_text('99.0.0')
        result=self.updates.check('d'*32);self.assertEqual(result['update']['installed']['version'],'0.12.0');self.assertEqual(result['update']['available_version'],'0.13.0')
        (self.root/'opt/access-gate/VERSION').write_text('0.12.1')
        self.assertIsNone(installed(self.root)['commit']);self.assertEqual(installed(self.root)['version'],'0.12.1')
    def test_reviewed_update_is_applied_once_with_progress_and_health(self):
        preview='d'*32;self.updates.check(preview);progress=[]
        with patch.object(self.updates,'deploy',side_effect=self.deploy):result=self.updates.apply('e'*32,preview,progress.append)
        self.assertEqual(self.deploys,1);self.assertEqual(result['deployed']['commit'],NEW);self.assertEqual(result['backup_location'],'/root/access-gate-resume.Test123')
        self.assertNotIn('Private output',str(result));self.assertEqual(len(progress),3)
        self.assertTrue(any(c[0][0]=='/usr/bin/python3' and c[1]['timeout']==60 for c in self.calls))
        with self.assertRaises(GateError):self.updates.apply('f'*32,preview,progress.append)
    def test_dirty_diverged_wrong_remote_and_branch_refuse_before_deploy(self):
        for field,value in (('dirty',True),('diverged',True),('remote','https://example.org/repo.git'),('branch','feature')):
            with self.subTest(field=field):
                previous=getattr(self,field);setattr(self,field,value)
                with self.assertRaises(GateError):self.updates.check('d'*32)
                setattr(self,field,previous)
        self.assertEqual(self.deploys,0)
    def test_remote_movement_stale_install_and_expired_previews_refuse(self):
        preview='d'*32;self.updates.check(preview);self.latest=LATER
        with self.assertRaises(GateError):self.updates.apply('e'*32,preview,lambda _:None)
        self.latest=NEW;self.updates.check(preview)
        (self.root/'opt/access-gate/VERSION').write_text('0.12.1')
        with self.assertRaises(GateError):self.updates.apply('e'*32,preview,lambda _:None)
        (self.root/'opt/access-gate/VERSION').write_text('0.12.0');self.updates.check(preview)
        path=self.updates.private/(preview+'.update-preview');data=json.loads(path.read_text());data['expires']=0;path.write_text(json.dumps(data))
        with self.assertRaises(GateError):self.updates.apply('e'*32,preview,lambda _:None)
        self.assertEqual(self.deploys,0)
    def test_installer_or_postcheck_failure_does_not_report_success_or_replay(self):
        preview='d'*32;self.updates.check(preview)
        with patch.object(self.updates,'deploy',side_effect=GateError('Installer failed.')):
            with self.assertRaises(GateError):self.updates.apply('e'*32,preview,lambda _:None)
        self.assertFalse((self.updates.private/(preview+'.update-preview')).exists())
        self.assertEqual(installed(self.root)['commit'],OLD)
    def test_symlinked_or_writable_source_refused(self):
        self.updates.repo.chmod(0o777)
        with self.assertRaises(GateError):self.updates.check('d'*32)
        self.updates.repo.chmod(0o700)
        target=self.updates.repo/'.git';target.rmdir();target.symlink_to(self.root/'etc')
        with self.assertRaises(GateError):self.updates.check('d'*32)
    def test_network_failure_stops_check_and_keeps_installed_state(self):
        def runner(args,**kwargs):
            if 'fetch' in args:raise GateError('Network unavailable.')
            return self.runner(args,**kwargs)
        self.updates.runner=runner
        with self.assertRaises(GateError):self.updates.check('d'*32)
        self.assertEqual(installed(self.root)['commit'],OLD)
    def test_no_automatic_downgrade(self):
        (self.root/'opt/access-gate/VERSION').write_text('9.0.0')
        with self.assertRaises(GateError):self.updates.check('d'*32)


class UpdateWebTests(BrowserWebFixture,unittest.TestCase):
    def setUp(self):
        super().setUp();self.jobs=self.app.extensions['jobs'];self.jobs.root=self.root/'jobs'
        for name in ('inbox','results'):(self.jobs.root/name).mkdir(parents=True,exist_ok=True)
    def login(self):self.request('/admin/login','POST',dict(csrf=self.csrf(),password='admin'))
    def test_check_update_needs_admin_csrf_password_and_review(self):
        self.assertEqual(self.request('/admin/updates').status_code,302);self.login()
        self.assertEqual(self.request('/admin/updates').status_code,200)
        self.assertEqual(self.request('/admin/updates','POST',dict(action='check')).status_code,400)
        response=self.request('/admin/updates','POST',dict(csrf=self.csrf(),action='check'));self.assertEqual(response.status_code,303)
        preview=response.location.rsplit('/',1)[-1]
        state=dict(id=preview,action='update-check',state='complete',update_confirm=True,updated=time.time(),message='Checked.',update=dict(installed=dict(version='0.12.0',commit=OLD),available_version='0.13.0',available_commit=NEW,checked_at=time.time(),changes='<script>unsafe</script>'))
        (self.jobs.root/'results'/(preview+'.json')).write_text(json.dumps(state))
        detail=self.request(response.location);self.assertIn(b'&lt;script&gt;unsafe&lt;/script&gt;',detail.data);self.assertNotIn(b'<script>unsafe',detail.data)
        base=dict(csrf=self.csrf(),action='update',preview=preview,confirm='UPDATE')
        self.assertEqual(self.request('/admin/updates','POST',dict(base,current_password='bad')).status_code,400)
        self.assertEqual(self.request('/admin/updates','POST',dict(base,current_password='admin')).status_code,303)
        other=self.app.test_client();self.assertEqual(self.request('/admin/api/maintenance/'+preview,client=other).status_code,302)
    def test_worker_result_survives_portal_recreation_and_job_is_not_replayed(self):
        from access_gate.maintenance_worker import Worker
        worker=Worker(self.root,runner=lambda _:None,gid=os.getgid());worker.setup();self.jobs.root=worker.jobs
        job=self.jobs.submit('update-check')
        with patch('access_gate.updates.Updates.check',return_value=dict(message='Check failed safely.',update_confirm=False)) as check:
            worker.run_once();worker.run_once();self.assertEqual(check.call_count,1)
        recreated=Jobs(worker.jobs);self.assertEqual(recreated.status(job)['state'],'complete')
    def test_crash_before_inbox_removal_never_replays_the_job(self):
        from access_gate.maintenance_worker import Worker
        worker=Worker(self.root,runner=lambda _:None,gid=os.getgid());worker.setup();self.jobs.root=worker.jobs
        job=self.jobs.submit('update-check')
        (worker.private/(job+'.running')).write_text(json.dumps(dict(action='update-check')))
        with patch('access_gate.updates.Updates.check') as check:
            worker.run_once();check.assert_not_called()
        self.assertEqual(self.jobs.status(job)['state'],'failed')
        self.assertFalse((worker.jobs/'inbox'/(job+'.json')).exists())

    def test_failed_jobs_retain_update_action_and_dont_expose_errors(self):
        from access_gate.maintenance_worker import Worker
        worker=Worker(self.root,runner=lambda _:None,gid=os.getgid());worker.setup();self.jobs.root=worker.jobs
        job=self.jobs.submit('update-check')
        with patch('access_gate.updates.Updates.check',side_effect=RuntimeError('PRIVATE TOKEN')):worker.run_once()
        state=self.jobs.status(job);self.assertEqual(state['action'],'update-check');self.assertEqual(state['state'],'failed');self.assertNotIn('PRIVATE TOKEN',str(state))


class DeploymentIdentityTests(unittest.TestCase):
    def setUp(self):
        spec=importlib.util.spec_from_file_location('record_deployment',Path(__file__).resolve().parents[1]/'scripts/record_deployment.py')
        self.module=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.module)
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        (self.root/'opt/access-gate').mkdir(parents=True);(self.root/'etc/access-gate').mkdir(parents=True)
        (self.root/'opt/access-gate/VERSION').write_text('0.13.0')
    def tearDown(self):self.temp.cleanup()
    def test_only_clean_source_commit_is_recorded_with_installed_version(self):
        import subprocess
        with patch.object(self.module.subprocess,'run',side_effect=[subprocess.CompletedProcess([],0,NEW+'\n',''),subprocess.CompletedProcess([],0,'','')]):
            data=self.module.record(self.root,self.root,gid=os.getgid())
        self.assertEqual(data['commit'],NEW);self.assertEqual(installed(self.root)['version'],'0.13.0')
        self.assertEqual((self.root/'etc/access-gate/deployment.json').stat().st_mode&0o777,0o640)
        with patch.object(self.module.subprocess,'run',side_effect=[subprocess.CompletedProcess([],0,NEW+'\n',''),subprocess.CompletedProcess([],0,' M web.py','')]):
            data=self.module.record(self.root,self.root,gid=os.getgid())
        self.assertIsNone(data['commit'])
    def test_archive_install_records_unknown_commit_without_fabricating_one(self):
        with patch.object(self.module.subprocess,'run',side_effect=FileNotFoundError()):data=self.module.record(self.root,self.root,gid=os.getgid())
        self.assertIsNone(data['commit']);self.assertEqual(data['version'],'0.13.0')
