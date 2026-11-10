"""Controlled Git updates for the dedicated server; no user-supplied commands or URLs."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
from .core import GateError
from .maintenance import JOB_ID,read_regular,write_private

REMOTE='https://github.com/CoyWorks/Access-Gate.git'
SHA=re.compile(r'^[a-f0-9]{40}$')


def installed(root='/'):
    root=Path(root)
    try:version=read_regular(root/'opt/access-gate/VERSION',100).decode().strip()
    except (OSError,ValueError):version='Unknown'
    try:
        metadata=json.loads(read_regular(root/'etc/access-gate/deployment.json',8192))
        if metadata.get('version')!=version:raise ValueError()
        commit=metadata.get('commit')
        if commit is not None and not SHA.fullmatch(commit):raise ValueError()
        return dict(version=version,commit=commit,deployed_at=metadata.get('deployed_at'))
    except (OSError,ValueError,TypeError):return dict(version=version,commit=None,deployed_at=None)


class Updates:
    def __init__(self,root='/',runner=None):
        self.root=Path(root);self.repo=self.root/'opt/access-gate-update-src';self.private=self.root/'var/lib/access-gate/maintenance'
        self.runner=runner or self.command

    @staticmethod
    def command(args,timeout=120,**kwargs):
        try:
            result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=timeout,env=dict(os.environ,GIT_TERMINAL_PROMPT='0'),**kwargs)
        except (OSError,subprocess.SubprocessError):raise GateError('Git/update command could not finish. Check the root maintenance journal; no automatic retry was performed.') from None
        if result.returncode:raise GateError('Git refused the update or the remote could not be reached. Check the root maintenance journal. Local changes were not overwritten.')
        if len(result.stdout)>65536:raise GateError('Unexpectedly large Git response.')
        return result.stdout.strip()

    def git(self,*args):
        return self.runner(['/usr/bin/git','-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false','-c','protocol.file.allow=never','-C',str(self.repo),*args])

    def owned_directory(self,path):
        path=Path(path)
        for parent in (path,*path.parents):
            if parent==self.root.parent:break
            info=parent.lstat()
            if parent.is_symlink() or not parent.is_dir() or info.st_mode&0o022:raise GateError('Update source must be a protected directory without symlinked or writable parents.')
            if self.root==Path('/') and info.st_uid!=0:raise GateError('Update source must be owned by root.')
            if parent==self.root:break

    def checkout(self):
        if not self.repo.exists():
            self.owned_directory(self.repo.parent)
            with tempfile.TemporaryDirectory(prefix='.access-gate-fetch-',dir=self.repo.parent) as temp:
                destination=Path(temp)/'source'
                self.runner(['/usr/bin/git','-c','core.hooksPath=/dev/null','-c','protocol.file.allow=never','clone','--branch','main','--single-branch','--',REMOTE,str(destination)])
                os.replace(destination,self.repo);self.repo.chmod(0o700)
        self.owned_directory(self.repo)
        if (self.repo/'.git').is_symlink() or not (self.repo/'.git').is_dir():raise GateError('The update source must be an ordinary Git clone.')
        if self.git('remote','get-url','origin')!=REMOTE:raise GateError('Update source origin differs from CoyWorks/Access-Gate. No deployment was started.')
        if self.git('symbolic-ref','--quiet','--short','HEAD')!='main':raise GateError('Update source is not on main. No deployment was started.')
        if self.git('status','--porcelain','--untracked-files=all'):raise GateError('Update source has local changes or untracked files. Move or commit them before retrying.')

    def check(self,job_id,save=True):
        self.checkout();before=self.git('rev-parse','HEAD')
        self.git('fetch','--prune','origin','+refs/heads/main:refs/remotes/origin/main')
        if self.git('rev-parse','HEAD')!=before or self.git('status','--porcelain','--untracked-files=all'):raise GateError('Update source changed during fetch. No deployment was started.')
        latest=self.git('rev-parse','refs/remotes/origin/main')
        if not SHA.fullmatch(latest) or not SHA.fullmatch(before):raise GateError('Invalid Git commit identity.')
        try:self.git('merge-base','--is-ancestor',before,latest)
        except GateError:raise GateError('Local and remote source history diverged. No deployment was started.') from None
        version=self.git('show',latest+':VERSION')
        if len(version)>64 or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[-+.][a-zA-Z0-9.-]+)?',version):raise GateError('Remote version is not valid.')
        current=installed(self.root)
        if current.get('commit') and current['commit']!=latest:
            try:self.git('merge-base','--is-ancestor',current['commit'],latest)
            except GateError:raise GateError('Installed and available commit history diverged. An automatic downgrade is not allowed.') from None
        if re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',current['version']):
            remote_core=version.split('-')[0].split('+')[0]
            if tuple(map(int,remote_core.split('.')))<tuple(map(int,current['version'].split('.'))):raise GateError('Available version is older than the installed version. Automatic downgrade is not allowed.')
        change_range=(current['commit']+'..'+latest) if current.get('commit') and current['commit']!=latest else latest
        try:changes=self.git('log','--format=%h %s','-10',change_range)[:1000]
        except GateError:changes=self.git('log','--format=%h %s','-10',latest)[:1000]
        available=current['commit']!=latest
        preview=dict(installed=current,available_version=version,available_commit=latest,changes=changes,update_available=available,checked_at=time.time(),expires=time.time()+900)
        if save:write_private(self.private/(job_id+'.update-preview'),json.dumps(preview).encode())
        return dict(message='Update check complete.' if available else 'The installed commit is current.',update=preview,update_confirm=available)

    def apply(self,job_id,preview_id,progress):
        if not JOB_ID.fullmatch(preview_id or ''):raise GateError('Invalid update preview.')
        file=self.private/(preview_id+'.update-preview')
        try:preview=json.loads(read_regular(file,16384))
        except FileNotFoundError:raise GateError('Update preview was already used or expired. Check for updates again.') from None
        if preview['expires']<time.time() or preview['installed']!=installed(self.root):raise GateError('The installed version changed or the preview expired. Check for updates again.')
        if not preview['update_available']:raise GateError('The installed commit is already current.')
        progress('Rechecking the reviewed source commit before installation.')
        latest=self.check(job_id,save=False)['update']
        if latest['available_commit']!=preview['available_commit']:raise GateError('A newer remote commit appeared. Check for updates and review it before installing.')
        file.unlink() # This confirmation can start only one installation, including after restart.
        self.git('merge','--ff-only','--no-edit',preview['available_commit'])
        if self.git('rev-parse','HEAD')!=preview['available_commit']:raise GateError('Checkout did not reach the reviewed commit.')
        for path in self.repo.rglob('*'):
            if '.git' not in path.relative_to(self.repo).parts and path.is_symlink():raise GateError('Update source contains unsupported symlinks.')
        progress('Installing the reviewed commit. The portal may briefly disconnect; this job survives its restart.')
        log=self.private/(job_id+'.update.log')
        self.deploy(job_id,log)
        progress('Installation returned successfully. Verifying deployed identity and HTTPS readiness.')
        deployed=installed(self.root)
        if deployed['version']!=preview['available_version'] or deployed['commit']!=preview['available_commit']:raise GateError('Installed identity does not match the reviewed commit. Inspect the root update log and deployment metadata.')
        self.runner(['/usr/bin/python3','-m','access_gate.readiness'],cwd=str(self.root/'opt/access-gate'),timeout=60)
        backup=None
        if log.exists():
            # Return only the fixed installer backup marker, never root stdout or secrets.
            with log.open(errors='replace') as stream:
                for line in stream:
                    match=re.fullmatch(r'Existing server state backed up to (/root/access-gate-resume\.[a-zA-Z0-9]+)\n?',line)
                    if match:backup=match.group(1)
        return dict(message='Update complete. Installed identity and HTTPS readiness passed.',deployed=deployed,backup_location=backup)

    def deploy(self,job_id,log):
        # The same freshly fetched update.sh --local/install.sh workflow used by the CLI.
        env=dict(os.environ,ACCESS_GATE_MAINTENANCE_JOB=job_id,GIT_TERMINAL_PROMPT='0')
        try:
            with open(log,'xb') as output:
                os.chmod(log,0o600)
                result=subprocess.run(['/bin/bash',str(self.repo/'update.sh'),'--local'],cwd=self.repo,env=env,stdout=output,stderr=subprocess.STDOUT,timeout=1800)
            if result.returncode:raise GateError('Update failed its installer or service checks. Root log and the installer backup are retained. No automatic downgrade was attempted.')
        except (OSError,subprocess.TimeoutExpired):raise GateError('Update was interrupted or timed out. Check the root update log and service state before retrying.') from None
