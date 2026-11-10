"""Root-only worker: fixed backup/preflight/restore operations, one job at a time."""
import fcntl
import grp
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from .core import GateError,Store
from .maintenance import Jobs,JOB_ID,MAX_ARCHIVE,read_regular,write_private
from .recovery import STATE_FILES,DATABASE,snapshot,encrypt,preflight,invalidate
from .settings import atomic_write


class Worker:
    def __init__(self,root='/',runner=None,gid=None):
        self.root=Path(root);self.jobs=self.root/'var/lib/access-gate/jobs';self.private=self.root/'var/lib/access-gate/maintenance'
        self.gid=grp.getgrnam('accessgate').gr_gid if gid is None else gid
        self.runner=runner or self.command

    @staticmethod
    def command(args):
        result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=60,text=True)
        if result.returncode:raise GateError('Service validation failed. Check the root maintenance journal and rollback snapshot.')

    def setup(self):
        for path,mode in ((self.jobs,0o755),(self.jobs/'inbox',0o700),(self.jobs/'results',0o750),(self.jobs/'downloads',0o750),(self.private,0o700)):
            if path.is_symlink():raise GateError('Maintenance directories must not be symlinks.')
            path.mkdir(parents=True,exist_ok=True);path.chmod(mode)
        for name in ('results','downloads'):os.chown(self.jobs/name,os.geteuid(),self.gid)
        if self.root==Path('/'):
            import pwd
            user=pwd.getpwnam('accessgate');os.chown(self.jobs/'inbox',user.pw_uid,self.gid)

    def result(self,job_id,**data):
        write_private(self.jobs/'results'/(job_id+'.json'),json.dumps(dict(id=job_id,updated=time.time(),**data)).encode(),0o640,self.gid)

    def installed_version(self):
        return read_regular(self.root/'opt/access-gate/VERSION',100).decode().strip()

    def service(self,*args):self.runner(['/usr/bin/systemctl',*args])

    def apply(self,stage):
        """Called only with stopped services and a fully validated private stage."""
        from .gateway_setup import prepare
        config=json.loads((stage/'etc/access-gate/config.json').read_text());config['secret']=os.urandom(32).hex()
        invalidate(stage/'database',config)
        (stage/'etc/access-gate/config.json').write_text(json.dumps(config))
        for name in STATE_FILES:
            dest=self.root/'etc/access-gate'/name
            if dest.is_symlink():raise GateError('Server state must not contain symlinks.')
            write_private(dest,(stage/'etc/access-gate'/name).read_bytes())
        database=self.root/DATABASE.lstrip('/')
        for suffix in ('-wal','-shm'):Path(str(database)+suffix).unlink(missing_ok=True)
        write_private(database,(stage/'database').read_bytes())
        if self.root==Path('/'):
            import pwd
            uid=pwd.getpwnam('accessgate').pw_uid;os.chown(database,uid,self.gid)
            os.chown(self.root/'etc/access-gate/config.json',0,self.gid);(self.root/'etc/access-gate/config.json').chmod(0o640)
            prepare(self.root)
        else:prepare(self.root,gid=self.gid)
        write_private(self.root/'var/lib/access-gate/public/ca.crt',(stage/'etc/access-gate/ca/root.crt').read_bytes(),0o644)
        atomic_write(self.root/'etc/access-gate/client-networks.nginx',''.join('allow '+n+';\n' for n in config['client_networks'])+'deny all;\n',0o644)

    def restore(self,job_id,preview):
        original=json.loads(read_regular(self.private/(preview+'.json'),MAX_ARCHIVE+8192))
        if original['expires']<time.time():raise GateError('Restore preview expired. Upload the archive again.')
        archive=read_regular(self.private/(preview+'.archive'),MAX_ARCHIVE)
        with tempfile.TemporaryDirectory(dir=self.private) as tmp:
            stage=Path(tmp);summary=preflight(archive,original['passphrase'],stage)
            rollback=self.private/(job_id+'.rollback')
            self.service('stop','access-gate-gateway.service','access-gate.service')
            try:
                saved=snapshot(self.root,self.installed_version());write_private(rollback,encrypt(saved,original['passphrase']))
                self.result(job_id,action='restore',state='running',message='Applying validated backup; all restored access is being invalidated.')
                self.apply(stage)
                self.service('restart','nginx.service','access-gate.service','access-gate-gateway.service')
                self.runner(['/usr/bin/python3','-m','access_gate.readiness'])
            except Exception:
                if rollback.exists():
                    # Revalidate our snapshot, then restore with the same fail-closed invalidation policy.
                    with tempfile.TemporaryDirectory(dir=self.private) as back:
                        preflight(rollback.read_bytes(),original['passphrase'],back);self.apply(Path(back))
                self.service('restart','nginx.service','access-gate.service','access-gate-gateway.service')
                raise GateError('Restore failed. A rollback was attempted; access remains revoked. Check services and the encrypted root rollback snapshot.') from None
        (self.private/(preview+'.json')).unlink(missing_ok=True);(self.private/(preview+'.archive')).unlink(missing_ok=True)
        return dict(message='Restore completed and services passed readiness. Sign in with the password from the backup. All restored codes and sessions are revoked.',summary=summary)

    def perform(self,job_id,record):
        action=record['action']
        if action=='backup':
            if set(record)-{'id','action','created','passphrase'}:raise GateError('Unexpected backup fields.')
            encrypted=encrypt(snapshot(self.root,self.installed_version()),record.get('passphrase'))
            write_private(self.jobs/'downloads'/(job_id+'.agbackup'),encrypted,0o640,self.gid)
            Store(self.root/DATABASE.lstrip('/'),json.loads((self.root/'etc/access-gate/config.json').read_text())['pepper']).audit('recovery.backup',actor='System')
            return dict(message='Encrypted backup ready. Download within seven days.',download=True)
        if action=='preflight':
            if set(record)-{'id','action','created','passphrase'}:raise GateError('Unexpected preflight fields.')
            archive=read_regular(self.jobs/'inbox'/(job_id+'.archive'),MAX_ARCHIVE)
            with tempfile.TemporaryDirectory(dir=self.private) as tmp:summary=preflight(archive,record.get('passphrase'),tmp)
            write_private(self.private/(job_id+'.archive'),archive)
            write_private(self.private/(job_id+'.json'),json.dumps(dict(passphrase=record['passphrase'],expires=time.time()+900)).encode())
            return dict(message='Preflight passed. Confirm within 15 minutes. Nothing has been replaced.',summary=summary,confirm=True)
        if action=='restore':
            if set(record)-{'id','action','created','preview'} or not JOB_ID.fullmatch(record.get('preview','')):raise GateError('Invalid restore preview.')
            return self.restore(job_id,record['preview'])
        raise GateError('Unknown maintenance action.')

    def run_once(self):
        self.setup()
        with open(self.private/'worker.lock','a') as lock:
            try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:return
            # Recover a crash marker without replaying a potentially applied restore.
            for marker in self.private.glob('*.running'):
                job_id=marker.stem
                if JOB_ID.fullmatch(job_id):self.result(job_id,action='maintenance',state='failed',message='Worker interrupted. Operation was not replayed. Check services before retrying.')
                marker.unlink()
            for source in sorted((self.jobs/'inbox').glob('*.json'))[:100]:
                job_id=source.stem
                if not JOB_ID.fullmatch(job_id):continue
                marker=self.private/(job_id+'.running')
                try:
                    data=read_regular(source,8192);source.unlink()
                    if (self.jobs/'results'/(job_id+'.json')).exists():continue
                    record=json.loads(data)
                    if record.get('id')!=job_id or not isinstance(record.get('created'),(int,float)) or not 0<=time.time()-record['created']<=3600:raise GateError('Invalid or stale maintenance request.')
                    write_private(marker,b'running')
                    self.result(job_id,action=record.get('action','maintenance'),state='running',message='Maintenance in progress.')
                    result=self.perform(job_id,record)
                    self.result(job_id,action=record['action'],state='complete',**result)
                except Exception as exc:
                    # Never serialize arbitrary exceptions, config, archive contents or passphrases.
                    message=str(exc) if isinstance(exc,GateError) else 'Maintenance failed validation. No secrets were included in this result.'
                    self.result(job_id,action='maintenance',state='failed',message=message[:500])
                finally:
                    marker.unlink(missing_ok=True);source.unlink(missing_ok=True)
                    (self.jobs/'inbox'/(job_id+'.archive')).unlink(missing_ok=True)
            self.cleanup()

    def cleanup(self):
        now=time.time()
        for directory,seconds in ((self.jobs/'downloads',7*86400),(self.jobs/'results',30*86400),(self.jobs/'inbox',3600),(self.private,900)):
            for path in directory.iterdir():
                if path.is_file() and not path.is_symlink() and path.suffix not in ('.lock','.rollback') and now-path.stat().st_mtime>seconds:path.unlink(missing_ok=True)


def main():
    if os.geteuid()!=0:raise SystemExit('Run the maintenance worker as root.')
    worker=Worker()
    while True:
        worker.run_once();time.sleep(2)


if __name__=='__main__':main()
