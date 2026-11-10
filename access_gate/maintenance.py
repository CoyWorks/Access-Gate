"""Fixed-action maintenance queue. The portal never executes privileged commands."""
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time
from .core import GateError

JOB_ID=re.compile(r'^[a-f0-9]{32}$')
MAX_ARCHIVE=64*1024*1024


def read_regular(path,limit):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size>limit:raise GateError('Unsupported or oversized maintenance file.')
        data=stream.read(limit+1)
        if len(data)>limit:raise GateError('Maintenance file is too large.')
        return data


def write_private(path,data,mode=0o600,gid=None):
    path=Path(path);temp=path.parent/('.'+secrets.token_hex(16))
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    try:
        with os.fdopen(fd,'wb') as stream:
            stream.write(data);stream.flush();os.fsync(stream.fileno())
            if gid is not None:os.fchown(stream.fileno(),os.geteuid(),gid)
            os.fchmod(stream.fileno(),mode)
        os.replace(temp,path)
    finally:
        temp.unlink(missing_ok=True)


class Jobs:
    def __init__(self,root='/var/lib/access-gate/jobs'):
        self.root=Path(root)

    def submit(self,action,**values):
        if action not in ('backup','preflight','restore'):raise GateError('Unknown maintenance action.')
        if not (self.root/'inbox').is_dir():raise GateError('Maintenance worker is not installed. Run the normal updater first.')
        job_id=secrets.token_hex(16)
        # No overwriting another job, no client-supplied file names or paths.
        archive=values.pop('archive',None)
        if archive is not None:
            if not isinstance(archive,bytes) or not archive or len(archive)>MAX_ARCHIVE:raise GateError('Choose an encrypted backup of at most 64 MiB.')
            write_private(self.root/'inbox'/(job_id+'.archive'),archive)
        record=dict(id=job_id,action=action,created=time.time(),**values)
        write_private(self.root/'inbox'/(job_id+'.json'),json.dumps(record).encode())
        return job_id

    def status(self,job_id):
        if not JOB_ID.fullmatch(job_id):raise GateError('Invalid job identifier.')
        try:return json.loads(read_regular(self.root/'results'/(job_id+'.json'),8192))
        except FileNotFoundError:
            if (self.root/'inbox'/(job_id+'.json')).is_file():return dict(id=job_id,state='queued',action='maintenance',message='Waiting for the maintenance worker.')
            raise GateError('Maintenance job not found or expired.')

    def recent(self):
        try:files=sorted((self.root/'results').glob('*.json'),key=lambda p:p.stat().st_mtime,reverse=True)[:20]
        except FileNotFoundError:return []
        return [self.status(p.stem) for p in files if JOB_ID.fullmatch(p.stem)]
