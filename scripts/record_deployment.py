#!/usr/bin/env python3
"""Record the source identity only after the installed services pass readiness."""
import grp
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time


def record(source,root=Path('/'),gid=None):
    source=Path(source);root=Path(root);commit=None
    def git(*args):
        return subprocess.run(['/usr/bin/git','-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false','-C',str(source),*args],capture_output=True,text=True,timeout=5)
    try:
        identity=git('rev-parse','HEAD');dirty=git('status','--porcelain','--untracked-files=all')
        if identity.returncode==0 and dirty.returncode==0 and not dirty.stdout.strip() and re.fullmatch('[a-f0-9]{40}',identity.stdout.strip()):commit=identity.stdout.strip()
    except (OSError,subprocess.SubprocessError):pass
    version=(root/'opt/access-gate/VERSION').read_text().strip()
    data=dict(version=version,commit=commit,deployed_at=time.time())
    destination=root/'etc/access-gate/deployment.json'
    fd,temp=tempfile.mkstemp(prefix='.deployment-',dir=destination.parent)
    try:
        with os.fdopen(fd,'w') as stream:
            json.dump(data,stream);stream.write('\n');stream.flush();os.fsync(stream.fileno());os.fchmod(stream.fileno(),0o640)
            os.fchown(stream.fileno(),os.geteuid(),grp.getgrnam('accessgate').gr_gid if gid is None else gid)
        os.replace(temp,destination)
    finally:
        if os.path.exists(temp):os.unlink(temp)
    return data


if __name__=='__main__':
    if os.geteuid()!=0:raise SystemExit('Run deployment recording as root.')
    if len(sys.argv)!=2:raise SystemExit('Usage: record_deployment.py SOURCE')
    record(sys.argv[1])
