"""Root-side, fixed-path Squid policy apply with rollback; no shell input."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

from .operations import validate_rule


def atomic_write(path,text,mode=0o644):
    path=Path(path)
    previous_stat=path.stat() if path.exists() else None
    fd,temp=tempfile.mkstemp(prefix='.'+path.name+'-',dir=path.parent)
    try:
        with os.fdopen(fd,'w') as stream:
            stream.write(text); stream.flush(); os.fsync(stream.fileno())
            os.fchmod(stream.fileno(),mode)
            if previous_stat: os.fchown(stream.fileno(),previous_stat.st_uid,previous_stat.st_gid)
        os.replace(temp,path)
    finally:
        if os.path.exists(temp): os.unlink(temp)


def render_acl(rules):
    entries=[]
    for rule in rules:
        domain,_=validate_rule(rule['domain'],rule['subdomains'],rule['description'])
        if rule['enabled']: entries.append(('.' if rule['subdomains'] else '')+domain)
    return '\n'.join(entries or ['.access-gate.invalid'])+'\n'


def apply_policy(store,path='/etc/access-gate/restricted.acl',run=subprocess.run,close_connections=None,force=False):
    with store.connect() as db:
        db.execute('BEGIN IMMEDIATE')
        state=dict(db.execute('SELECT * FROM policy_state WHERE id=1').fetchone())
        if not force and state['desired']==state['applied'] and not state['applying']: return True
        rules=[dict(r) for r in db.execute('SELECT * FROM domain_rules ORDER BY domain')]
        candidate=render_acl(rules)  # Validate again at the privilege boundary.
        db.execute('UPDATE policy_state SET applying=1 WHERE id=1'); db.commit()
    path=Path(path); previous=path.read_text() if path.exists() else '.access-gate.invalid\n'
    success=False; error=''
    try:
        atomic_write(path,candidate)
        run(['/usr/sbin/squid','-k','parse'],check=True,capture_output=True,timeout=15)
        run(['/usr/bin/systemctl','reload','squid.service'],check=True,capture_output=True,timeout=15)
        if close_connections: close_connections()
        success=True
    except (OSError,subprocess.SubprocessError) as exc:
        error='Squid policy apply failed; previous rules restored. Check journalctl -u access-gate-keeper -u squid, then Retry apply.'
        try:
            atomic_write(path,previous)
            run(['/usr/sbin/squid','-k','parse'],check=True,capture_output=True,timeout=15)
            run(['/usr/bin/systemctl','reload','squid.service'],check=True,capture_output=True,timeout=15)
        except (OSError,subprocess.SubprocessError):
            error='Squid rollback failed. Proxy stopped to prevent an uncertain policy. Check service logs before retrying.'
            run(['/usr/bin/systemctl','stop','squid.service'],check=True,capture_output=True,timeout=15)
        print('Access Gate: '+error,flush=True)
    finally:
        with store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if success:
                db.execute("UPDATE policy_state SET applied=?,applied_json=?,applying=0,error='' WHERE id=1",(state['desired'],json.dumps(rules)))
            else: db.execute('UPDATE policy_state SET applying=0,error=? WHERE id=1',(error,))
            db.commit()
    return success
