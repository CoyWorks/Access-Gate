"""Root-only setup for optional DNS; only public deployment settings reach it."""
import grp
import json
import os
from pathlib import Path
import pwd
from .deployment import normalize,names
from .settings import atomic_write


def public_config(c):
    public={k:c[k] for k in ('listen_ipv4','dns_target_ipv4','client_networks','dns_upstreams')}
    public['portal_names']=names(c)
    return public


def prepare():
    c=normalize(json.loads(Path('/etc/access-gate/config.json').read_text()))
    if c['dns_mode']!='builtin':return
    dns_gid=grp.getgrnam('accessgate-dns').gr_gid;portal_uid=pwd.getpwnam('accessgate').pw_uid
    directory=Path('/var/lib/access-gate/dns');directory.mkdir(exist_ok=True)
    os.chown(directory,portal_uid,dns_gid);directory.chmod(0o2750)
    public=public_config(c)
    path=Path('/etc/access-gate/dns.json');atomic_write(path,json.dumps(public)+'\n',0o640);os.chown(path,0,dns_gid)
    from .recovery import database_account
    from .dns_publisher import snapshot
    import time
    with database_account(Path('/')):payload,count=snapshot(c)
    for name in ('rules.json','status.json'):
        if (directory/name).is_symlink():raise ValueError('DNS state must not be symlinked.')
    atomic_write(directory/'rules.json',payload,0o640)
    atomic_write(directory/'status.json',json.dumps(dict(state='healthy',updated=time.time(),domains=count))+'\n',0o640)
    for name in ('rules.json','status.json'):os.chown(directory/name,portal_uid,dns_gid);(directory/name).chmod(0o640)


if __name__=='__main__':prepare()
