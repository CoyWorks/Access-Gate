"""Bounded read-only DNS monitor snapshots; no optional DNS dependency."""
import hashlib
import json
import math
import os
import re
from pathlib import Path
import stat
import time

HEALTH_PATH=Path('/var/lib/access-gate/dns/health.json')
MAX_BYTES=128*1024


def fingerprint(config):
    from .deployment import names
    fields={key:config[key] for key in ('listen_ipv4','dns_target_ipv4','dns_upstreams','client_networks')}
    fields['portal_names']=config.get('portal_names') or names(config)
    return hashlib.sha256(json.dumps(fields,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def read_small(path,limit):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size>limit:raise ValueError('Invalid monitor file.')
        raw=stream.read(limit+1)
    if len(raw)>limit:raise ValueError('Invalid monitor file.')
    return json.loads(raw)


def read_health(config,path=HEALTH_PATH,now=None):
    now=time.time() if now is None else now
    if config['dns_mode']!='builtin':return dict(state='not configured',stale=False,snapshot=None,message='Built-in DNS is not selected. Pi-hole health is managed on that service.')
    try:
        data=read_small(path,MAX_BYTES)
        if data['format']!=1 or data['configuration']!=fingerprint(config):raise ValueError('Monitor configuration changed.')
        if not isinstance(data['history'],list) or len(data['history'])>72 or len(data['upstreams'])>3:raise ValueError('Invalid monitor size.')
        stamp=data['updated']
        if not isinstance(stamp,(float,int)) or not math.isfinite(stamp):raise ValueError('Invalid monitor clock.')
        if not re.fullmatch('[0-9a-f]{16}',data['boot_id']) or not isinstance(data['started'],(int,float)) or not math.isfinite(data['started']):raise ValueError('Invalid monitor identity.')
        if set(data['local'])!={'UDP','TCP'} or set(data['upstreams'])!=set(config['dns_upstreams']):raise ValueError('Invalid probe labels.')
        for row in list(data['local'].values())+list(data['upstreams'].values()):
            if row['state'] not in ('healthy','failed','unknown') or row['reason'] not in ('Not checked','Valid response','Invalid response','Timeout','Network or DNS error'):raise ValueError('Invalid probe state.')
            if any(type(row[k]) is not int or row[k]<0 for k in ('count','success','failure')) or row['count']!=row['success']+row['failure']:raise ValueError('Invalid counters.')
            for key in ('total_ms','max_ms','mean_ms','last_success'):
                if row[key] is not None and (not isinstance(row[key],(float,int)) or not math.isfinite(row[key]) or row[key]<0):raise ValueError('Invalid aggregate.')
        if data['publisher']['state'] not in ('healthy','failed','unknown'):raise ValueError('Invalid publisher status.')
        for sample in data['history']:
            if sample['state'] not in ('healthy','degraded','failed','unknown') or not isinstance(sample['at'],(int,float)) or not math.isfinite(sample['at']):raise ValueError('Invalid history sample.')
        state=data['state']
        if state not in ('healthy','degraded','failed','unknown'):raise ValueError('Invalid monitor state.')
        stale=not 0<=now-stamp<=30
        return dict(state='unknown' if stale else state,stale=stale,snapshot=data,message='DNS monitor samples are stale; check the DNS rule publisher and monitor process.' if stale else 'Fixed server-side probes only; this does not prove client DNS, browser routing or CA trust.')
    except (OSError,ValueError,KeyError,TypeError,OverflowError):
        return dict(state='unknown',stale=True,snapshot=None,message='DNS monitor data is missing, invalid or from another configuration. Check the DNS rule publisher service.')
