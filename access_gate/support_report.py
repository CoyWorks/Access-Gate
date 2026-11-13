"""Allowlisted, bounded support snapshots; no config/log/history serialization."""
import datetime as dt
import json
import math
import re
import threading
import time
from concurrent.futures import Future,TimeoutError
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from .maintenance import read_regular
from .updates import installed
from .dns_health_view import read_health
from .performance import COUNTERS

CHECKS=('Portal','Database','access-gate','access-gate-gateway','access-gate-maintenance','access-gate-scheduler',
        'access-gate-push','nginx','access-gate-dns','access-gate-dns-rules','access-gate-remote-domains',
        'Clock synchronization','Gateway HTTPS','Activity delivery','DNS synchronization','DNS probes','Remote DNS synchronization')
CERTS=('Device root CA','Portal certificate','Gateway issuing certificate')
STATES=('healthy','warning','failed','unknown')
MAX_REPORT=12000

def stamp(value,future=False):
    return value if type(value) in (int,float) and math.isfinite(value) and 0<=value<=(253402300799 if future else time.time()+300) else None

def state(value):return value if isinstance(value,str) and value in STATES else 'unknown'
def fingerprint(value):return value.upper() if isinstance(value,str) and re.fullmatch('[A-Fa-f0-9]{64}',value) else None

def certificate(path):
    cert=x509.load_pem_x509_certificate(read_regular(path,65536))
    return dict(state='published',sha256=cert.fingerprint(hashes.SHA256()).hex().upper(),
                not_before=cert.not_valid_before.replace(tzinfo=dt.timezone.utc).timestamp(),
                expires_at=cert.not_valid_after.replace(tzinfo=dt.timezone.utc).timestamp())

def blank(config,collection='not-collected'):
    return dict(format=1,generated_at=time.time(),collection=collection,
        scope='Server-local observations only. Client DNS, routing and certificate trust are not verified.',
        installed=dict(version='Unknown',commit=None,deployed_at=None),
        deployment=dict(dns_mode=config['dns_mode'],web_mode=config['web_mode'],role='authority' if config['public_portal'] else ('remote-gateway' if config['remote_gateway'] else 'local')),
        checks=[dict(name=name,state='unknown',checked_at=None) for name in CHECKS],
        certificates=[dict(name=name,state='unknown',sha256=None,not_before=None,expires_at=None) for name in CERTS],
        diagnostics=dict(client='not-collected',dns=dict(state='unknown',checked_at=None)),
        gateway_failures=dict(state='unknown',since=None,counts={name:None for name in COUNTERS if name.startswith('failure_')}))

def encode(report):
    result=json.dumps(report,indent=2,sort_keys=True,allow_nan=False)
    if len(result.encode())>MAX_REPORT:raise ValueError('Report size exceeded.')
    return result

class SupportReport:
    def __init__(self,config,health,ca_path,root='/',deadline=3):
        self.config=config;self.health=health;self.ca_path=ca_path;self.root=root;self.deadline=deadline
        self.lock=threading.Lock();self.future=None;self.started=0

    def collect(self):
        report=blank(self.config,'complete')
        try:
            identity=installed(self.root)
            version=identity.get('version')
            report['installed']=dict(version=version if isinstance(version,str) and re.fullmatch(r'[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}',version) else 'Unknown',
                commit=identity.get('commit') if isinstance(identity.get('commit'),str) and re.fullmatch('[a-f0-9]{40}',identity['commit']) else None,
                deployed_at=stamp(identity.get('deployed_at')))
        except Exception:pass
        try:
            health=self.health.snapshot();when=stamp(health.get('checked_at'))
            fresh=when is not None and 0<=time.time()-when<=30 and not health.get('stale',True)
            rows=health.get('checks')
            if not isinstance(rows,list) or len(rows)>40:raise ValueError()
            indexed={r['name']:r for r in rows if isinstance(r,dict) and isinstance(r.get('name'),str) and r['name'] in CHECKS+CERTS}
            for row in report['checks']:
                observed=indexed.get(row['name'],{})
                row.update(state=state(observed.get('state')) if fresh else 'unknown',checked_at=when)
            for row in report['certificates']:
                observed=indexed.get(row['name'],{}) if not (self.config['public_portal'] and row['name']=='Device root CA') else {}
                row.update(state=state(observed.get('state')) if fresh else 'unknown',expires_at=stamp(observed.get('expires_at'),future=True),
                           sha256=fingerprint(observed.get('sha256')))
        except Exception:pass
        if not self.config['public_portal']:
            try:report['certificates'][0].update(certificate(self.ca_path))
            except Exception:pass
        try:
            dns=read_health(self.config);snapshot=dns.get('snapshot') or {}
            report['diagnostics']['dns']=dict(state='not-applicable' if self.config['dns_mode']!='builtin' else ('warning' if dns.get('state')=='degraded' else state(dns.get('state'))),checked_at=stamp(snapshot.get('updated')))
        except Exception:pass
        try:
            metrics=self.health.performance();counts=metrics.get('counters',{})
            if not isinstance(counts,dict):raise ValueError()
            allowed=report['gateway_failures']['counts']
            for name in allowed:
                value=counts.get(name)
                allowed[name]=value if type(value) is int and 0<=value<=2**63-1 else None
            report['gateway_failures'].update(state='collected' if any(value is not None for value in allowed.values()) else 'unknown',since=stamp(metrics.get('started')))
        except Exception:pass
        encode(report)
        return report

    def capture(self):
        # At most one collector per worker, no task queue, no arbitrary commands.
        with self.lock:
            if self.future is None or (self.future.done() and time.monotonic()-self.started>=10):
                future=self.future=Future();self.started=time.monotonic()
                def run():
                    try:future.set_result(self.collect())
                    except Exception:future.set_result(blank(self.config,'unavailable'))
                threading.Thread(target=run,daemon=True,name='support-snapshot').start()
            future=self.future
        try:return future.result(timeout=self.deadline)
        except TimeoutError:return blank(self.config,'deadline-exceeded')
