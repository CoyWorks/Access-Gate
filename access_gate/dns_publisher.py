"""Unprivileged restricted-domain snapshot publisher for the optional DNS service."""
import json
from pathlib import Path
import time
from .core import Store
from .deployment import normalize
from .dns_export import hostname
from .settings import atomic_write


def snapshot(config):
    c=normalize(config)
    store=Store(c['database'],c['pepper'])
    with store.connect() as db:
        rows=db.execute('SELECT domain,include_subdomains FROM dns_export_domains WHERE enabled=1 ORDER BY domain')
        domains=[dict(domain=hostname(r['domain']),include_subdomains=bool(r['include_subdomains'])) for r in rows]
    payload=json.dumps(dict(domains=domains),separators=(',',':'))+'\n'
    if len(payload.encode())>64*1024*1024:raise ValueError('DNS snapshot exceeds its limit.')
    return payload,len(domains)


def publish(config,directory):
    directory=Path(directory);payload,count=snapshot(config)
    destination=directory/'rules.json'
    if not destination.exists() or destination.read_text()!=payload:atomic_write(destination,payload,0o640)
    atomic_write(directory/'status.json',json.dumps(dict(state='healthy',updated=time.time(),domains=count))+'\n',0o640)


def main():
    while True:
        try:
            c=json.loads(Path('/etc/access-gate/config.json').read_text())
            publish(c,Path('/var/lib/access-gate/dns'))
        except Exception:
            atomic_write('/var/lib/access-gate/dns/status.json',json.dumps(dict(state='failed',updated=time.time(),message='DNS rules synchronization failed; last known-good mappings remain active.'))+'\n',0o640)
        time.sleep(2)


if __name__=='__main__':main()
