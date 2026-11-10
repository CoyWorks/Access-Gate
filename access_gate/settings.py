"""Small portal settings; no firewall, DNS or user-registration configuration."""
import ipaddress
import json
import os
from pathlib import Path
import re
import tempfile
from urllib.parse import urlsplit


def validate(config):
    for name in ('secret','pepper','admin_hash','acl_token','database'):
        if not isinstance(config.get(name),str) or not config[name]: raise ValueError('Missing portal setting: '+name)
    config=dict(config)
    config.setdefault('portal_url','https://10.40.22.5')
    config.setdefault('client_networks',['10.40.0.0/16','127.0.0.1/32','::1/128'])
    url=urlsplit(config['portal_url'])
    host=url.hostname or ''
    if url.scheme!='https' or url.username or url.password or url.port not in (None,443) or url.path not in ('','/') or url.query or url.fragment:
        raise ValueError('portal_url must be an HTTPS origin without a path, credentials or a query.')
    try: ipaddress.ip_address(host)
    except ValueError:
        if not host or len(host)>253 or not all(re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?',part) for part in host.split('.')): raise ValueError('Invalid portal hostname.')
    config['portal_url']=config['portal_url'].rstrip('/')
    if not isinstance(config['client_networks'],list) or not config['client_networks']: raise ValueError('At least one client network is required.')
    config['client_networks']=[str(ipaddress.ip_network(n)) for n in config['client_networks']]
    if 'admin_networks' in config:
        from .administration import management_networks
        if not isinstance(config['admin_networks'],list): raise ValueError('admin_networks must be a list of networks.')
        config['admin_networks']=management_networks('\n'.join(config['admin_networks']))
    for name in ('pilot_clients','require_identity','enforcement','control_socket','domains'):
        config.pop(name,None)
    return config


def atomic_write(path,text,mode=0o640):
    path=Path(path); previous=path.stat() if path.exists() else None
    fd,temp=tempfile.mkstemp(prefix='.'+path.name+'-',dir=path.parent)
    try:
        with os.fdopen(fd,'w') as stream:
            stream.write(text); stream.flush(); os.fsync(stream.fileno()); os.fchmod(stream.fileno(),mode)
            if previous: os.fchown(stream.fileno(),previous.st_uid,previous.st_gid)
        os.replace(temp,path)
    finally:
        if os.path.exists(temp): os.unlink(temp)
