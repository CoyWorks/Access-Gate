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
    from .deployment import normalize
    config=normalize(config)
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
