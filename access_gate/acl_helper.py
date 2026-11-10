#!/usr/bin/python3
"""Squid external ACL. Missing identity/socket evidence always denies access."""
import sys
import urllib.parse
import urllib.request
from pathlib import Path


def check(line,token,opener):
    values=[urllib.parse.unquote(v) for v in line.split()]
    if len(values)<4: return False
    params=dict(zip(('ip','client_port','local_ip','local_port'),values[:4]))
    req=urllib.request.Request('http://127.0.0.1:8088/internal/check?'+urllib.parse.urlencode(params),headers={'X-Gate-Key':token})
    with opener.open(req,timeout=6) as response: return response.read(16).strip()==b'OK'


def main():
    token=Path('/etc/access-gate/acl-token').read_text().strip()
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for line in sys.stdin:
        try: allowed=check(line,token,opener)
        except Exception: allowed=False
        print('OK' if allowed else 'ERR',flush=True)


if __name__=='__main__': main()
