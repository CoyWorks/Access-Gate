#!/usr/bin/python3
"""Squid external ACL. Errors always deny access."""
import sys
import urllib.parse
import urllib.request
from pathlib import Path

token = Path('/etc/access-gate/acl-token').read_text().strip()
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
for line in sys.stdin:
    try:
        ip = urllib.parse.unquote(line.split()[0])
        req = urllib.request.Request('http://127.0.0.1:8088/internal/check?'+urllib.parse.urlencode({'ip':ip}),
                                     headers={'X-Gate-Key':token})
        with opener.open(req, timeout=2) as response:
            result = response.read(16).strip()
        print('OK' if result == b'OK' else 'ERR', flush=True)
    except Exception:
        print('ERR', flush=True)
