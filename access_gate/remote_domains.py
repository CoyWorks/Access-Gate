"""Authenticated remote domain synchronization into the private node's local DNS table."""
import argparse
import http.client
import json
import os
from pathlib import Path
import ssl
import subprocess
import time
from urllib.parse import urlsplit

LIMIT=64*1024*1024
UNIT='''[Unit]
Description=Access Gate remote domain synchronization
Requires=access-gate.service
After=network-online.target access-gate.service
PartOf=access-gate.service
[Service]
User=accessgate-gateway
Group=accessgate-gateway
WorkingDirectory=/opt/access-gate
ExecStart=/usr/bin/python3 -m access_gate.remote_domains
Restart=on-failure
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
[Install]
WantedBy=multi-user.target
'''


def synchronize(c):
    context=ssl.create_default_context(cafile=c.get('api_ca_file'));context.load_cert_chain(c['api_client_cert'],c['api_client_key'])
    target=urlsplit(c['api_url']);connection=http.client.HTTPSConnection(target.hostname,target.port or 443,context=context,timeout=10)
    try:
        connection.request('GET','/gateway/v1/rules',headers={'X-Gateway-Key':c['api_key'],'Host':target.hostname})
        response=connection.getresponse();data=response.read(LIMIT+1)
        if response.status!=200 or len(data)>LIMIT:raise ValueError('Remote rules unavailable or oversized.')
        payload=json.loads(data)
        if not isinstance(payload,dict) or not isinstance(payload.get('domains'),list):raise ValueError('Invalid domain snapshot.')
    finally:connection.close()
    local=http.client.HTTPConnection('127.0.0.1',8088,timeout=20)
    try:
        local.request('POST','/internal/remote-domains',body=data,headers={'X-Gate-Key':c['local_api_key'],'Content-Type':'application/json'})
        result=local.getresponse();result.read(4096)
        if result.status!=200:raise ValueError('Local DNS mirror rejected the remote snapshot.')
    finally:local.close()


def install(start=False):
    if os.geteuid()!=0:raise ValueError('Run service provisioning as root.')
    c=json.loads(Path('/etc/access-gate/config.json').read_text())
    if not c.get('remote_gateway'):
        if Path('/etc/systemd/system/access-gate-remote-domains.service').exists():subprocess.run(['systemctl','disable','--now','access-gate-remote-domains.service'],check=True)
        return
    Path('/etc/systemd/system/access-gate-remote-domains.service').write_text(UNIT)
    subprocess.run(['systemctl','daemon-reload'],check=True)
    subprocess.run(['systemctl','enable','access-gate-remote-domains.service'],check=True)
    if start:subprocess.run(['systemctl','restart','access-gate-remote-domains.service'],check=True)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--install',action='store_true');parser.add_argument('--start',action='store_true');parser.add_argument('--once',action='store_true');args=parser.parse_args()
    if args.install:install(args.start);return
    while True:
        c=json.loads(Path('/etc/access-gate/gateway/gateway.json').read_text())
        if not c.get('remote_gateway'):
            if args.once:raise ValueError('This node is not using remote authorization.')
            return
        try:synchronize(c)
        except Exception:
            if args.once:raise
            print('Remote domain synchronization failed; retaining the last validated local DNS rules.',flush=True)
        if args.once:return
        time.sleep(30)


if __name__=='__main__':main()
