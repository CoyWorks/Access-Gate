#!/usr/bin/python3
"""Validate the standalone code portal; does not change DNS or firewall settings."""
import argparse
import json
import os
from pathlib import Path
from access_gate.core import Store
from access_gate.settings import validate,atomic_write


def main():
    if os.geteuid()!=0: raise SystemExit('Run this command as root.')
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true',help='Validate configuration and the database')
    args=parser.parse_args()
    path=Path('/etc/access-gate/config.json')
    config=validate(json.loads(path.read_text()))
    Store(config['database'],config['pepper']).initialize()
    atomic_write(path,json.dumps(config,indent=2)+'\n')
    atomic_write('/etc/access-gate/client-networks.nginx',''.join('allow '+n+';\n' for n in config['client_networks'])+'deny all;\n',0o644)
    print('Portal configuration and database are ready.')
    print('Client networks: '+', '.join(config['client_networks']))
    print('Select restricted domains and configure redirects in your external DNS/firewall/proxy solution.')


if __name__=='__main__': main()
