#!/usr/bin/env python3
"""Local privileged recovery: disable API and revoke integration credentials."""
import argparse
import json
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from access_gate.core import Store

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',default='/etc/access-gate/config.json')
    parser.add_argument('--all',action='store_true',required=True,help='Disable API and revoke all integration credentials.')
    args=parser.parse_args()
    config=json.loads(Path(args.config).read_text())
    store=Store(config['database'],config['pepper']);store.initialize()
    with store.connect() as db:
        db.execute('BEGIN IMMEDIATE')
        db.execute('UPDATE api_policy SET enabled=0')
        db.execute('UPDATE api_credentials SET revoked=1')
        store._event(db,'integration.revoked',actor='Local recovery',details=dict(reason='all'))
        db.commit()
    print('API disabled. All integration credentials revoked.')

if __name__=='__main__':main()
