#!/usr/bin/python3
"""Root-only pilot configuration; never edits FortiGate or Pi-hole."""
import argparse
import ipaddress
import json
import os
import subprocess
from pathlib import Path
from access_gate.core import Store, domains


def render(config):
    entries = domains(config['domains'])
    if 'toegang.coyseinri.nl' in entries or 'coyseinri.nl' in entries:
        raise ValueError('Keep the portal domain outside the restricted domain list.')
    Path('/etc/access-gate/restricted.acl').write_text(''.join('.'+d+'\n' for d in entries) or '.access-gate.invalid\n')
    Path('/etc/access-gate/clients.acl').write_text('\n'.join(config['pilot_clients'])+'\n')
    for name in ('restricted.acl','clients.acl'):
        os.chmod('/etc/access-gate/'+name, 0o644)


def main():
    if os.geteuid() != 0:
        raise SystemExit('Run this command as root.')
    parser = argparse.ArgumentParser()
    parser.add_argument('--pilot-ip', help='Current test address; replaces previous VPN pilot addresses')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    path = Path('/etc/access-gate/config.json')
    config = json.loads(path.read_text())
    if args.pilot_ip:
        ip = ipaddress.ip_address(args.pilot_ip)
        if ip not in ipaddress.ip_network('10.40.135.0/24'):
            raise SystemExit('Use an address within 10.40.135.0/24 for this pilot.')
        config['pilot_clients'] = ['127.0.0.1/32','10.40.22.5/32',str(ip)+'/32']
        path.write_text(json.dumps(config, indent=2)+'\n')
        os.chmod(path, 0o640)
    render(config)
    subprocess.run(['/usr/sbin/squid','-k','parse'],check=True)
    if not args.check:
        # A config change clears grants (used vouchers are never restored).
        store = Store(config['database'], config['pepper'])
        with store.connect() as db:
            db.execute('UPDATE grants SET revoked=1')
        subprocess.run(['systemctl','restart','access-gate.service','access-gate-keeper.service'],check=True)
        subprocess.run(['systemctl','reload','squid.service'],check=True)
    print('Pilot IP addresses:', ', '.join(config['pilot_clients']))
    print('Restricted domains:', ', '.join(domains(config['domains'])) or '(not configured yet)')


if __name__ == '__main__':
    main()
