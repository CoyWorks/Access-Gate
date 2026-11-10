#!/usr/bin/python3
"""Root-only local configuration and identity checks; never writes to FortiGate."""
import argparse
import ipaddress
import json
import os
import re
import subprocess
from pathlib import Path
from access_gate.core import Store
from access_gate.identity import FortiGate
from access_gate.policy import atomic_write,render_acl


def render(config):
    store=Store(config['database'],config['pepper']); store.initialize(); store.import_domains(config['domains'])
    rules=store.applied_rules() if store.policy_status()['applied']>=0 else store.domain_rules()
    atomic_write('/etc/access-gate/restricted.acl',render_acl(rules))
    atomic_write('/etc/access-gate/clients.acl','\n'.join(config['pilot_clients'])+'\n')


def main():
    if os.geteuid()!=0: raise SystemExit('Run this command as root.')
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pilot-ip',help='Explicit IPv4 pilot address; replaces previous VPN pilot addresses')
    parser.add_argument('--check',action='store_true')
    parser.add_argument('--reader-setup',action='store_true',help='Create local reader key/config and print the public key')
    parser.add_argument('--fortigate-host',default='10.40.22.1')
    parser.add_argument('--fortigate-user',default='accessgate-reader')
    parser.add_argument('--identity-check',action='store_true',help='Query live read-only IKE evidence; makes no FortiGate changes')
    parser.add_argument('--enable-vpn-enforcement',action='store_true',help='Use verified identities across 10.40.135.0/24 after reader setup')
    args=parser.parse_args()
    path=Path('/etc/access-gate/config.json'); config=json.loads(path.read_text())
    if args.reader_setup:
        ipaddress.ip_address(args.fortigate_host)
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}',args.fortigate_user): raise SystemExit('Invalid reader username.')
        directory=Path('/etc/access-gate/ssh'); directory.mkdir(mode=0o700,exist_ok=True); directory.chmod(0o700)
        key=directory/'id_ed25519'
        if not key.exists(): subprocess.run(['/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-C','Access Gate read-only IKE identity','-f',str(key)],check=True)
        hostfile=directory/'known_hosts'
        if not hostfile.exists(): atomic_write(hostfile,'',0o600)
        atomic_write('/etc/access-gate/fortigate.json',json.dumps(dict(host=args.fortigate_host,username=args.fortigate_user,tunnel='NATIVE-VPN',network='10.40.135.0/24'),indent=2)+'\n',0o600)
        print('Public reader key (install on a dedicated diagnostic reader account restricted to 10.40.22.5):')
        print(key.with_suffix('.pub').read_text().strip())
        print('Verify the FortiGate SSH host fingerprint through its trusted management connection, then add the verified key to '+str(hostfile)+'. Never disable host-key verification.')
        print('Follow docs/ACTIVATION.md; reader setup does not change the FortiGate or enable interception.')
        return
    if args.identity_check or args.enable_vpn_enforcement:
        reader=json.loads(Path('/etc/access-gate/fortigate.json').read_text())
        sessions=FortiGate(reader).snapshot()
        if not sessions: raise SystemExit('No unambiguous established NATIVE-VPN sessions with EAP user, assigned IPv4 and id/spi were found. Keep a test device connected and inspect diagnose vpn ike gateway list.')
        for item in sessions: print(item['username']+' -> '+item['ip']+' ('+item['tunnel']+')')
        if not args.enable_vpn_enforcement: return
        config['pilot_clients']=['127.0.0.1/32','10.40.22.5/32','10.40.135.0/24']
        config['require_identity']=True; config['enforcement']=True
    if args.pilot_ip:
        ip=ipaddress.ip_address(args.pilot_ip)
        if ip not in ipaddress.ip_network('10.40.135.0/24'): raise SystemExit('Use an address within 10.40.135.0/24.')
        config['pilot_clients']=['127.0.0.1/32','10.40.22.5/32',str(ip)+'/32']
    changed=bool(args.pilot_ip or args.enable_vpn_enforcement)
    if changed: atomic_write(path,json.dumps(config,indent=2)+'\n',0o640)
    render(config)
    subprocess.run(['/usr/sbin/squid','-k','parse'],check=True)
    if changed and not args.check:
        subprocess.run(['/usr/bin/systemctl','restart','access-gate.service','access-gate-keeper.service'],check=True)
        subprocess.run(['/usr/bin/systemctl','reload','squid.service'],check=True)
    print('Allowed proxy addresses: '+', '.join(config['pilot_clients']))
    print('Manage restricted domains in the portal. No FortiGate or Pi-hole setting was changed.')


if __name__=='__main__': main()
