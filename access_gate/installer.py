"""Interactive and unattended installation planning, before package installation."""
import argparse
import getpass
import ipaddress
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
from .deployment import normalize,FIELDS


def local_addresses():
    result=subprocess.run(['ip','-j','-4','addr','show'],check=True,capture_output=True,text=True)
    return sorted({a['local'] for i in json.loads(result.stdout) for a in i.get('addr_info',[]) if a.get('scope')=='global'})


def profile(config):
    c=normalize(config,legacy=False)
    mode=config.get('dns_mode','external-pihole')
    if mode not in ('external-pihole','external'): raise ValueError('Built-in DNS is not available yet; choose external-pihole or external.')
    c['dns_mode']=mode
    return c


def password_file(path):
    p=Path(path)
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd) as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077 or info.st_size>1024:
            raise ValueError('Password input must be a private file owned by the installer user (mode 0600).')
        value=stream.read().rstrip('\n')
    if not 8<=len(value)<=256: raise ValueError('Administrator password must contain 8 to 256 characters.')
    return value


def preflight(c,addresses=None, listeners=None):
    if c['listen_ipv4'] not in (local_addresses() if addresses is None else addresses): raise ValueError('The selected IPv4 address is not assigned to this server.')
    if listeners is None:
        result=subprocess.run(['ss','-H','-lnt'],check=True,capture_output=True,text=True)
        listeners=[row.split()[3] for row in result.stdout.splitlines() if row.split()]
    ports={80,443,8088,8089}
    for endpoint in listeners:
        if int(endpoint.rsplit(':',1)[-1]) in ports: raise ValueError('A required TCP port is occupied ('+endpoint+'). Use a dedicated address/host; existing services were not changed.')


def ask(label,default=None):
    value=input(label+(' ['+default+']' if default else '')+': ').strip()
    return value or default or ''


def wizard():
    print('Access Gate installation\n1. Existing Pi-hole\n2. External DNS configured separately\n3. Custom (portal and gateway with external DNS)\nBuilt-in DNS will be offered when that component is available.')
    choice=ask('Installation type','1')
    if choice not in ('1','2','3'): raise ValueError('Choose 1, 2 or 3.')
    if choice=='3':
        selection=ask('DNS integration: pihole or external','external')
        if selection not in ('pihole','external'): raise ValueError('Choose pihole or external.')
        choice='1' if selection=='pihole' else '2'
    addresses=local_addresses()
    print('Detected IPv4 addresses: '+', '.join(addresses))
    address=ask('Server IPv4',addresses[0] if len(addresses)==1 else None)
    portal=ask('Portal hostname or IPv4',address)
    networks=ask('Client networks (comma-separated CIDRs)')
    admin=ask('Management networks (comma-separated CIDRs)',networks)
    c=profile(dict(deployment_version=1,server_ipv4=address,listen_ipv4=address,dns_target_ipv4=address,portal_url='https://'+portal,
                   portal_aliases=[],client_networks=[n.strip() for n in networks.split(',')]+['127.0.0.1/32','::1/128'],admin_networks=[n.strip() for n in admin.split(',')],dns_mode='external-pihole' if choice=='1' else 'external'))
    preflight(c,addresses=addresses)
    print(json.dumps({k:c[k] for k in ('deployment_version',)+FIELDS+('dns_mode',)},indent=2))
    print('Host addressing and external DNS/firewall settings will not be changed.')
    if ask('Apply this installation? Type INSTALL')!='INSTALL': raise ValueError('Installation cancelled; no services were changed.')
    password=getpass.getpass('Admin password (empty = generate): ')
    if password:
        if not 8<=len(password)<=256 or password!=getpass.getpass('Confirm admin password: '): raise ValueError('Passwords must match and contain 8 to 256 characters.')
    return c,password


def main():
    parser=argparse.ArgumentParser();parser.add_argument('destination');parser.add_argument('--profile');args=parser.parse_args()
    if os.geteuid()!=0: raise SystemExit('Run the installation planner as root.')
    if args.profile:
        raw=json.loads(Path(args.profile).read_text());c=profile(raw);preflight(c)
        password=password_file(raw['admin_password_file']) if raw.get('admin_password_file') else ''
    else:
        if not sys.stdin.isatty(): raise SystemExit('An interactive terminal or ACCESS_GATE_INSTALL_CONFIG profile is required.')
        c,password=wizard()
    allowed={k:c[k] for k in ('deployment_version',)+FIELDS+('dns_mode',)}
    p=Path(args.destination);p.write_text(json.dumps(allowed,indent=2)+'\n');p.chmod(0o600)
    if password:
        secret=p.with_suffix(p.suffix+'.password');secret.write_text(password);secret.chmod(0o600)


if __name__=='__main__':
    try: main()
    except (ValueError,OSError,EOFError,KeyboardInterrupt) as exc: raise SystemExit('Installation planning stopped: '+str(exc))
