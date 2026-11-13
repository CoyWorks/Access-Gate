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
import warnings
from .deployment import normalize,FIELDS


def local_addresses():
    result=subprocess.run(['ip','-j','-4','addr','show'],check=True,capture_output=True,text=True,timeout=5)
    return sorted({a['local'] for i in json.loads(result.stdout) for a in i.get('addr_info',[]) if a.get('scope')=='global'})


def profile(config):
    c=normalize(config,legacy=False)
    mode=config.get('dns_mode','external-pihole')
    if mode not in ('external-pihole','external','builtin'): raise ValueError('Choose builtin, external-pihole or external.')
    c['dns_mode']=mode
    return c


def password_file(path):
    p=Path(path)
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd) as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077 or info.st_size>1024:
            raise ValueError('Password input must be a private file owned by the installer user (mode 0600).')
        value=stream.read().rstrip('\n')
    if not 8<=len(value)<=256: raise ValueError('Administrator password must contain 8 to 256 characters.')
    return value


def service_conflicts(root=Path('/'),web_mode='dedicated'):
    root=Path(root)
    if web_mode=='shared-nginx':
        from .services import check_shared_nginx
        check_shared_nginx(root)
    if web_mode!='shared-nginx' and ((root/'etc/cloudpanel').exists() or (root/'home/clp').exists()):
        raise ValueError('CloudPanel host detected. Choose shared-nginx with a reserved gateway address or use a dedicated VM. See docs/DEPLOYMENTS.md.')
    enabled=root/'etc/nginx/sites-enabled'
    if web_mode!='shared-nginx' and enabled.exists() and any(enabled.iterdir()):
        raise ValueError('Existing enabled nginx sites detected. Choose shared-nginx with a reserved gateway address or use a dedicated VM; no sites were changed. See docs/DEPLOYMENTS.md.')
    for relative in ('etc/nginx/sites-enabled/access-gate.conf','etc/nginx/sites-available/access-gate','etc/systemd/system/access-gate.service','etc/systemd/system/access-gate-dns.service'):
        if (root/relative).exists() or (root/relative).is_symlink():raise ValueError('An Access Gate target file already exists; inspect the installation or use resume instead of overwriting it.')


def preflight(c,addresses=None, listeners=None):
    if not any(ipaddress.ip_address(c['listen_ipv4']) in ipaddress.ip_network(n) for n in c['client_networks']):raise ValueError('Include the server IPv4 (or its /32) in client networks for local HTTPS/DNS verification.')
    if c['listen_ipv4'] not in (local_addresses() if addresses is None else addresses): raise ValueError('The selected IPv4 address is not assigned to this server.')
    if listeners is None:
        result=subprocess.run(['ss','-H','-lntu'],check=True,capture_output=True,text=True,timeout=5)
        listeners=[row.split()[4] for row in result.stdout.splitlines() if row.split()]
    if c['dns_mode']=='builtin' and set(c['dns_upstreams'])&set(local_addresses() if addresses is None else addresses):raise ValueError('DNS upstream must not be another local address of this host.')
    ports={80,443,8088,8089}
    if c['dns_mode']=='builtin':
        ports.add(53)
        if listeners is None: raise ValueError('Unable to inspect DNS listeners.')
    from .services import conflicts
    for endpoint in listeners:
        if conflicts(c,endpoint): raise ValueError('A required TCP/UDP port is occupied ('+endpoint+'). Use a dedicated address/host; existing services were not changed.')


def ask(label,default=None):
    value=input(label+(' ['+default+']' if default else '')+': ').strip()
    return value or default or ''


PLAN_FIELDS=('deployment_version',)+FIELDS+('dns_mode','dns_upstreams','web_mode')


def public_plan(config):return {key:config[key] for key in PLAN_FIELDS if key in config}


def installation_state(root=Path('/')):
    root=Path(root)
    if (root/'etc/access-gate/config.json').exists():return 'existing'
    if (root/'var/lib/access-gate/data/gate.sqlite3').exists() or (root/'var/lib/access-gate/installation/complete').exists():return 'missing-config'
    if (root/'var/lib/access-gate/installation/profile.json').is_file():return 'interrupted'
    if any((root/'etc/access-gate'/name).exists() for name in ('ca/root.key','ca/root.crt','acl-token','portal.key')):return 'missing-config'
    return 'new'


def load_profile(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size>65536:raise ValueError('Use a regular deployment profile of at most 64 KiB.')
        data=stream.read(65537)
    if len(data)>65536:raise ValueError('Deployment profile is too large.')
    raw=json.loads(data)
    if not isinstance(raw,dict) or set(raw)-set(PLAN_FIELDS)-{'admin_password_file'}:raise ValueError('Use deployment settings only; runtime secrets do not belong in an installation profile.')
    return raw


def write_plan(path,config,new=False):
    # Never truncate an existing non-empty file or follow a link/device.
    path=Path(path)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK|(os.O_EXCL if new else 0),0o600)
    with os.fdopen(fd,'w') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_size:raise ValueError('Choose a new profile path or an empty private planner file; existing files are not overwritten.')
        os.fchmod(stream.fileno(),0o600)
        stream.write(json.dumps(public_plan(config),indent=2)+'\n');stream.flush();os.fsync(stream.fileno())


def networks(value):
    parts=value.replace(',',' ').split()
    if not parts or len(parts)>64 or len(value)>4096:raise ValueError('Enter 1 to 64 IPv4/IPv6 CIDRs.')
    return list(dict.fromkeys(str(ipaddress.ip_network(part,strict=False)) for part in parts))


def wizard(seed=None,plan_only=False):
    print('Access Gate installation planner. No packages or services change during planning.')
    print('At a field: BACK returns to the previous choice; CANCEL stops. Review supports EDIT number, EDIT aliases, SAVE path and RETRY.')
    print('1. Existing Pi-hole  2. External DNS  3. Custom DNS choice  4. Built-in DNS')
    draft={} if seed is None else public_plan(profile(seed))
    if seed is not None:draft['choice']={'external-pihole':'1','external':'2','builtin':'4'}[draft['dns_mode']]
    index=None if seed is not None else 1;editing=False
    labels={1:'DNS integration',2:'Web ownership',3:'Server IPv4',4:'Portal identity',5:'Client networks',6:'Management networks',7:'DNS upstreams',8:'Portal aliases'}
    def active():return [1,2,3,4,5,6]+([7] if draft.get('choice')=='4' else [])
    def candidate():
        address=draft['server_ipv4'];choice=draft['choice']
        return profile(dict(deployment_version=1,server_ipv4=address,listen_ipv4=address,dns_target_ipv4=address,portal_url=draft['portal_url'],portal_aliases=draft.get('portal_aliases',[]),
            client_networks=list(dict.fromkeys(draft['client_networks']+['127.0.0.1/32','::1/128'])),admin_networks=draft['admin_networks'],
            dns_mode={'1':'external-pihole','2':'external','4':'builtin'}[choice],dns_upstreams=draft.get('dns_upstreams',[]) if choice=='4' else [],web_mode=draft['web_mode']))
    while True:
        if index is None:
            missing=next((step for step,key in ((1,'choice'),(2,'web_mode'),(3,'server_ipv4'),(4,'portal_url'),(5,'client_networks'),(6,'admin_networks'),(7,'dns_upstreams')) if step in active() and not draft.get(key)),None)
            if missing:index=missing;editing=True;continue
            try:c=candidate()
            except ValueError as exc:
                print('Plan needs correction: '+str(exc));index=5;editing=True;continue
            print('Review: 1 DNS, 2 web, 3 address, 4 portal, 5 client CIDRs, 6 management CIDRs, 7 upstreams, aliases.')
            print(json.dumps(public_plan(c),indent=2));ready=False
            try:service_conflicts(web_mode=c['web_mode']);preflight(c);ready=True;print('Local preflight passed. External DNS, VPN/firewall and device trust still need setup.')
            except (ValueError,OSError,subprocess.SubprocessError) as exc:print('Preflight failed: '+str(exc)+'. Services are unchanged. Edit settings, correct the host and RETRY, SAVE settings, or CANCEL.')
            command=ask('FINISH to save the plan' if plan_only else 'INSTALL to apply this reviewed plan').strip()
            upper=command.upper()
            if upper in ('CANCEL','NO'):raise ValueError('Installation cancelled; no services were changed.')
            if upper in ('BACK','EDIT'):
                index=active()[-1] if upper=='BACK' else 1;editing=True;continue
            if upper.startswith('EDIT '):
                target=command.split(None,1)[1].lower()
                if target=='aliases':index=8
                elif target.isdigit() and int(target) in active():index=int(target)
                else:print('Choose an available field number or EDIT aliases.');continue
                editing=True;continue
            if upper.startswith('SAVE '):
                try:write_plan(command.split(None,1)[1],c,new=True);print('Deployment settings saved privately; no password or runtime secret was exported. Preflight is repeated when reused.')
                except (ValueError,OSError) as exc:print('Could not save profile: '+str(exc))
                continue
            if upper=='RETRY':continue
            if upper==('FINISH' if plan_only else 'INSTALL'):
                if not ready:print('Resolve preflight failures before continuing.');continue
                if plan_only:return c,''
                while True:
                    with warnings.catch_warnings():
                        warnings.simplefilter('error',getpass.GetPassWarning)
                        password=getpass.getpass('Admin password (empty = generate): ')
                    if not password:return c,''
                    if not 8<=len(password)<=256:print('Use 8 to 256 characters. Try again; the reviewed plan is retained.');continue
                    with warnings.catch_warnings():
                        warnings.simplefilter('error',getpass.GetPassWarning)
                        confirmation=getpass.getpass('Confirm admin password: ')
                    if password!=confirmation:print('Passwords do not match. Try again; the reviewed plan is retained.');continue
                    return c,password
            print('Choose INSTALL/FINISH, EDIT number, EDIT aliases, BACK, SAVE path, RETRY or CANCEL.');continue
        addresses=[]
        if index==1:prompt,default='Installation type',draft.get('choice','1')
        elif index==2:prompt,default='Web server: dedicated or shared-nginx',draft.get('web_mode','dedicated')
        elif index==3:
            try:addresses=local_addresses();print('Assigned IPv4 addresses: '+(', '.join(addresses) or 'none; assign one before continuing'))
            except (OSError,ValueError,subprocess.SubprocessError):print('Could not discover IPv4 addresses. Check iproute2 or CANCEL.');addresses=[]
            prompt,default='Server IPv4',draft.get('server_ipv4') or (addresses[0] if len(addresses)==1 else None)
        elif index==4:prompt,default='Portal hostname/IP or HTTPS origin',draft.get('portal_url',draft.get('server_ipv4'))
        elif index==5:prompt,default='Client networks (comma-separated CIDRs)',','.join(draft.get('client_networks',[])) or None
        elif index==6:prompt,default='Management networks (comma-separated CIDRs)',','.join(draft.get('admin_networks',draft.get('client_networks',[]))) or None
        elif index==7:prompt,default='Upstream DNS IPv4 addresses (comma-separated)',','.join(draft.get('dns_upstreams',[])) or None
        else:prompt,default='Portal aliases (comma-separated; NONE clears)',','.join(draft.get('portal_aliases',[])) or 'NONE'
        value=ask(str(index)+'. '+prompt,default)
        if value.upper()=='CANCEL':raise ValueError('Installation cancelled; no services were changed.')
        if value.upper()=='BACK':
            steps=active();index=steps[max(0,steps.index(index)-1)] if index in steps else None;editing=False;continue
        try:
            if index==1:
                if value not in ('1','2','3','4'):raise ValueError('Choose 1, 2, 3 or 4.')
                if value=='3':
                    selection=ask('DNS integration: pihole, external or builtin','external')
                    if selection.upper()=='CANCEL':raise KeyboardInterrupt()
                    if selection.upper()=='BACK':continue
                    if selection not in ('pihole','external','builtin'):raise ValueError('Choose pihole, external or builtin.')
                    value={'pihole':'1','external':'2','builtin':'4'}[selection]
                draft['choice']=value
            elif index==2:
                if value not in ('dedicated','shared-nginx'):raise ValueError('Choose dedicated or shared-nginx.')
                service_conflicts(web_mode=value);draft['web_mode']=value
            elif index==3:
                address=str(ipaddress.IPv4Address(value));ip=ipaddress.ip_address(address)
                if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_reserved or address not in addresses:raise ValueError('Choose a usable IPv4 address already assigned on this host.')
                if draft.get('portal_url')=='https://'+draft.get('server_ipv4',''):draft['portal_url']='https://'+address;print('Literal portal address follows the selected server address; review field 4.')
                draft['server_ipv4']=address
            elif index==4:
                from urllib.parse import urlsplit
                origin=value if '://' in value else 'https://'+value
                trial=profile(dict(deployment_version=1,server_ipv4=draft['server_ipv4'],listen_ipv4=draft['server_ipv4'],dns_target_ipv4=draft['server_ipv4'],portal_url=origin,portal_aliases=[],client_networks=[draft['server_ipv4']+'/32'],admin_networks=[draft['server_ipv4']+'/32']))
                try:literal=ipaddress.ip_address(urlsplit(trial['portal_url']).hostname)
                except ValueError:literal=None
                if literal and str(literal)!=draft['server_ipv4']:raise ValueError('A literal portal IPv4 must match the chosen server IPv4.')
                draft['portal_url']=trial['portal_url']
            elif index in (5,6):
                rows=networks(value)
                if index==5 and len(set(rows+['127.0.0.1/32','::1/128']))>64:raise ValueError('Allow room for the two local verification CIDRs (at most 64 total).')
                draft['client_networks' if index==5 else 'admin_networks']=rows
            elif index==7:
                rows=value.replace(',',' ').split()
                if not 1<=len(rows)<=3:raise ValueError('Use 1 to 3 upstream IPv4 addresses.')
                rows=list(dict.fromkeys(str(ipaddress.IPv4Address(n)) for n in rows))
                if any(ipaddress.ip_address(n).is_loopback or ipaddress.ip_address(n).is_unspecified or ipaddress.ip_address(n).is_multicast or ipaddress.ip_address(n).is_reserved or n==draft['server_ipv4'] for n in rows):raise ValueError('Use valid upstreams, not this resolver or loopback.')
                draft['dns_upstreams']=rows
            else:
                from .deployment import host
                rows=[] if value.upper()=='NONE' else value.replace(',',' ').split()
                if len(rows)>20:raise ValueError('Use at most 20 aliases.')
                draft['portal_aliases']=sorted({host(n) for n in rows})
        except (ValueError,OSError,subprocess.SubprocessError) as exc:print(labels[index]+': '+str(exc)+' Try again, BACK or CANCEL.');continue
        if editing:index=None;editing=False
        else:
            steps=active();position=steps.index(index);index=steps[position+1] if position+1<len(steps) else None


def require_root():
    if os.geteuid()!=0:raise SystemExit('Run the installation planner as root.')


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('destination',nargs='?')
    group=parser.add_mutually_exclusive_group();group.add_argument('--profile');group.add_argument('--edit-profile')
    parser.add_argument('--plan-only',action='store_true',help='Save reviewed settings without collecting a password or starting installation')
    parser.add_argument('--state',action='store_true',help='Print new/existing/interrupted/missing-config for the install/resume launcher')
    args=parser.parse_args(argv)
    require_root()
    if args.state:print(installation_state());return
    if not args.destination:parser.error('Provide a new/empty destination for the plan.')
    if installation_state() in ('existing','missing-config'):raise ValueError('Existing or incomplete installed state detected. Use update/resume or restore its configuration; this is a new-installation planner.')
    if args.profile:
        raw=load_profile(args.profile);c=profile(raw);service_conflicts(web_mode=c['web_mode']);preflight(c)
        password='' if args.plan_only else (password_file(raw['admin_password_file']) if raw.get('admin_password_file') else '')
    else:
        if not sys.stdin.isatty():raise SystemExit('Use an interactive terminal or a deployment --profile.')
        c,password=wizard(public_plan(profile(load_profile(args.edit_profile))) if args.edit_profile else None,plan_only=args.plan_only)
    write_plan(args.destination,c)
    if password:
        path=Path(str(args.destination)+'.password');fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as stream:stream.write(password);stream.flush();os.fsync(stream.fileno())
    print('Plan saved. Planning is complete; installation has not started.' if args.plan_only else 'Planning complete. The launcher can now checkpoint settings and install components.')


if __name__=='__main__':
    try:main()
    except (ValueError,OSError,subprocess.SubprocessError,EOFError,KeyboardInterrupt,getpass.GetPassWarning) as exc:raise SystemExit('Installation planning stopped: '+str(exc))
