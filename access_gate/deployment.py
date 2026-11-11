"""Validated deployment identity; personal values exist only for legacy migration."""
import argparse
import ipaddress
import json
from pathlib import Path
import re
import shlex
from urllib.parse import urlsplit

LEGACY = dict(server_ipv4='10.40.22.5', listen_ipv4='10.40.22.5',
              dns_target_ipv4='10.40.22.5', portal_url='https://10.40.22.5',
              portal_aliases=['toegang.coyseinri.nl'],
              client_networks=['10.40.0.0/16','127.0.0.1/32','::1/128'])
FIELDS = ('server_ipv4','listen_ipv4','dns_target_ipv4','portal_url','portal_aliases','client_networks','admin_networks')


def host(value):
    if not isinstance(value,str) or not value or len(value)>253: raise ValueError('Invalid portal hostname.')
    try: return str(ipaddress.IPv4Address(value))
    except ValueError: pass
    if not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?',p) for p in value.split('.')) or value.replace('.','').isdigit():
        raise ValueError('Invalid portal hostname.')
    return value.lower()


def normalize(config, legacy=True):
    c=dict(config)
    # Missing version marks pre-portability installations, not new defaults.
    if 'deployment_version' not in c:
        if not legacy: raise ValueError('New installation profiles require deployment_version: 1.')
        for k,v in LEGACY.items(): c.setdefault(k,v)
    if c.get('deployment_version',1)!=1: raise ValueError('Unsupported deployment configuration version.')
    for name in ('server_ipv4','listen_ipv4','dns_target_ipv4'):
        try:
            address=ipaddress.IPv4Address(c[name])
            if address.is_unspecified or address.is_multicast or address.is_loopback or address.is_reserved or int(address)==0xffffffff: raise ValueError()
            c[name]=str(address)
        except (KeyError,ValueError,TypeError): raise ValueError(name+' must be a usable IPv4 address.')
    # Single-host topology is supported first. Separate fields reserve future topologies.
    if len({c[k] for k in ('server_ipv4','listen_ipv4','dns_target_ipv4')})!=1:
        raise ValueError('This release requires server, listener and DNS target to use the same local IPv4 address.')
    try:
        u=urlsplit(c['portal_url'])
        if u.scheme!='https' or u.username or u.password or u.port not in (None,443) or u.path not in ('','/') or u.query or u.fragment: raise ValueError()
        identity=host(u.hostname)
    except (KeyError,ValueError,TypeError): raise ValueError('portal_url must be an HTTPS hostname or IPv4 origin on port 443.')
    c['portal_url']='https://'+identity
    aliases=c.get('portal_aliases',[])
    if not isinstance(aliases,list) or len(aliases)>20: raise ValueError('Use at most 20 portal aliases.')
    c['portal_aliases']=sorted(set(host(a) for a in aliases)-{identity})
    for name in ('client_networks','admin_networks'):
        values=c.get(name,c.get('client_networks'))
        if not isinstance(values,list) or not values or len(values)>64: raise ValueError(name+' requires 1 to 64 CIDRs.')
        c[name]=list(dict.fromkeys(str(ipaddress.ip_network(n)) for n in values))
    c['deployment_version']=1
    return c


def names(config):
    c=normalize(config)
    return sorted({urlsplit(c['portal_url']).hostname,c['server_ipv4'],*c['portal_aliases']})


def certificate_extensions(config):
    values=[]
    for value in names(config):
        try: ipaddress.IPv4Address(value); kind='IP'
        except ValueError: kind='DNS'
        values.append(kind+':'+value)
    return 'subjectAltName='+','.join(values)+'\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n'


def render_http(config):
    c=normalize(config)
    return Path(__file__).with_name('nginx-http.conf.in').read_text().replace('@@LISTEN@@',c['listen_ipv4']).replace('@@NAMES@@',' '.join(names(c)))


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('action',choices=('plan','shell','certificate'))
    parser.add_argument('path')
    parser.add_argument('--new',action='store_true')
    args=parser.parse_args()
    c=normalize(json.loads(Path(args.path).read_text()),legacy=not args.new)
    if args.action=='plan': print(json.dumps({k:c[k] for k in ('deployment_version',)+FIELDS},indent=2))
    elif args.action=='certificate': print(certificate_extensions(c),end='')
    else:
        for name,value in dict(GATE_SERVER_IP=c['server_ipv4'],GATE_PORTAL_URL=c['portal_url'],GATE_PORTAL_HOST=urlsplit(c['portal_url']).hostname,GATE_NAMES=' '.join(names(c))).items():
            print(name+'='+shlex.quote(value))


if __name__=='__main__': main()
