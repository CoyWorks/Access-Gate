"""Scoped, reversible Linux interception and additive FortiGate plan generation."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import subprocess
from .policy import atomic_write

STATE=Path('/etc/access-gate/network.json')
POOL=ipaddress.ip_network('10.40.135.0/24')


def scope(value):
    network=ipaddress.ip_network(value,strict=True)
    if network.version!=4 or not network.subnet_of(POOL): raise ValueError('Use a subnet within 10.40.135.0/24.')
    return str(network)


def nft_rules(client_scope):
    client_scope=scope(client_scope)
    return '''table inet access_gate {
    chain guard {
        type filter hook prerouting priority -150; policy accept;
        iifname "eth0" ip saddr SCOPE tcp dport { 3129, 3130 } counter drop
        iifname "eth0" ip saddr SCOPE udp dport 443 counter drop
    }
    chain intercept {
        type nat hook prerouting priority dstnat; policy accept;
        iifname "eth0" ip saddr SCOPE ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } return
        iifname "eth0" ip saddr SCOPE tcp dport 80 counter redirect to :3129
        iifname "eth0" ip saddr SCOPE tcp dport 443 counter redirect to :3130
    }
    chain no_forward {
        type filter hook forward priority filter; policy accept;
        iifname "eth0" ip saddr SCOPE counter drop
    }
}
'''.replace('SCOPE',client_scope)


def apply(client_scope,run=subprocess.run,state_path=STATE):
    client_scope=scope(client_scope)
    exists=run(['/usr/sbin/nft','list','table','inet','access_gate'],capture_output=True).returncode==0
    if exists and not state_path.exists(): raise ValueError('An unowned access_gate nftables table already exists. Inspect it before activation.')
    text=('delete table inet access_gate\n' if exists else '')+nft_rules(client_scope)
    run(['/usr/sbin/nft','--check','--file','-'],input=text,text=True,check=True,capture_output=True,timeout=5)
    run(['/usr/sbin/nft','--file','-'],input=text,text=True,check=True,capture_output=True,timeout=5)
    atomic_write(state_path,json.dumps({'scope':client_scope},indent=2)+'\n',0o600)


def disable(run=subprocess.run,state_path=STATE):
    if not state_path.exists(): return
    exists=run(['/usr/sbin/nft','list','table','inet','access_gate'],capture_output=True).returncode==0
    if exists: run(['/usr/sbin/nft','delete','table','inet','access_gate'],check=True,capture_output=True,timeout=5)
    state_path.unlink()


def fortigate_plan(client_scope,before_policy,base_id=9000):
    client_scope=scope(client_scope)
    if not 1<=before_policy<=4294967294 or not 100<=base_id<=4294967270:
        raise ValueError('Provide valid, unused policy IDs and the existing VPN policy to precede.')
    if base_id<=before_policy<base_id+20: raise ValueError('The anchor must not be one of the new policy IDs.')
    # These IDs/names must be checked for conflicts on the live firewall before pasting.
    lines=['# Verify every AG-* name and ID below is unused. Do not overwrite an existing object.',
           '# Applies to NATIVE-VPN only. Existing IKE settings, routes and OCI tunnels are untouched.',
           'config firewall address','    edit "AG-VPN"',f'        set subnet {ipaddress.ip_network(client_scope).network_address} {ipaddress.ip_network(client_scope).netmask}',
           '    next','    edit "AG-Proxy"','        set subnet 10.40.22.5 255.255.255.255','    next',
           '    edit "AG-DNS"','        set subnet 10.40.22.10 255.255.255.255','    next',
           '    edit "AG-Private10"','        set subnet 10.0.0.0 255.0.0.0','    next',
           '    edit "AG-Private172"','        set subnet 172.16.0.0 255.240.0.0','    next',
           '    edit "AG-Private192"','        set subnet 192.168.0.0 255.255.0.0','    next','end',
           'config firewall addrgrp','    edit "AG-Private"','        set member "AG-Private10" "AG-Private172" "AG-Private192"','    next','end','config firewall service custom','    edit "AG-AltDNS-QUIC"','        set tcp-portrange 853','        set udp-portrange 443 853','    next','end']
    # Policy-route exceptions preserve ordinary LAN/OCI access and keep DNS/portal out of interception.
    lines+=['config router policy']
    for offset,destination in enumerate(('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')):
        net=ipaddress.ip_network(destination)
        lines += [f'    edit {base_id+offset}','        set input-device "NATIVE-VPN"',f'        set src "{client_scope}"',f'        set dst "{net}"','        set action deny','        set comments "Access Gate: preserve private routing"','    next']
    for offset,port in ((3,80),(4,443)):
        lines += [f'    edit {base_id+offset}','        set input-device "NATIVE-VPN"',f'        set src "{client_scope}"','        set dst "0.0.0.0/0"','        set protocol 6',f'        set start-port {port}',f'        set end-port {port}','        set gateway 10.40.22.5','        set output-device "vlan22"','        set comments "Access Gate: original destination preserved"','    next']
    lines+=['end','# Place the three private-route exceptions before the two web routes and before any earlier matching PBR.',
            'config firewall policy']
    definitions=[
        ('AG-DNS','NATIVE-VPN','vlan22','AG-VPN','AG-DNS','DNS','accept',False),
        ('AG-Portal','NATIVE-VPN','vlan22','AG-VPN','AG-Proxy','HTTP" "HTTPS','accept',False),
        ('AG-Web','NATIVE-VPN','vlan22','AG-VPN','AG-Private','HTTP" "HTTPS','accept',False),
        ('AG-Block-DNS-QUIC','NATIVE-VPN','any','AG-VPN','all','DNS" "AG-AltDNS-QUIC','deny',False),
        ('AG-Block-WebBypass','NATIVE-VPN','any','AG-VPN','AG-Private','HTTP" "HTTPS','deny',False),
        ('AG-Proxy-Out','vlan22','pppoe1','AG-Proxy','all','HTTP" "HTTPS','accept',True),
    ]
    for offset,(name,source,destination,srcaddr,dstaddr,service,action,nat) in enumerate(definitions,10):
        lines += [f'    edit {base_id+offset}',f'        set name "{name}"',f'        set srcintf "{source}"',f'        set dstintf "{destination}"',f'        set srcaddr "{srcaddr}"',f'        set dstaddr "{dstaddr}"',f'        set action {action}','        set schedule "always"',f'        set service "{service}"','        set logtraffic all']
        if name in ('AG-Web','AG-Block-WebBypass'): lines+=['        set dstaddr-negate enable']
        if action=='accept': lines+=['        set nat '+('enable' if nat else 'disable'),'        set auto-asic-offload disable']
        lines+=['    next']
    lines += ['end','# Position narrow allows, then the bypass deny, above the existing VPN Internet allow.']
    lines += ['config firewall policy']
    for offset in (10,11,12,13,14): lines += [f'    move {base_id+offset} before {before_policy}']
    lines += ['end','# Direct public web, alternate DNS and QUIC bypass are denied; existing private-web policy behavior is preserved.',
              '# The proxy VM still needs its existing DNS/network-management policy.',
              '# IPv6 outside this IPv4-only tunnel must be blocked by device VPN lockdown; test before rollout.']
    rollback=['# Remove only the objects created by this plan. Confirm IDs/names still belong to Access Gate.', 'config router policy']
    rollback += [f'    delete {base_id+i}' for i in range(5)]+['end','config firewall policy']
    rollback += [f'    delete {base_id+i}' for i in range(10,16)]+['end','config firewall addrgrp','    delete "AG-Private"','end','config firewall address','    delete "AG-VPN"','    delete "AG-Proxy"','    delete "AG-DNS"','    delete "AG-Private10"','    delete "AG-Private172"','    delete "AG-Private192"','end','config firewall service custom','    delete "AG-AltDNS-QUIC"','end']
    return '\n'.join(lines)+'\n','\n'.join(rollback)+'\n'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='action',required=True)
    plan=sub.add_parser('plan'); plan.add_argument('--scope',default='10.40.135.0/24'); plan.add_argument('--before-policy',type=int,required=True); plan.add_argument('--base-id',type=int,default=9000); plan.add_argument('--output',default='/root/access-gate-network')
    enable=sub.add_parser('enable'); enable.add_argument('--scope',default='10.40.135.0/24')
    sub.add_parser('restore'); sub.add_parser('disable'); sub.add_parser('status')
    args=parser.parse_args()
    if os.geteuid()!=0: raise SystemExit('Run as root on the Access Gate server.')
    if args.action=='plan':
        forward,rollback=fortigate_plan(args.scope,args.before_policy,args.base_id)
        output=Path(args.output); output.mkdir(parents=True,exist_ok=True,mode=0o700)
        atomic_write(output/'fortigate-enable.conf',forward,0o600)
        atomic_write(output/'fortigate-rollback.conf',rollback,0o600)
        atomic_write(output/'linux-intercept.nft',nft_rules(args.scope),0o600)
        print('Plan written to '+str(output)+'. Check unused IDs, existing policy order and identity readiness before applying.')
    elif args.action=='enable':
        from .core import Store
        from .identity import lookup
        config=json.loads(Path('/etc/access-gate/config.json').read_text())
        store=Store(config['database'],config['pepper'])
        state=store.policy_status()
        if not config.get('require_identity') or not config.get('enforcement') or not state['healthy'] or not 0<=__import__('time').monotonic()-state['heartbeat']<=3 or state['desired']!=state['applied'] or state['applying'] or state['error']:
            raise SystemExit('Identity enforcement, a healthy worker and successfully applied rules are required first.')
        observed=[d for d in store.devices() if d['enabled'] and d['last_ip'] and ipaddress.ip_address(d['last_ip']) in ipaddress.ip_network(scope(args.scope))]
        if not observed: raise SystemExit('Register a VPN username, connect that device and verify its live address first.')
        lookup(observed[0]['last_ip'])
        apply(args.scope)
        subprocess.run(['/usr/bin/systemctl','enable','access-gate-network.service'],check=True)
        print('Scoped Linux interception enabled. Apply the reviewed FortiGate plan next.')
    elif args.action=='restore':
        if STATE.exists(): apply(json.loads(STATE.read_text())['scope'])
    elif args.action=='disable':
        disable(); subprocess.run(['/usr/bin/systemctl','disable','access-gate-network.service'],check=True)
        print('Access Gate Linux interception removed. Apply the matching FortiGate rollback too.')
    else:
        print(STATE.read_text() if STATE.exists() else 'Linux interception is disabled.')
        subprocess.run(['/usr/sbin/nft','list','table','inet','access_gate'],check=False)


if __name__=='__main__': main()
