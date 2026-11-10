"""Read-only FortiGate session evidence. No cached positive identity decisions."""
import hashlib
import ipaddress
import json
import re
import socket
import subprocess


class IdentityUnavailable(ValueError): pass


def parse_gateways(output,tunnel='NATIVE-VPN',network='10.40.135.0/24'):
    if len(output)>1024*1024 or re.search(r'permission denied|command fail|parse error|unknown action',output,re.I):
        raise IdentityUnavailable('FortiGate session output was rejected.')
    allowed=ipaddress.ip_network(network)
    sessions=[]
    for block in re.split(r'(?m)^\s*(?=name:)',output):
        name=re.search(r'^\s*name:\s*(\S+)\s*$',block,re.M)
        if not name or not re.fullmatch(re.escape(tunnel)+r'_\d+',name[1]): continue
        user=re.search(r'^\s*eap-user:\s*(\S+)\s*$',block,re.M)
        address=re.search(r'^\s*assigned IPv4 address:\s*([0-9.]+)/',block,re.M)
        spi=re.search(r'\bid/spi:\s*\d+\s+([0-9a-fA-F]{16}/[0-9a-fA-F]{16})',block)
        established=all(re.search(kind+r' SA:.*\bestablished\s+[1-9]\d*/[1-9]\d*',block) for kind in ('IKE','IPsec'))
        if not user or not address or not spi or not established: continue
        try: ip=ipaddress.ip_address(address[1])
        except ValueError: raise IdentityUnavailable('Invalid assigned VPN address.')
        if ip not in allowed: continue
        fingerprint=hashlib.sha256((name[1]+'|'+user[1]+'|'+spi[1].lower()).encode()).hexdigest()
        sessions.append(dict(ip=str(ip),username=user[1],binding=fingerprint,tunnel=name[1]))
    # A shared username or overlapping assignment is ambiguous: deny both.
    return [s for s in sessions if sum(x['username']==s['username'] for x in sessions)==1 and sum(x['ip']==s['ip'] for x in sessions)==1]


class FortiGate:
    def __init__(self,config,run=subprocess.run):
        self.config,self.run=config,run
        ipaddress.ip_address(config['host'])
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}',config['username']): raise IdentityUnavailable('Invalid FortiGate reader username.')

    def snapshot(self):
        c=self.config
        command=['/usr/bin/ssh','-T','-F','/dev/null','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
                 '-o','ConnectTimeout=2','-o','ConnectionAttempts=1','-o','IdentitiesOnly=yes',
                 '-o','UserKnownHostsFile=/etc/access-gate/ssh/known_hosts',
                 '-i','/etc/access-gate/ssh/id_ed25519',c['username']+'@'+c['host'],
                 'diagnose vpn ike gateway list']
        try:
            result=self.run(command,capture_output=True,text=True,timeout=4,check=True)
            return parse_gateways(result.stdout,c.get('tunnel','NATIVE-VPN'),c.get('network','10.40.135.0/24'))
        except (subprocess.SubprocessError,OSError,ValueError) as exc:
            raise IdentityUnavailable('Live FortiGate identity is unavailable. Check reader access, host key and gateway output.') from exc


def lookup(ip,path='/run/access-gate/control.sock'):
    ip=str(ipaddress.ip_address(ip))
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
            client.settimeout(5)
            client.connect(path)
            client.sendall((json.dumps({'action':'identity','ip':ip})+'\n').encode())
            data=b''
            while b'\n' not in data and len(data)<=4096:
                part=client.recv(4096)
                if not part: break
                data+=part
            response=json.loads(data)
            if response.get('error') or not response.get('identity'): raise IdentityUnavailable('No unique, established VPN session was verified for this address.')
            return response['identity']
    except (OSError,ValueError,KeyError) as exc:
        raise IdentityUnavailable('VPN identity could not be verified. Restricted access remains locked.') from exc
