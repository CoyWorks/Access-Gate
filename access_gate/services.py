"""Service ownership and listener checks for dedicated/shared deployments."""
import ipaddress
import json
from pathlib import Path
import subprocess


def endpoint(value):
    address,port=value.rsplit(':',1)
    return address.strip('[]').split('%',1)[0],int(port)


def conflicts(c,listener):
    address,port=endpoint(listener)
    required={80,443,8088,8089}|({53} if c['dns_mode']=='builtin' else set())
    if port not in required:return False
    if c.get('web_mode','dedicated')=='dedicated':return True
    # A wildcard socket may also occupy IPv4 when shown as [::]. Reject both.
    if address in ('*','0.0.0.0','::',''):return True
    if port in (8088,8089):return address in ('127.0.0.1','::1',c['listen_ipv4'])
    return address==c['listen_ipv4']


def check_shared_nginx(root=Path('/'),runner=subprocess.run):
    root=Path(root)
    if not (root/'etc/nginx/sites-enabled').is_dir():raise ValueError('Shared nginx needs /etc/nginx/sites-enabled support.')
    if root!=Path('/'):return
    result=runner(['/usr/sbin/nginx','-T'],capture_output=True,text=True,timeout=10,check=False)
    if result.returncode or 'include /etc/nginx/sites-enabled/' not in result.stdout:
        raise ValueError('The existing nginx configuration must validate and include /etc/nginx/sites-enabled/*. Do not overwrite its nginx.conf.')
    active=runner(['/usr/bin/systemctl','is-active','--quiet','nginx.service'],check=False,timeout=5)
    if active.returncode:raise ValueError('Start the existing nginx service before selecting shared-nginx mode.')


def refresh_nginx(c,runner=subprocess.run):
    runner(['/usr/sbin/nginx','-t'],check=True,timeout=10)
    action='reload' if c.get('web_mode','dedicated')=='shared-nginx' else 'restart'
    runner(['/usr/bin/systemctl',action,'nginx.service'],check=True,timeout=30)


def main():
    c=json.loads(Path('/etc/access-gate/config.json').read_text());refresh_nginx(c)


if __name__=='__main__':main()
