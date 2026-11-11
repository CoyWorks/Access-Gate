"""Root-only, serialized deployment changes with configuration rollback."""
import argparse
import datetime as dt
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from urllib.parse import urlsplit
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID,NameOID
from .deployment import normalize,FIELDS,names,render_http
from .settings import validate,atomic_write
from .installer import local_addresses,ask

FILES=('etc/access-gate/config.json','etc/access-gate/portal.crt','etc/access-gate/portal.key',
       'etc/access-gate/gateway/gateway.json','etc/access-gate/gateway/issuer.crt','etc/access-gate/gateway/issuer.key',
       'etc/access-gate/client-networks.nginx','etc/nginx/sites-available/access-gate')
SERVICES=('nginx.service','access-gate.service','access-gate-gateway.service','access-gate-scheduler.service','access-gate-push.service')


def command(args):
    subprocess.run(args,check=True,timeout=60)


def updated(current,requested):
    unknown=set(requested)-set(FIELDS)-{'deployment_version'}
    if unknown: raise ValueError('Reconfigure accepts deployment fields only: '+', '.join(sorted(unknown)))
    return validate(dict(current,**requested))


def portal_certificate(base,c):
    import ipaddress
    ca=x509.load_pem_x509_certificate((base/'ca/root.crt').read_bytes())
    key=serialization.load_pem_private_key((base/'ca/root.key').read_bytes(),password=None)
    now=dt.datetime.now(dt.timezone.utc)
    end=min(now+dt.timedelta(days=365),ca.not_valid_after.replace(tzinfo=dt.timezone.utc)-dt.timedelta(hours=1))
    if end<=now+dt.timedelta(days=1): raise ValueError('Retained CA expires too soon to issue a portal certificate.')
    leaf_key=ec.generate_private_key(ec.SECP256R1());sans=[]
    for name in names(c):
        try:sans.append(x509.IPAddress(ipaddress.IPv4Address(name)))
        except ValueError:sans.append(x509.DNSName(name))
    cert=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Access Gate portal')]))
        .issuer_name(ca.subject).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-dt.timedelta(minutes=5)).not_valid_after(end)
        .add_extension(x509.SubjectAlternativeName(sans),False).add_extension(x509.BasicConstraints(ca=False,path_length=None),True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),False).sign(key,hashes.SHA256()))
    atomic_write(base/'portal.key',leaf_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode(),0o640)
    atomic_write(base/'portal.crt',cert.public_bytes(serialization.Encoding.PEM).decode(),0o640)


def apply(root,c,runner=command,gid=None):
    """Caller owns maintenance lock. Staged crypto validation precedes service changes."""
    from .gateway_setup import prepare
    root=Path(root);current=normalize(json.loads((root/'etc/access-gate/config.json').read_text()))
    private=root/'var/lib/access-gate/reconfigure';private.mkdir(parents=True,exist_ok=True,mode=0o700);private.chmod(0o700)
    backup=Path(tempfile.mkdtemp(prefix='rollback-',dir=private));backup.chmod(0o700)
    for relative in FILES:
        source=root/relative
        if source.is_symlink():raise ValueError('Managed configuration must not be a symlink.')
        if source.exists():
            dest=backup/relative;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,dest)
    with tempfile.TemporaryDirectory(prefix='stage-',dir=private) as temp:
        stage=Path(temp);base=stage/'etc/access-gate'
        shutil.copytree(root/'etc/access-gate',base)
        atomic_write(base/'config.json',json.dumps(c,indent=2)+'\n')
        if names(c)!=names(current):portal_certificate(base,c)
        prepare(stage,gid=gid)
        atomic_write(stage/'nginx.conf',render_http(c),0o644)
        # Syntax-test an isolated nginx config before touching the running server.
        testconf=stage/'test-nginx.conf'
        include=stage/'clients.conf';include.write_text(''.join('allow '+n+';\n' for n in c['client_networks'])+'deny all;\n')
        http=render_http(c).replace('/etc/access-gate/client-networks.nginx',str(include))
        testconf.write_text('pid '+str(stage/'nginx.pid')+';\nevents {}\nhttp { access_log off; error_log stderr; default_type application/octet-stream; '+http+' }\n')
        runner(['/usr/sbin/nginx','-t','-c',str(testconf)])
        try:
            runner(['/usr/bin/systemctl','stop',*SERVICES[1:]])
            for relative in FILES:
                if relative.startswith('etc/access-gate/'):
                    source=stage/relative
                    if source.exists():atomic_write(root/relative,source.read_text(),(root/relative).stat().st_mode&0o777 if (root/relative).exists() else 0o640)
            atomic_write(root/'etc/access-gate/client-networks.nginx',''.join('allow '+n+';\n' for n in c['client_networks'])+'deny all;\n',0o644)
            atomic_write(root/'etc/nginx/sites-available/access-gate',render_http(c),0o644)
            runner(['/usr/sbin/nginx','-t'])
            runner(['/usr/bin/systemctl','restart',*SERVICES])
            runner(['/usr/bin/python3','-m','access_gate.readiness'])
        except Exception as original:
            try:
                for relative in FILES:
                    previous=backup/relative
                    if previous.exists():atomic_write(root/relative,previous.read_text(),previous.stat().st_mode&0o777)
                    else:(root/relative).unlink(missing_ok=True)
                runner(['/usr/bin/systemctl','restart',*SERVICES])
                runner(['/usr/bin/python3','-m','access_gate.readiness'])
            except Exception:raise RuntimeError('Reconfiguration and rollback readiness failed. Retained private backup: '+str(backup)) from original
            raise RuntimeError('Reconfiguration failed; previous configuration restored. Backup: '+str(backup)) from original
    # Database security policy is applied only after the new listeners pass readiness.
    from .core import Store
    database=root/c['database'].lstrip('/')
    from .recovery import database_account
    with database_account(root):
        store=Store(database,c['pepper'])
        if c['admin_networks']!=current['admin_networks']:
            store.save_admin_security(c,networks=c['admin_networks'])
        if c['portal_url']!=current['portal_url']:
            with store.connect() as db:
                for table in ('push_deliveries','push_subscriptions','admin_site_tokens','admin_handoffs','admin_logins'):db.execute('DELETE FROM '+table)
                db.commit()
        store.audit('system.reconfigured',actor='System')
    return backup


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--profile');parser.add_argument('--yes',action='store_true');parser.add_argument('--check',action='store_true');args=parser.parse_args()
    if os.geteuid()!=0:raise SystemExit('Run reconfigure as root.')
    path=Path('/etc/access-gate/config.json');current=normalize(json.loads(path.read_text()))
    if args.profile:requested=json.loads(Path(args.profile).read_text())
    else:
        address=ask('Server IPv4',current['server_ipv4']);portal=ask('Portal HTTPS origin',current['portal_url'])
        requested=dict(server_ipv4=address,listen_ipv4=address,dns_target_ipv4=address,portal_url=portal,
                       client_networks=ask('Client CIDRs, comma-separated',','.join(current['client_networks'])).replace(' ','').split(','),
                       admin_networks=ask('Management CIDRs, comma-separated',','.join(current['admin_networks'])).replace(' ','').split(','))
    c=updated(current,requested)
    if c['listen_ipv4'] not in local_addresses():raise SystemExit('Assign the new IPv4 address on the host before reconfiguring.')
    for key in FIELDS:
        if c[key]!=current[key]:print(key+': '+str(current[key])+' -> '+str(c[key]))
    print('CA and code database are retained. Update external DNS/Pi-hole sync after an address change. Portal-origin changes require admin sign-in, phone-app and push re-enrollment; visitors may need a new code when browser identity changes.')
    if args.check:return
    if not args.yes and ask('Apply changes? Type RECONFIGURE')!='RECONFIGURE':raise SystemExit('Cancelled.')
    lock=Path('/var/lib/access-gate/maintenance/worker.lock');lock.parent.mkdir(parents=True,exist_ok=True)
    with lock.open('a') as stream:
        fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
        # Reject a stale preview if another maintenance command changed settings.
        if normalize(json.loads(path.read_text()))!=current:raise SystemExit('Configuration changed; review again.')
        backup=apply(Path('/'),c)
    print('Reconfiguration passed readiness. Private rollback snapshot: '+str(backup))


if __name__=='__main__':main()
