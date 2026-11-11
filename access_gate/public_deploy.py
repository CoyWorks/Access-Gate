"""Root-only public TLS, MFA and remote gateway enrollment operations."""
import argparse
import base64
import datetime as dt
import fcntl
import getpass
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import ssl
import socket
import subprocess
import tempfile
from urllib.parse import quote,urlsplit
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
from .core import Store,GateError
from .deployment import normalize
from .settings import atomic_write
from .recovery import database_account

BASE=Path('/etc/access-gate')


def run(args):subprocess.run(args,check=True,timeout=300)


def pair(cert,key):
    return cert.public_bytes(serialization.Encoding.PEM),key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())


def validate_tls(cert,key,hostname,cafile=None):
    """Validate the public chain, name, validity and matching private key offline."""
    serialization.load_pem_private_key(key,password=None)
    with tempfile.TemporaryDirectory() as temp:
        path=Path(temp);(path/'chain').write_bytes(cert);(path/'key').write_bytes(key);(path/'key').chmod(0o600)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(path/'chain',path/'key')
        leaf=x509.load_pem_x509_certificate(cert)
        if leaf.not_valid_after.replace(tzinfo=dt.timezone.utc)<dt.datetime.now(dt.timezone.utc)+dt.timedelta(days=2):raise ValueError('Portal certificate must remain valid for more than two days.')
        (path/'leaf').write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        args=['/usr/bin/openssl','verify','-purpose','sslserver','-verify_hostname',hostname]
        args+=['-CAfile',str(cafile)] if cafile else ['-CApath','/etc/ssl/certs']
        result=subprocess.run(args+['-untrusted',str(path/'chain'),str(path/'leaf')],capture_output=True,timeout=10)
        if result.returncode:raise ValueError('Portal TLS chain must validate against trusted system roots and cover the portal hostname.')


def ensure_authority(base=BASE,gid=None):
    import grp
    directory=base/'authority'
    if directory.is_symlink():raise ValueError('Authority directory must not be a symlink.')
    directory.mkdir(mode=0o750,exist_ok=True)
    gid=grp.getgrnam('accessgate-gateway').gr_gid if gid is None else gid
    os.chown(directory,os.geteuid(),gid);directory.chmod(0o750)
    certfile,keyfile=directory/'ca.crt',directory/'ca.key'
    if certfile.exists()!=keyfile.exists():raise ValueError('Enrollment authority state is incomplete; restore its matching key/certificate.')
    if not certfile.exists():
        key=ec.generate_private_key(ec.SECP256R1());now=dt.datetime.now(dt.timezone.utc);subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Access Gate enrollment CA')])
        cert=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-dt.timedelta(minutes=5)).not_valid_after(now+dt.timedelta(days=730))
            .add_extension(x509.BasicConstraints(ca=True,path_length=0),True)
            .add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),True).sign(key,hashes.SHA256()))
        certdata,keydata=pair(cert,key);atomic_write(certfile,certdata.decode(),0o640);atomic_write(keyfile,keydata.decode(),0o600)
    os.chown(certfile,os.geteuid(),gid);certfile.chmod(0o640);keyfile.chmod(0o600)
    certificate=x509.load_pem_x509_certificate(certfile.read_bytes());private=serialization.load_pem_private_key(keyfile.read_bytes(),password=None)
    if not certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca or certificate.public_key().public_numbers()!=private.public_key().public_numbers():raise ValueError('Enrollment CA certificate/key mismatch.')
    return certificate,private


def enrollment(store,c,name,base=BASE,gid=None):
    authority,authority_key=ensure_authority(base,gid=gid);key=ec.generate_private_key(ec.SECP256R1());now=dt.datetime.now(dt.timezone.utc)
    expires=min(now+dt.timedelta(days=90),authority.not_valid_after.replace(tzinfo=dt.timezone.utc)-dt.timedelta(hours=1))
    if expires<=now+dt.timedelta(days=1):raise ValueError('Enrollment CA expires too soon. Plan an authority rotation and gateway re-enrollment.')
    cert=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'gateway-'+secrets.token_hex(8))]))
        .issuer_name(authority.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-dt.timedelta(minutes=5)).not_valid_after(expires).add_extension(x509.BasicConstraints(ca=False,path_length=None),True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),False).sign(authority_key,hashes.SHA256()))
    certdata,keydata=pair(cert,key);api_key=secrets.token_hex(32)
    gateway=store.register_gateway(name,cert.fingerprint(hashes.SHA256()).hex(),api_key,expires.timestamp())
    return dict(format=1,id=gateway,portal_url=c['portal_url'],key=api_key,cert=certdata.decode(),private_key=keydata.decode(),expires=expires.timestamp())


def request_peer(peer,path,method='GET',cafile=None):
    context=ssl.create_default_context(cafile=cafile)
    with tempfile.TemporaryDirectory() as temp:
        p=Path(temp);(p/'cert').write_text(peer['cert']);(p/'key').write_text(peer['private_key']);(p/'key').chmod(0o600)
        context.load_cert_chain(p/'cert',p/'key')
        target=urlsplit(peer['portal_url']);connection=http.client.HTTPSConnection(target.hostname,target.port or 443,context=context,timeout=5)
        try:
            connection.request(method,path,body=b'' if method=='POST' else None,headers={'X-Gateway-Key':peer['key']})
            response=connection.getresponse();data=response.read(4097)
            if response.status!=200 or len(data)>4096:raise ValueError('Gateway enrollment/health failed; check public DNS, TLS and enrollment status.')
            result=json.loads(data)
            if result.get('gateway')!=peer['id']:raise ValueError('Unexpected gateway enrollment identity.')
            return result
        finally:connection.close()


def save_json(path,value,mode=0o640):atomic_write(path,json.dumps(value,indent=2)+'\n',mode)


def update_config(c,files,runner=run):
    """Preserve all modified files and roll back a failed activation."""
    from .gateway_setup import prepare
    directory=Path(tempfile.mkdtemp(prefix='access-gate-public-',dir='/root'));directory.chmod(0o700)
    targets=[Path('/etc/nginx/sites-available/access-gate'),BASE/'config.json',BASE/'portal.crt',BASE/'portal.key',BASE/'gateway/gateway.json',*files]
    old={str(p):p.read_bytes() if p.exists() else None for p in targets}
    for index,(name,data) in enumerate(old.items()):
        if data is not None:(directory/str(index)).write_bytes(data)
    (directory/'manifest.json').write_text(json.dumps({str(index):name for index,name in enumerate(old)},indent=2)+'\n')
    try:
        for path,data in files.items():atomic_write(path,data.decode(),0o640)
        save_json(BASE/'config.json',c)
        from .deployment import render_http
        atomic_write('/etc/nginx/sites-available/access-gate',render_http(c),0o644)
        prepare();runner(['/usr/bin/python3','-m','access_gate.services']);runner(['/usr/bin/systemctl','restart','access-gate.service','access-gate-gateway.service'])
        runner(['/usr/bin/python3','-m','access_gate.readiness'])
    except Exception as exc:
        for name,data in old.items():
            if data is None:Path(name).unlink(missing_ok=True)
            else:atomic_write(name,data.decode())
        runner(['/usr/bin/python3','-m','access_gate.services'])
        runner(['/usr/bin/systemctl','restart','access-gate.service','access-gate-gateway.service'])
        try:runner(['/usr/bin/python3','-m','access_gate.readiness'])
        except Exception:raise RuntimeError('Activation and rollback readiness failed. Private backup: '+str(directory)) from exc
        raise RuntimeError('Activation failed; previous configuration restored. Private backup: '+str(directory)) from exc
    return directory


def tls_sources(certpath,keypath):
    certpath,keypath=Path(certpath),Path(keypath)
    if not certpath.is_absolute() or not keypath.is_absolute():raise ValueError('Use absolute TLS source paths.')
    info=keypath.stat()
    if info.st_uid!=0 or info.st_mode&0o027:raise ValueError('TLS source key must be root-owned, not group-writable and inaccessible to other users.')
    cert,key=certpath.read_bytes(),keypath.read_bytes()
    if len(cert)>1024*1024 or len(key)>65536:raise ValueError('TLS source files exceed their size limits.')
    return cert,key


def verify_live_certificate(c,cert,port=443,cafile=BASE/'ca/root.crt'):
    context=ssl.create_default_context();context.load_verify_locations(cafile=str(cafile))
    expected=x509.load_pem_x509_certificate(cert).fingerprint(hashes.SHA256())
    with socket.create_connection((c['listen_ipv4'],port),timeout=3) as sock:
        with context.wrap_socket(sock,server_hostname=urlsplit(c['portal_url']).hostname) as tls:
            if hashlib.sha256(tls.getpeercert(binary_form=True)).digest()!=expected:raise ValueError('The live TLS listener did not load the expected certificate.')


def renew(c):
    if not c['public_portal']:return
    cert,key=tls_sources(c['public_tls_cert'],c['public_tls_key'])
    validate_tls(cert,key,urlsplit(c['portal_url']).hostname)
    if cert==(BASE/'portal.crt').read_bytes() and key==(BASE/'portal.key').read_bytes():return
    oldcert,oldkey=(BASE/'portal.crt').read_bytes(),(BASE/'portal.key').read_bytes()
    try:
        atomic_write(BASE/'portal.crt',cert.decode());atomic_write(BASE/'portal.key',key.decode())
        run(['/usr/bin/systemctl','kill','--signal=HUP','--kill-whom=main','access-gate-gateway.service'])
        run(['/usr/bin/python3','-m','access_gate.readiness'])
        verify_live_certificate(c,cert)
    except Exception:
        atomic_write(BASE/'portal.crt',oldcert.decode());atomic_write(BASE/'portal.key',oldkey.decode())
        run(['/usr/bin/systemctl','kill','--signal=HUP','--kill-whom=main','access-gate-gateway.service']);raise


def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='action',required=True)
    enable=sub.add_parser('enable');enable.add_argument('--cert',required=True);enable.add_argument('--key',required=True);enable.add_argument('--admin-public',action='store_true');enable.add_argument('--admin-networks')
    acme=sub.add_parser('acme');acme.add_argument('--email',required=True);acme.add_argument('--agree-tos',action='store_true')
    enroll=sub.add_parser('enroll');enroll.add_argument('--name',required=True);enroll.add_argument('--output',required=True)
    activate=sub.add_parser('activate');activate.add_argument('bundle')
    revoke=sub.add_parser('revoke');revoke.add_argument('gateway_id')
    sub.add_parser('list');sub.add_parser('mfa-setup');sub.add_parser('renew');sub.add_parser('disconnect');sub.add_parser('disable')
    args=parser.parse_args()
    if os.geteuid()!=0:raise SystemExit('Run public deployment commands as root.')
    lock=Path('/var/lib/access-gate/maintenance/worker.lock')
    with lock.open('a') as stream:
        fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
        c=normalize(json.loads((BASE/'config.json').read_text()))
        store=Store(c['database'],c['pepper'])
        if args.action=='enable':
            if c['remote_gateway']:raise ValueError('Disconnect the remote gateway before enabling an authority.')
            hostname=urlsplit(c['portal_url']).hostname
            try:__import__('ipaddress').ip_address(hostname)
            except ValueError:pass
            else:raise ValueError('Choose a DNS hostname as portal_url before enabling public TLS.')
            certpath=Path(args.cert);keypath=Path(args.key)
            if not certpath.is_absolute() or not keypath.is_absolute():raise ValueError('Use absolute TLS source paths.')
            cert,key=tls_sources(certpath,keypath);validate_tls(cert,key,hostname);ensure_authority()
            with database_account(Path('/')):
                if args.admin_public and not store.mfa_enabled():raise ValueError('Configure MFA first with mfa-setup.')
            c.update(public_portal=True,public_admin=args.admin_public,public_tls_cert=str(certpath),public_tls_key=str(keypath))
            with database_account(Path('/')):
                networks=__import__('access_gate.administration',fromlist=['management_networks']).management_networks(args.admin_networks) if args.admin_networks else None
                store.save_admin_security(c,networks=networks)
            update_config(c,{BASE/'portal.crt':cert,BASE/'portal.key':key})
            # TLS issuance remains with the operator's ACME/web-host client; this imports verified renewals.
            Path('/etc/systemd/system/access-gate-public-tls.service').write_text('[Unit]\nDescription=Import verified Access Gate public TLS renewal\n[Service]\nType=oneshot\nWorkingDirectory=/opt/access-gate\nExecStart=/usr/bin/python3 -m access_gate.public_deploy renew\n')
            Path('/etc/systemd/system/access-gate-public-tls.timer').write_text('[Unit]\nDescription=Check Access Gate public TLS source daily\n[Timer]\nOnBootSec=10min\nOnUnitActiveSec=12h\nPersistent=true\n[Install]\nWantedBy=timers.target\n')
            run(['/usr/bin/systemctl','daemon-reload']);run(['/usr/bin/systemctl','enable','--now','access-gate-public-tls.timer'])
            print('Public portal enabled. Keep administration private unless explicitly configured with MFA. DNS and firewall changes remain operator controlled.')
        elif args.action=='acme':
            if not args.agree_tos:raise ValueError('Review the ACME provider terms and pass --agree-tos explicitly to request a certificate.')
            from .browser import origin
            domain=urlsplit(origin(c['portal_url'])).hostname
            if not args.email or len(args.email)>254 or '@' not in args.email or any(ord(ch)<33 for ch in args.email):raise ValueError('Supply a valid ACME contact email.')
            directory=Path('/var/lib/access-gate/acme');directory.mkdir(parents=True,exist_ok=True,mode=0o755)
            c['acme_http']=True;update_config(c,{})
            run(['/usr/bin/apt-get','update']);run(['/usr/bin/apt-get','install','-y','certbot'])
            run(['/usr/bin/systemctl','enable','--now','certbot.timer'])
            run(['/usr/bin/certbot','certonly','--webroot','-w',str(directory),'--cert-name','access-gate','-d',domain,'--email',args.email,'--agree-tos','--non-interactive'])
            print('Certificate issued. Enable it with: python3 -m access_gate.public_deploy enable --cert /etc/letsencrypt/live/access-gate/fullchain.pem --key /etc/letsencrypt/live/access-gate/privkey.pem')
        elif args.action=='enroll':
            if not c['public_portal']:raise ValueError('Enable the verified public portal before enrolling gateways.')
            if Path(args.output).exists():raise ValueError('Enrollment output already exists; select a new private file.')
            # Root signs; SQLite operations run under the database owner.
            # Signing happens as root; register only the resulting public metadata as the database owner.
            class Registry:
                def register_gateway(self,*values):
                    with database_account(Path('/')):return store.register_gateway(*values)
            peer=enrollment(Registry(),c,args.name)
            fd=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'w') as out:json.dump(peer,out)
            print('Enrollment saved privately. Transfer it securely, activate it once on the gateway, then remove the transfer copy. Gateway ID: '+peer['id'])
        elif args.action=='activate':
            if c['public_portal']:raise ValueError('Do not enroll an active authority as a private gateway. Use a separate node.')
            from .browser import origin
            peer=json.loads(Path(args.bundle).read_text())
            if peer.get('format')!=1 or peer.get('expires',0)<=__import__('time').time():raise ValueError('Enrollment bundle is expired or invalid.')
            peer['portal_url']=origin(peer['portal_url'])
            if not __import__('re').fullmatch('[a-f0-9]{64}',peer.get('key','')):raise ValueError('Invalid enrollment credential.')
            directory=BASE/'remote';directory.mkdir(mode=0o750,exist_ok=True)
            import grp
            gid=grp.getgrnam('accessgate-gateway').gr_gid;os.chown(directory,0,gid);directory.chmod(0o750)
            pending=directory/'activation.json';digest=hashlib.sha256(json.dumps(peer,sort_keys=True).encode()).hexdigest()
            if pending.exists() and json.loads(pending.read_text()).get('bundle_hash')==digest:
                request_peer(peer,'/gateway/v1/health')
            else:
                request_peer(peer,'/gateway/v1/activate',method='POST')
                save_json(pending,dict(bundle_hash=digest),0o600)
            files={directory/'client.crt':peer['cert'].encode(),directory/'client.key':peer['private_key'].encode(),directory/'peer.json':json.dumps({k:peer[k] for k in ('id','portal_url','key','expires')}).encode()}
            for path in files:
                if not path.exists():path.touch(mode=0o640)
                os.chown(path,0,gid)
            c.update(remote_gateway=True,remote_portal_url=peer['portal_url'],public_portal=False,public_admin=False)
            update_config(c,files)
            from .remote_domains import install
            install(start=True)
            run(['/usr/bin/python3','-m','access_gate.remote_domains','--once'])
            print('Remote gateway activated. Its existing inspection CA remains local. Public portal owns codes and requests; local runtime data is retained for recovery.')
        elif args.action=='disable':
            if not c['public_portal']:raise ValueError('This node is not a public authority.')
            from .reconfigure import portal_certificate
            c.update(public_portal=False,public_admin=False)
            with tempfile.TemporaryDirectory() as temporary:
                stage=Path(temporary);(stage/'ca').mkdir()
                for name in ('root.key','root.crt'):shutil.copy2(BASE/'ca'/name,stage/'ca'/name)
                portal_certificate(stage,c)
                with database_account(Path('/')):
                    with store.connect() as db:db.execute('UPDATE remote_gateways SET enabled=0')
                    store.save_admin_security(c,networks=c['admin_networks'])
                update_config(c,{BASE/'portal.crt':(stage/'portal.crt').read_bytes(),BASE/'portal.key':(stage/'portal.key').read_bytes()})
            subprocess.run(['systemctl','disable','--now','access-gate-public-tls.timer'],check=False)
            print('Public authority disabled; local CA TLS and private network access restored. Remote credentials are revoked.')
        elif args.action=='disconnect':
            if not c['remote_gateway']:raise ValueError('This node has no remote authorization connection.')
            c['remote_gateway']=False;update_config(c,{})
            run(['/usr/bin/systemctl','disable','--now','access-gate-remote-domains.service'])
            print('Local authorization restored. Revoke the old gateway credential on the authority.')
        elif args.action=='renew':renew(c)
        elif args.action=='mfa-setup':
            seed=base64.b32encode(os.urandom(20)).decode()
            print('Add this secret to your authenticator: '+seed)
            print('otpauth://totp/Access%20Gate:admin?secret='+seed+'&issuer=Access%20Gate')
            proof=getpass.getpass('Current authenticator code: ')
            with database_account(Path('/')):codes=store.set_mfa(seed,proof)
            print('One-use recovery codes; save privately:\n'+'\n'.join(codes))
        else:
            with database_account(Path('/')):
                if args.action=='revoke':store.revoke_gateway(args.gateway_id);print('Gateway revoked. Active checks will deny it immediately.')
                elif args.action=='list':
                    with store.connect() as db:
                        for row in db.execute('SELECT id,name,expires,enabled,activated FROM remote_gateways ORDER BY created'):print(json.dumps(dict(row)))


if __name__=='__main__':main()
