"""Authenticated, bounded recovery bundles. Never extract an uploaded tar/zip."""
from contextlib import contextmanager
import base64
import json
from pathlib import Path
import secrets
import sqlite3
import tempfile
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from .core import Store,SCHEMA_VERSION,GateError
from .settings import validate
from .maintenance import MAX_ARCHIVE,read_regular,write_private

MAGIC=b'ACCESSGATE-BACKUP-1\n'
STATE_FILES=('config.json','acl-token','ca/root.key','ca/root.crt','portal.key','portal.crt','gateway/issuer.key','gateway/issuer.crt')
DATABASE='/var/lib/access-gate/data/gate.sqlite3'


def password_check(password):
    if not isinstance(password,str) or not 12<=len(password)<=256:raise GateError('Use a backup passphrase of 12 to 256 characters.')


def encrypt(data,password):
    password_check(password)
    salt,nonce=secrets.token_bytes(16),secrets.token_bytes(12)
    key=Scrypt(salt=salt,length=32,n=2**14,r=8,p=1).derive(password.encode())
    result=MAGIC+salt+nonce+AESGCM(key).encrypt(nonce,data,MAGIC)
    if len(result)>MAX_ARCHIVE:raise GateError('Backup exceeds the 64 MiB archive limit.')
    return result


def decrypt(data,password):
    password_check(password)
    if not data.startswith(MAGIC) or not len(MAGIC)+44<=len(data)<=MAX_ARCHIVE:raise GateError('Unsupported encrypted backup.')
    offset=len(MAGIC);salt,nonce=data[offset:offset+16],data[offset+16:offset+28]
    key=Scrypt(salt=salt,length=32,n=2**14,r=8,p=1).derive(password.encode())
    try:return AESGCM(key).decrypt(nonce,data[offset+28:],MAGIC)
    except Exception:raise GateError('The backup passphrase is incorrect or the archive is damaged.') from None


@contextmanager
def database_account(root):
    # The root worker reads SQLite as the portal user, so database-path races cannot
    # turn a backup job into arbitrary root-file access or root-owned WAL files.
    import os
    if Path(root)!=Path('/') or os.geteuid()!=0:
        yield
        return
    import pwd
    user=pwd.getpwnam('accessgate');previous_gid=os.getegid();groups=os.getgroups()
    try:
        os.setgroups([]);os.setegid(user.pw_gid);os.seteuid(user.pw_uid)
        yield
    finally:
        os.seteuid(0);os.setegid(previous_gid);os.setgroups(groups)


def snapshot(root,version):
    root=Path(root);base=root/'etc/access-gate'
    config=validate(json.loads(read_regular(base/'config.json',65536)))
    if config['database']!=DATABASE:raise GateError('Only the standard dedicated-server database path is supported.')
    files={name:base64.b64encode(read_regular(base/name,1024*1024)).decode() for name in STATE_FILES}
    source=root/DATABASE.lstrip('/')
    with tempfile.TemporaryDirectory() as tmp:
        import os
        if root==Path('/') and os.geteuid()==0:
            import pwd
            user=pwd.getpwnam('accessgate');os.chown(tmp,user.pw_uid,user.pw_gid)
        target=Path(tmp)/'snapshot.sqlite3'
        with database_account(root):
            read_regular(source,MAX_ARCHIVE)
            with sqlite3.connect(source) as db,sqlite3.connect(target) as saved:db.backup(saved)
        files['database']=base64.b64encode(read_regular(target,MAX_ARCHIVE)).decode()
    return json.dumps(dict(format=1,schema=SCHEMA_VERSION,version=version,created=time.time(),files=files),separators=(',',':')).encode()


def preflight(data,password,directory):
    """Validate in a private staging root. Nothing is replaced on the server."""
    from .gateway_setup import prepare
    import os
    directory=Path(directory)
    bundle=json.loads(decrypt(data,password))
    if bundle.get('format')!=1 or bundle.get('schema')!=SCHEMA_VERSION:raise GateError('Backup schema does not match this installed version. Install a matching version first.')
    files=bundle.get('files')
    if not isinstance(files,dict) or set(files)!=set(STATE_FILES)|{'database'}:raise GateError('Backup has missing or unexpected components.')
    total=0
    for name,value in files.items():
        if not isinstance(value,str):raise GateError('Invalid backup component.')
        decoded=base64.b64decode(value,validate=True);total+=len(decoded)
        if total>MAX_ARCHIVE:raise GateError('Backup contents exceed the size limit.')
        target=directory/'database' if name=='database' else directory/'etc/access-gate'/name
        target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        write_private(target,decoded)
    config=validate(json.loads((directory/'etc/access-gate/config.json').read_text()))
    if config['database']!=DATABASE:raise GateError('Unexpected database path in backup.')
    if (directory/'etc/access-gate/acl-token').read_text().strip()!=config['acl_token']:raise GateError('Backup ACL token does not match.')
    database=directory/'database'
    with sqlite3.connect(database) as db:
        db.execute('PRAGMA foreign_keys=ON')
        if db.execute('PRAGMA integrity_check').fetchone()[0]!='ok' or db.execute('PRAGMA foreign_key_check').fetchall():raise GateError('Backup database failed integrity checks.')
        if db.execute('PRAGMA user_version').fetchone()[0]!=SCHEMA_VERSION:raise GateError('Backup database schema mismatch.')
        if db.execute("SELECT 1 FROM sqlite_master WHERE type IN ('trigger','view')").fetchone():raise GateError('Unexpected executable database schema.')
        reference=directory/'reference';Store(reference,config['pepper']).initialize()
        with sqlite3.connect(reference) as expected:
            tables={r[0] for r in expected.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            actual={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if tables!=actual:raise GateError('Unexpected database tables.')
            for table in tables:
                if list(db.execute('PRAGMA table_info("'+table+'")'))!=list(expected.execute('PRAGMA table_info("'+table+'")')):raise GateError('Unexpected database columns.')
        counts={table:db.execute('SELECT count(*) FROM '+table).fetchone()[0] for table in ('batches','codes','grants')}
    # Validate root/issuer chains, key matches and portal key match before stopping anything.
    prepare(directory,gid=os.getgid())
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    cert=x509.load_pem_x509_certificate((directory/'etc/access-gate/portal.crt').read_bytes())
    key=serialization.load_pem_private_key((directory/'etc/access-gate/portal.key').read_bytes(),password=None)
    if cert.public_key().public_numbers()!=key.public_key().public_numbers():raise GateError('Portal certificate/key mismatch.')
    import datetime as dt
    import ipaddress
    from urllib.parse import urlsplit
    from cryptography.hazmat.primitives.asymmetric import rsa,padding,ec
    from .gateway_tls import expires
    root_cert=x509.load_pem_x509_certificate((directory/'etc/access-gate/ca/root.crt').read_bytes())
    public=root_cert.public_key()
    if cert.issuer!=root_cert.subject or expires(cert)<=dt.datetime.now(dt.timezone.utc):raise GateError('Portal certificate is expired or has the wrong issuer.')
    if isinstance(public,rsa.RSAPublicKey):public.verify(cert.signature,cert.tbs_certificate_bytes,padding.PKCS1v15(),cert.signature_hash_algorithm)
    else:public.verify(cert.signature,cert.tbs_certificate_bytes,ec.ECDSA(cert.signature_hash_algorithm))
    host=urlsplit(config['portal_url']).hostname
    san=cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    try:matched=ipaddress.ip_address(host) in san.get_values_for_type(x509.IPAddress)
    except ValueError:matched=host in san.get_values_for_type(x509.DNSName)
    if not matched:raise GateError('Portal certificate does not cover the configured portal address.')
    return dict(version=str(bundle.get('version',''))[:40],created=bundle.get('created'),counts=counts,policy='All restored codes, grants, pending requests and administrator sessions will be invalidated.')


def invalidate(database,config):
    store=Store(database,config['pepper'])
    with store.connect() as db:
        db.execute('BEGIN IMMEDIATE')
        db.execute('DELETE FROM push_deliveries');db.execute('DELETE FROM push_subscriptions')
        db.execute('UPDATE schedules SET enabled=0')
        db.execute("UPDATE schedule_runs SET payload=NULL,status='invalidated' WHERE status='ready'")
        db.execute('UPDATE codes SET revoked=1');db.execute('UPDATE batches SET revoked=1');db.execute('UPDATE grants SET revoked=1,browser_hash=NULL')
        for table in ('admin_site_tokens','admin_handoffs','admin_logins','gateway_tokens','gateway_entries'):db.execute('DELETE FROM '+table)
        db.execute("UPDATE access_requests SET status='expired',read_at=?,resolved_at=? WHERE status='pending'",(time.time(),time.time()))
        db.execute('UPDATE administrator_policy SET version=?',(secrets.token_hex(32),))
        store._event(db,'recovery.restored',actor='System')
        db.commit();db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
