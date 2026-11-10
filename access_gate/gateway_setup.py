"""Root-only gateway deployment settings and intermediate CA provisioning."""
import datetime as dt
import grp
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .gateway_tls import expires
from .settings import atomic_write


def prepare(root=Path('/'), gid=None):
    root = Path(root)
    base = root/'etc/access-gate'; directory = base/'gateway'
    config = json.loads((base/'config.json').read_text())
    ca = x509.load_pem_x509_certificate((base/'ca/root.crt').read_bytes())
    ca_key = serialization.load_pem_private_key((base/'ca/root.key').read_bytes(), password=None)
    now = dt.datetime.now(dt.timezone.utc)
    constraints = ca.extensions.get_extension_for_class(x509.BasicConstraints).value
    if not constraints.ca or constraints.path_length == 0 or expires(ca) <= now+dt.timedelta(days=1):
        raise ValueError('The retained root CA cannot issue a gateway intermediate or expires too soon.')
    if ca.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != ca_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo):
        raise ValueError('The retained root CA key does not match its certificate.')
    if directory.is_symlink(): raise ValueError('Gateway configuration must not be a symlink.')
    directory.mkdir(mode=0o750, exist_ok=True)
    files = [directory/name for name in ('issuer.crt', 'issuer.key', 'gateway.json')]
    portal_files = [base/'portal.crt', base/'portal.key']
    if any(path.is_symlink() for path in files + portal_files): raise ValueError('Gateway state and TLS files must not be symlinks.')
    cert_path, key_path, config_path = files
    if cert_path.exists() != key_path.exists(): raise ValueError('Gateway issuer state is incomplete. Restore the saved matching key/certificate.')
    renew = not cert_path.exists()
    if not renew:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        if cert.issuer != ca.subject or cert.public_key().public_numbers() != key.public_key().public_numbers():
            raise ValueError('The gateway issuer does not match the retained CA/key. Restore the matching backup.')
        authority = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if not authority.ca or authority.path_length != 0:
            raise ValueError('The gateway issuer must be a path-length-zero intermediate CA.')
        if isinstance(ca.public_key(), rsa.RSAPublicKey):
            ca.public_key().verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
        else:
            ca.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        renew = expires(cert) <= now+dt.timedelta(days=30)
    if renew:
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Access Gate HTTPS Gateway CA')]))
            .issuer_name(ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-dt.timedelta(minutes=5)).not_valid_after(min(now+dt.timedelta(days=365), expires(ca)-dt.timedelta(hours=1)))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
        atomic_write(key_path, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode())
        atomic_write(cert_path, cert.public_bytes(serialization.Encoding.PEM).decode())
    portal_host = urlsplit(config['portal_url']).hostname
    gateway = dict(api_url='http://127.0.0.1:8088', api_key=config['acl_token'],
        portal_url=config['portal_url'], portal_hosts=sorted({portal_host, '10.40.22.5', 'toegang.coyseinri.nl'}),
        client_networks=config['client_networks'], listen_host='10.40.22.5', listen_port=443,
        http_host='127.0.0.1', http_port=8089, runtime_dir='/run/access-gate-gateway',
        issuer_cert='/etc/access-gate/gateway/issuer.crt', issuer_key='/etc/access-gate/gateway/issuer.key',
        portal_cert='/etc/access-gate/portal.crt', portal_key='/etc/access-gate/portal.key')
    atomic_write(config_path, json.dumps(gateway, indent=2)+'\n')
    if gid is None: gid = grp.getgrnam('accessgate-gateway').gr_gid
    os.chown(directory, 0 if os.geteuid()==0 else os.geteuid(), gid); directory.chmod(0o750)
    # OpenSSL under the installer's umask 027 can leave an existing public certificate
    # root:root 0640. The separate gateway needs group access to BOTH cert and key.
    for path in files + portal_files:
        os.chown(path, 0 if os.geteuid()==0 else os.geteuid(), gid); path.chmod(0o640)
    return gateway


if __name__ == '__main__':
    if os.geteuid() != 0: raise SystemExit('Run gateway setup as root.')
    prepare()
    print('HTTPS gateway configured with the retained root CA and an isolated issuing CA.')
