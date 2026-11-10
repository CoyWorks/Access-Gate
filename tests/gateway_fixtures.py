import datetime as dt
import json
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from access_gate.gateway_setup import prepare


def ca(name, rsa_root=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072) if rsa_root else ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-dt.timedelta(days=1)).not_valid_after(now+dt.timedelta(days=730))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), True)
        .sign(key, hashes.SHA256()))
    return cert, key


def write_pair(cert, key, cert_file, key_file):
    Path(cert_file).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    Path(key_file).write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


def leaf(issuer, issuer_key, name, cert_file, key_file):
    key = ec.generate_private_key(ec.SECP256R1()); now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(issuer.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-dt.timedelta(hours=1)).not_valid_after(now+dt.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True).sign(issuer_key, hashes.SHA256()))
    write_pair(cert, key, cert_file, key_file)


def settings(root, portal_config, rsa_root=False):
    root = Path(root); base = root/'etc/access-gate'; (base/'ca').mkdir(parents=True)
    (base/'config.json').write_text(json.dumps(portal_config))
    cert, key = ca('Test Access Gate root', rsa_root=rsa_root)
    write_pair(cert, key, base/'ca/root.crt', base/'ca/root.key')
    leaf(cert, key, 'portal.example', base/'portal.crt', base/'portal.key')
    config = prepare(root, gid=os.getgid())
    for name in ('issuer_cert', 'issuer_key', 'portal_cert', 'portal_key', 'runtime_dir'):
        config[name] = str(root/config[name].lstrip('/'))
    Path(config['runtime_dir']).mkdir(parents=True, mode=0o700)
    return config
