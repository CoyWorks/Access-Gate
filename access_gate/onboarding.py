"""Public device setup data; only the public CA copy is ever read."""
import datetime as dt
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec,rsa,padding
from .maintenance import read_regular

PLATFORMS=('ios','android','windows')
LOCAL_SETUP_PATHS=frozenset(('/setup','/setup/bootstrap','/ca.crt','/static/gate.css','/static/gate.js'))


def public_root(path):
    data=read_regular(path,65536)
    cert=x509.load_pem_x509_certificate(data)
    if not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca or cert.subject!=cert.issuer:raise ValueError('The published certificate is not a root CA.')
    key=cert.public_key()
    if isinstance(key,rsa.RSAPublicKey):key.verify(cert.signature,cert.tbs_certificate_bytes,padding.PKCS1v15(),cert.signature_hash_algorithm)
    elif isinstance(key,ec.EllipticCurvePublicKey):key.verify(cert.signature,cert.tbs_certificate_bytes,ec.ECDSA(cert.signature_hash_algorithm))
    else:raise ValueError('Unsupported root certificate.')
    now=dt.datetime.now(dt.timezone.utc)
    if not cert.not_valid_before.replace(tzinfo=dt.timezone.utc)<=now<cert.not_valid_after.replace(tzinfo=dt.timezone.utc):raise ValueError('The published CA is outside its validity period.')
    return dict(der=cert.public_bytes(serialization.Encoding.DER),sha256=cert.fingerprint(hashes.SHA256()).hex().upper(),subject=cert.subject.rfc4514_string(),expires=cert.not_valid_after.replace(tzinfo=dt.timezone.utc).timestamp())


def setup_context(config,ca_path):
    result=dict(portal_url=config['portal_url'],gateway=config['listen_ipv4'],dns_mode=config['dns_mode'],authority=config['public_portal'],remote=config['remote_gateway'],ca=None,ca_error=None)
    if config['public_portal']:return result
    try:
        ca=public_root(ca_path);result['ca']={k:v for k,v in ca.items() if k!='der'}
    except Exception:result['ca_error']='The published device CA is missing, invalid or expired. Ask the administrator to check System status and the public CA copy. No certificate was replaced.'
    return result
