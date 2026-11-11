"""Short-lived exact-host TLS certificates under an isolated intermediate CA."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import threading
from collections import OrderedDict
from contextlib import nullcontext
import datetime as dt
from pathlib import Path
import ssl
import tempfile
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def expires(cert):
    try: return cert.not_valid_after_utc
    except AttributeError: return cert.not_valid_after.replace(tzinfo=dt.timezone.utc)


def server_context(cert, key=None):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(['http/1.1'])
    context.load_cert_chain(str(cert), str(key) if key else None)
    return context


@dataclass(frozen=True)
class CacheEntry:
    created: float
    context: ssl.SSLContext
    not_after: dt.datetime


class CertificateCache:
    def __init__(self, config, restricted, metrics=None):
        self.metrics=metrics
        self.clock=time.monotonic
        self.utcnow=lambda:dt.datetime.now(dt.timezone.utc)
        self.ttl=86400;self.grace=300;self.renew_before=300
        self.lock=threading.RLock();self.pending={};self.worker=None;self.renew_task=None;self.stopping=False
        self.restricted = restricted
        self.portal_hosts = set(config['portal_hosts'])
        self.directory = Path(config['runtime_dir'])
        self.issuer = x509.load_pem_x509_certificate(Path(config['issuer_cert']).read_bytes())
        self.key = serialization.load_pem_private_key(Path(config['issuer_key']).read_bytes(), password=None)
        self.limit = 256
        self.cache = OrderedDict()
        self.context = server_context(config['portal_cert'], config['portal_key'])
        if config.get('public_portal'):
            self.context.load_verify_locations(cafile=config['gateway_client_ca'])
            self.context.verify_mode=ssl.CERT_OPTIONAL
        self.context.set_servername_callback(self.select)

    def select(self, ssl_object, server_name, initial_context):
        from .browser import origin
        if not server_name or server_name.lower() in self.portal_hosts:
            ssl_object.access_gate_sni = None
            return None
        try:
            name = origin('https://' + server_name)[8:]
            if not self.restricted(name): return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
            ssl_object.context = self.for_host(name)
            ssl_object.access_gate_sni = name
        except Exception:
            return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
        return None

    def for_host(self, name):
        lookup_start=self.clock()
        with self.lock:
            entry=self.cache.get(name)
            now=self.utcnow();age=self.clock()-entry.created if entry else None
            if entry and now<entry.not_after and age<self.ttl+self.grace:
                self.cache.move_to_end(name)
                if self.metrics:self.metrics.observe('certificate_hit',self.clock()-lookup_start)
                return entry.context
            if entry:self.cache.pop(name,None)
            if name in self.pending:raise ValueError('Certificate replacement is pending; retry shortly.')
            if self.metrics:self.metrics.observe('certificate_miss',self.clock()-lookup_start)
            with self.metrics.measure('certificate_generate') if self.metrics else nullcontext():
                context=self.generate(name)
            self.cache[name]=CacheEntry(self.clock(),context,context.access_gate_not_after)
            self.trim()
            return context

    def trim(self):
        while len(self.cache)>self.limit:
            self.cache.popitem(last=False)
            if self.metrics:self.metrics.increment('cache_eviction')

    def start(self):
        self.worker=ThreadPoolExecutor(max_workers=1,thread_name_prefix='gate-certificate')
        self.renew_task=asyncio.create_task(self.renew_loop())

    async def close(self):
        self.stopping=True
        if self.renew_task:
            self.renew_task.cancel()
            try:await self.renew_task
            except asyncio.CancelledError:pass
        if self.worker:
            await asyncio.to_thread(self.worker.shutdown,wait=True,cancel_futures=True)
        self.pending.clear();self.cache.clear()

    async def renew_loop(self):
        while True:
            await asyncio.sleep(60)
            await self.renew_due()

    async def renew_due(self):
        # One bounded worker; no unbounded task queue for a large imported list.
        for name,entry in list(self.cache.items()):
            if self.stopping:return
            age=self.clock()-entry.created
            if age>=self.ttl+self.grace or self.utcnow()>=entry.not_after:
                if self.cache.get(name) is entry:self.cache.pop(name,None)
                continue
            if age<self.ttl-self.renew_before or name in self.pending:continue
            # Policy must still manage the group; its actual SNI is checked separately.
            if not self.restricted(name):continue
            self.pending[name]=entry
            try:
                with self.metrics.measure('certificate_renew') if self.metrics else nullcontext():
                    context=await asyncio.get_running_loop().run_in_executor(self.worker,self.generate,name)
                if not self.stopping and self.cache.get(name) is entry:
                    self.cache[name]=CacheEntry(self.clock(),context,context.access_gate_not_after)
            except asyncio.CancelledError:raise
            except Exception:
                if self.metrics:self.metrics.increment('renew_error')
            finally:self.pending.pop(name,None)

    def generate(self,name):
        now=self.utcnow()
        if expires(self.issuer)<now+dt.timedelta(hours=48,minutes=5):
            raise ValueError('Gateway issuing CA has insufficient lifetime for a full 48-hour certificate; run the supported installer/update provisioning to renew it.')
        key = ec.generate_private_key(ec.SECP256R1())
        certificate = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Access Gate website')]))
            .issuer_name(self.issuer.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-dt.timedelta(minutes=5))
            .not_valid_after(now+dt.timedelta(hours=48))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()), critical=False)
            .sign(self.key, hashes.SHA256()))
        pem = (certificate.public_bytes(serialization.Encoding.PEM) + self.issuer.public_bytes(serialization.Encoding.PEM)
               + key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        # The private leaf key is loaded into OpenSSL and the temporary file is immediately removed.
        with tempfile.NamedTemporaryFile(dir=self.directory, prefix='leaf-', suffix='.pem') as handle:
            handle.write(pem); handle.flush()
            context = server_context(handle.name)
        context.access_gate_not_after=expires(certificate)
        return context
