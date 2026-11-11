"""Public-portal security state: gateway enrollment, bounded limits and MFA."""
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import struct
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


def private_address(value):
    ip=ipaddress.ip_address(value)
    ranges=('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','127.0.0.0/8') if ip.version==4 else ('fc00::/7','::1/128')
    return any(ip in ipaddress.ip_network(n) for n in ranges)


def totp(seed,counter,digits=6):
    digest=hmac.new(base64.b32decode(seed),struct.pack('!Q',counter),hashlib.sha1).digest()
    offset=digest[-1]&15
    return str((struct.unpack('!I',digest[offset:offset+4])[0]&0x7fffffff)%10**digits).zfill(digits)


class PublicSecurity:
    @staticmethod
    def initialize_public(db):
        db.execute('''CREATE TABLE IF NOT EXISTS remote_gateways(id TEXT PRIMARY KEY,name TEXT NOT NULL,fingerprint TEXT UNIQUE NOT NULL,
            key_hash TEXT NOT NULL,created REAL NOT NULL,expires REAL NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,activated INTEGER NOT NULL DEFAULT 0)''')
        db.execute('CREATE TABLE IF NOT EXISTS remote_sync_status(id INTEGER PRIMARY KEY CHECK(id=1),updated REAL NOT NULL)')
        db.execute('CREATE TABLE IF NOT EXISTS admin_mfa(id INTEGER PRIMARY KEY CHECK(id=1),seed BLOB NOT NULL,last_counter INTEGER NOT NULL)')
        db.execute('CREATE TABLE IF NOT EXISTS mfa_recovery(digest TEXT PRIMARY KEY)')
        db.execute('CREATE TABLE IF NOT EXISTS public_limits(scope TEXT NOT NULL,window INTEGER NOT NULL,count INTEGER NOT NULL,PRIMARY KEY(scope,window))')
        for table in ('gateway_entries','gateway_tokens','admin_site_tokens'):
            if 'gateway_id' not in {r['name'] for r in db.execute('PRAGMA table_info('+table+')')}:
                db.execute('ALTER TABLE '+table+' ADD COLUMN gateway_id TEXT')

    def peer_hash(self,key):
        return hmac.new(self.pepper,b'gateway-key:'+key.encode(),hashlib.sha256).hexdigest()

    def register_gateway(self,name,fingerprint,key,expires,now=None):
        from .core import GateError
        if not isinstance(name,str) or not 1<=len(name.strip())<=80 or any(ord(c)<32 for c in name):raise GateError('Use a gateway name of 1 to 80 characters.')
        gid=secrets.token_hex(16)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT count(*) FROM remote_gateways WHERE enabled=1').fetchone()[0]>=32:raise GateError('At most 32 enabled gateways are supported.')
            db.execute('INSERT INTO remote_gateways(id,name,fingerprint,key_hash,created,expires,enabled) VALUES(?,?,?,?,?,?,1)',(gid,name.strip(),fingerprint,self.peer_hash(key),time.time() if now is None else now,expires))
            self._event(db,'gateway.enrolled',actor='System',details=dict(reason=gid))
            db.commit()
        return gid

    def authenticate_gateway(self,fingerprint,key,now=None):
        if not isinstance(key,str) or len(key)!=64:return None
        now=time.time() if now is None else now
        with self.connect() as db:
            row=db.execute('SELECT * FROM remote_gateways WHERE fingerprint=? AND enabled=1 AND expires>?',(fingerprint,now)).fetchone()
            if not row or not hmac.compare_digest(self.peer_hash(key),row['key_hash']):return None
            return dict(row)

    def revoke_gateway(self,gid):
        with self.connect() as db:
            db.execute('UPDATE remote_gateways SET enabled=0 WHERE id=?',(gid,))
            self._event(db,'gateway.revoked',actor='System',details=dict(reason=gid))

    def public_limit(self,scope,limit,period=60,now=None):
        now=time.time() if now is None else now;window=int(now)//period
        digest=self.peer_hash(scope)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE');db.execute('DELETE FROM public_limits WHERE window<?',(window-2,))
            row=db.execute('SELECT count FROM public_limits WHERE scope=? AND window=?',(digest,window)).fetchone()
            if row and row['count']>=limit:return False
            db.execute('INSERT INTO public_limits VALUES(?,?,1) ON CONFLICT(scope,window) DO UPDATE SET count=count+1',(digest,window));db.commit()
        return True

    def mfa_enabled(self):
        with self.connect() as db:return bool(db.execute('SELECT 1 FROM admin_mfa').fetchone())

    def set_mfa(self,seed,proof,now=None):
        from .core import GateError
        now=time.time() if now is None else now;counter=int(now)//30
        if not any(hmac.compare_digest(totp(seed,c),proof) for c in (counter-1,counter,counter+1)):raise GateError('Authenticator confirmation failed.')
        key=hashlib.sha256(self.pepper+b'admin-mfa').digest();nonce=os.urandom(12)
        encrypted=nonce+AESGCM(key).encrypt(nonce,seed.encode(),b'admin-mfa-v1')
        recovery=[secrets.token_hex(8).upper() for _ in range(10)]
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE');db.execute('DELETE FROM admin_mfa');db.execute('DELETE FROM mfa_recovery')
            db.execute('INSERT INTO admin_mfa VALUES(1,?,?)',(encrypted,max(c for c in (counter-1,counter,counter+1) if hmac.compare_digest(totp(seed,c),proof))))
            db.executemany('INSERT INTO mfa_recovery VALUES(?)',[(self.peer_hash('recovery:'+code),) for code in recovery])
            db.execute('DELETE FROM admin_logins');db.execute('DELETE FROM push_subscriptions');self._event(db,'mfa.enrolled',actor='System');db.commit()
        return recovery

    def verify_mfa(self,value,now=None):
        if not isinstance(value,str) or len(value)>32:return False
        value=value.strip().replace(' ','');now=time.time() if now is None else now
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE');row=db.execute('SELECT * FROM admin_mfa WHERE id=1').fetchone()
            if not row:return False
            digest=self.peer_hash('recovery:'+value.upper())
            if db.execute('DELETE FROM mfa_recovery WHERE digest=?',(digest,)).rowcount:self._event(db,'mfa.recovery_used',actor='Administrator');db.commit();return True
            try:
                blob=row['seed'];key=hashlib.sha256(self.pepper+b'admin-mfa').digest()
                seed=AESGCM(key).decrypt(blob[:12],blob[12:],b'admin-mfa-v1').decode()
                for counter in (int(now)//30-1,int(now)//30,int(now)//30+1):
                    if counter>row['last_counter'] and hmac.compare_digest(totp(seed,counter),value):
                        db.execute('UPDATE admin_mfa SET last_counter=? WHERE id=1',(counter,));db.commit();return True
            except (ValueError,TypeError,InvalidTag):pass
        return False
