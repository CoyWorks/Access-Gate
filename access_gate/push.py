"""Opt-in, payload-free Web Push with a durable bounded delivery queue."""
import base64
import hashlib
import json
import re
import secrets
import ssl
import time
from urllib.parse import urlsplit
from urllib.request import Request,build_opener,ProxyHandler,HTTPSHandler,HTTPRedirectHandler
from urllib.error import HTTPError
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

PROVIDERS=frozenset(('fcm.googleapis.com','updates.push.services.mozilla.com','web.push.apple.com'))


def b64(value):return base64.urlsafe_b64encode(value).rstrip(b'=').decode()


def endpoint_url(value):
    from .core import GateError
    if not isinstance(value,str) or not 1<=len(value)<=2048 or any(ord(c)<=32 or ord(c)>126 for c in value):raise GateError('Invalid push subscription.')
    try:
        url=urlsplit(value)
        if url.scheme!='https' or url.hostname not in PROVIDERS or url.port not in (None,443) or url.username or url.password or url.fragment or not url.path.startswith('/') or url.path=='/':raise ValueError()
    except ValueError:raise GateError('This browser push provider is not supported. Use Chrome, Firefox or Safari.') from None
    return value


def authorization(private,endpoint,subject,now=None):
    now=time.time() if now is None else now;url=urlsplit(endpoint_url(endpoint))
    if not isinstance(subject,str) or len(subject)>512 or not subject.startswith(('https://','mailto:')):raise ValueError('Invalid VAPID contact URI.')
    key=serialization.load_pem_private_key(private,password=None)
    public=b64(key.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint))
    header=b64(b'{"typ":"JWT","alg":"ES256"}')
    payload=b64(json.dumps(dict(aud='https://'+url.hostname,exp=int(now)+3600,sub=subject),separators=(',',':')).encode())
    message=(header+'.'+payload).encode();r,s=decode_dss_signature(key.sign(message,ec.ECDSA(hashes.SHA256())))
    return 'vapid t='+message.decode()+'.'+b64(r.to_bytes(32,'big')+s.to_bytes(32,'big'))+', k='+public


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None


def send_push(endpoint,private,subject):
    endpoint=endpoint_url(endpoint)
    request=Request(endpoint,data=b'',method='POST',headers={
        'Authorization':authorization(private,endpoint,subject),'TTL':'300','Urgency':'normal','Topic':'access-gate-requests','Content-Length':'0'})
    # No request data, user fields, codes, domains or credentials leave the portal.
    opener=build_opener(ProxyHandler({}),HTTPSHandler(context=ssl.create_default_context()),NoRedirect())
    try:
        with opener.open(request,timeout=5) as response:return response.status
    except HTTPError as exc:
        status=exc.code;exc.close();return status


class Push:
    @staticmethod
    def initialize_push(db):
        for sql in (
            'CREATE TABLE IF NOT EXISTS push_settings(id INTEGER PRIMARY KEY CHECK(id=1),private_key BLOB NOT NULL,public_key TEXT NOT NULL)',
            '''CREATE TABLE IF NOT EXISTS push_subscriptions(id TEXT PRIMARY KEY,endpoint TEXT NOT NULL,endpoint_hash TEXT UNIQUE NOT NULL,
                browser_hash TEXT NOT NULL,login_id TEXT NOT NULL REFERENCES admin_logins(id) ON DELETE CASCADE,created REAL NOT NULL,
                last_sent REAL,last_error TEXT)''',
            '''CREATE TABLE IF NOT EXISTS push_deliveries(id TEXT PRIMARY KEY,subscription TEXT NOT NULL REFERENCES push_subscriptions(id) ON DELETE CASCADE,
                request_id TEXT REFERENCES access_requests(id) ON DELETE CASCADE,created REAL NOT NULL,available REAL NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,claim TEXT,claimed_until REAL,status TEXT NOT NULL DEFAULT 'queued',UNIQUE(subscription,request_id))''',
            'CREATE INDEX IF NOT EXISTS push_due ON push_deliveries(status,available)',
        ):db.execute(sql)
        if not db.execute('SELECT 1 FROM push_settings WHERE id=1').fetchone():
            key=ec.generate_private_key(ec.SECP256R1())
            private=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
            public=b64(key.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint))
            db.execute('INSERT INTO push_settings VALUES(1,?,?)',(private,public))

    def push_state(self,browser_token,config,now=None):
        now=time.time() if now is None else now;owner=self.browser_digest(browser_token)
        with self.connect() as db:
            version=self._admin_security(db,config)['version']
            devices=[dict(r) for r in db.execute('''SELECT s.id,s.created,s.last_sent,s.last_error FROM push_subscriptions s JOIN admin_logins l ON l.id=s.login_id
                WHERE s.browser_hash=? AND l.revoked=0 AND l.expires>? AND l.version=?''',(owner,now,version))]
            public=db.execute('SELECT public_key FROM push_settings WHERE id=1').fetchone()[0]
        return dict(public_key=public,devices=devices)

    def save_push(self,browser_token,login_id,endpoint,config,now=None):
        from .core import GateError
        now=time.time() if now is None else now;endpoint=endpoint_url(endpoint);owner=self.browser_digest(browser_token)
        digest=hashlib.sha256(endpoint.encode()).hexdigest()
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE');version=self._admin_security(db,config)['version']
            login=db.execute('SELECT 1 FROM admin_logins WHERE id=? AND browser_hash=? AND revoked=0 AND expires>? AND version=?',(login_id,owner,now,version)).fetchone()
            if not login:raise GateError('Sign in again before enabling notifications.')
            old=db.execute('SELECT id,browser_hash FROM push_subscriptions WHERE endpoint_hash=?',(digest,)).fetchone()
            if old and old['browser_hash']!=owner:raise GateError('This subscription belongs to a different browser identity. Disable notifications on this device and enable them again.')
            # Expired/revoked subscriptions cannot receive alerts, and are bounded/removed.
            db.execute('DELETE FROM push_subscriptions WHERE login_id IN(SELECT id FROM admin_logins WHERE revoked=1 OR expires<=? OR version!=?)',(now,version))
            old=db.execute('SELECT id FROM push_subscriptions WHERE endpoint_hash=?',(digest,)).fetchone()
            if old:
                db.execute('UPDATE push_subscriptions SET login_id=?,last_error=NULL WHERE id=?',(login_id,old['id']));sid=old['id']
            else:
                if db.execute('SELECT count(*) FROM push_subscriptions').fetchone()[0]>=32:raise GateError('At most 32 notification subscriptions are supported. Disable an old device first.')
                sid=secrets.token_hex(16)
                db.execute('INSERT INTO push_subscriptions(id,endpoint,endpoint_hash,browser_hash,login_id,created) VALUES(?,?,?,?,?,?)',(sid,endpoint,digest,owner,login_id,now))
            self._event(db,'push.enabled',now=now);db.commit()
        return sid

    def disable_push(self,browser_token):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE');db.execute('DELETE FROM push_subscriptions WHERE browser_hash=?',(self.browser_digest(browser_token),))
            self._event(db,'push.disabled');db.commit()

    @staticmethod
    def queue_request_push(db,request_id,now):
        for row in db.execute('''SELECT s.id FROM push_subscriptions s JOIN admin_logins l ON l.id=s.login_id
            WHERE l.revoked=0 AND l.expires>? LIMIT 32''',(now,)).fetchall():
            db.execute('INSERT OR IGNORE INTO push_deliveries(id,subscription,request_id,created,available) VALUES(?,?,?,?,?)',(secrets.token_hex(16),row['id'],request_id,now,now))

    def test_push(self,browser_token,config,now=None):
        from .core import GateError
        now=time.time() if now is None else now;devices=self.push_state(browser_token,config,now)['devices']
        if not devices:raise GateError('Enable notifications on this device first.')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            for device in devices:db.execute('INSERT INTO push_deliveries(id,subscription,created,available) VALUES(?,?,?,?)',(secrets.token_hex(16),device['id'],now,now))
            db.commit()

    def deliver_push(self,config,sender=send_push,now=None):
        live_clock=now is None
        now=time.time() if live_clock else now
        # Claim one delivery at a time. Expiry/policy are checked without renewing a login.
        for _ in range(10):
            if live_clock:now=time.time()
            claim=secrets.token_hex(16)
            with self.connect() as db:
                db.execute('BEGIN IMMEDIATE');version=self._admin_security(db,config)['version']
                db.execute('DELETE FROM push_subscriptions WHERE login_id IN(SELECT id FROM admin_logins WHERE revoked=1 OR expires<=? OR version!=?)',(now,version))
                db.execute("DELETE FROM push_deliveries WHERE created<?",(now-86400,))
                db.execute("UPDATE push_deliveries SET status='expired' WHERE status='queued' AND (created<=? OR (request_id IS NOT NULL AND request_id NOT IN(SELECT id FROM access_requests WHERE status='pending')))",(now-600,))
                row=db.execute('''SELECT d.*,s.endpoint FROM push_deliveries d JOIN push_subscriptions s ON s.id=d.subscription
                    WHERE d.status='queued' AND d.available<=? AND (d.claimed_until IS NULL OR d.claimed_until<=?) ORDER BY d.created LIMIT 1''',(now,now)).fetchone()
                if not row:db.commit();return
                private=db.execute('SELECT private_key FROM push_settings WHERE id=1').fetchone()[0]
                db.execute('UPDATE push_deliveries SET claim=?,claimed_until=?,attempts=attempts+1 WHERE id=?',(claim,now+60,row['id']));db.commit()
            try:code=sender(row['endpoint'],private,config.get('push_contact','https://github.com/CoyWorks/Access-Gate'))
            except Exception:code=0
            with self.connect() as db:
                db.execute('BEGIN IMMEDIATE')
                current=db.execute('SELECT attempts FROM push_deliveries WHERE id=? AND claim=?',(row['id'],claim)).fetchone()
                if not current:db.commit();continue
                if code in (404,410):db.execute('DELETE FROM push_subscriptions WHERE id=?',(row['subscription'],))
                elif 200<=code<300:
                    db.execute("UPDATE push_deliveries SET status='sent',claim=NULL,claimed_until=NULL WHERE id=?",(row['id'],))
                    db.execute('UPDATE push_subscriptions SET last_sent=?,last_error=NULL WHERE id=?',(now,row['subscription']))
                else:
                    retry=(code in (0,429) or 500<=code<600) and current['attempts']<3
                    db.execute('UPDATE push_deliveries SET status=?,available=?,claim=NULL,claimed_until=NULL WHERE id=?',('queued' if retry else 'failed',now+(15 if current['attempts']==1 else 60),row['id']))
                    db.execute('UPDATE push_subscriptions SET last_error=? WHERE id=?',('Temporary delivery error; retry pending.' if retry else 'Push provider rejected or could not accept this notification. Re-enable and test.',row['subscription']))
                db.commit()
