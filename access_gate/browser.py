"""Anonymous browser identity and one-time, origin-bound gateway handoffs."""
import hashlib
import hmac
import ipaddress
import re
import secrets
import time
from urllib.parse import urlsplit

TOKEN=re.compile(r'[a-f0-9]{64}')


def origin(value):
    from .core import GateError
    try:
        if not isinstance(value,str) or len(value)>300 or any(ord(c)<=32 for c in value): raise ValueError()
        url=urlsplit(value)
        host=(url.hostname or '').rstrip('.').encode('idna').decode('ascii').lower()
        if url.scheme!='https' or url.username or url.password or url.port not in (None,443) or url.path not in ('','/') or url.query or url.fragment: raise ValueError()
        if '.' not in host or len(host)>253 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in host.split('.')): raise ValueError()
        if host.endswith(('.local','.internal','.localhost')): raise ValueError()
        try: ipaddress.ip_address(host)
        except ValueError: return 'https://'+host
        raise ValueError()
    except (ValueError,UnicodeError):
        raise GateError('Use a public HTTPS hostname without credentials, a path or a query.')


class BrowserSessions:
    def browser_digest(self,token):
        from .core import GateError
        if not isinstance(token,str) or not TOKEN.fullmatch(token): raise GateError('Invalid browser session.')
        return hmac.new(self.pepper,b'browser:'+token.encode(),hashlib.sha256).hexdigest()

    def _legacy_token(self,ip):
        # Compatibility for Python callers only. The web/API never authorizes an IP alone.
        return hmac.new(self.pepper,('legacy:'+str(ipaddress.ip_address(ip))).encode(),hashlib.sha256).hexdigest()

    def initialize_browsers(self,db,version):
        if version<3:
            db.execute('ALTER TABLE grants RENAME TO grants_legacy_v03')
            db.execute('''CREATE TABLE grants(session_id TEXT PRIMARY KEY,ip TEXT NOT NULL,code TEXT NOT NULL REFERENCES codes(id),
                expires REAL NOT NULL,revoked INTEGER NOT NULL DEFAULT 0,started REAL,browser_hash TEXT)''')
            # IP-only/VPN-bound access cannot be assigned to an unknown browser after migration.
            db.execute('''INSERT INTO grants(session_id,ip,code,expires,revoked,started)
                SELECT session_id,ip,code,expires,1,started FROM grants_legacy_v03''')
            db.execute('PRAGMA user_version=3')
        for sql in (
            'CREATE UNIQUE INDEX IF NOT EXISTS grants_browser ON grants(browser_hash) WHERE browser_hash IS NOT NULL',
            'CREATE INDEX IF NOT EXISTS grants_current_code ON grants(code)',
            '''CREATE TABLE IF NOT EXISTS gateway_entries(id TEXT PRIMARY KEY,origin TEXT NOT NULL,nonce_hash TEXT NOT NULL,expires REAL NOT NULL,
                ticket_hash TEXT UNIQUE,session_id TEXT REFERENCES grants(session_id),ticket_expires REAL,used INTEGER NOT NULL DEFAULT 0)''',
            '''CREATE TABLE IF NOT EXISTS gateway_tokens(digest TEXT PRIMARY KEY,session_id TEXT NOT NULL REFERENCES grants(session_id) ON DELETE CASCADE,origin TEXT NOT NULL)''',
        ): db.execute(sql)

    def browser_grant(self,token,now=None):
        now=time.time() if now is None else now
        digest=self.browser_digest(token)
        with self.connect() as db:
            row=db.execute('''SELECT g.*,b.name AS batch_name FROM grants g JOIN codes c ON c.id=g.code JOIN batches b ON b.id=c.batch
                WHERE g.browser_hash=? AND g.expires>? AND g.revoked=0 AND c.revoked=0 AND b.revoked=0''',(digest,now)).fetchone()
            return dict(row) if row else None

    def new_entry(self,target,nonce,now=None,gateway_id=None):
        from .core import GateError
        now=time.time() if now is None else now
        target=origin(target)
        if not isinstance(nonce,str) or not TOKEN.fullmatch(nonce): raise GateError('The gateway must supply a random 32-byte browser challenge.')
        entry=secrets.token_hex(16)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('DELETE FROM gateway_entries WHERE expires<?',(now-300,))
            db.execute('INSERT INTO gateway_entries(id,origin,nonce_hash,expires,gateway_id) VALUES(?,?,?,?,?)',(entry,target,self.browser_digest(nonce),now+300,gateway_id))
            db.commit()
        return entry

    def entry(self,entry_id,now=None):
        from .core import GateError
        now=time.time() if now is None else now
        with self.connect() as db:
            row=db.execute('SELECT * FROM gateway_entries WHERE id=? AND expires>? AND used=0',(entry_id,now)).fetchone()
            if not row: raise GateError('The website request expired. Open the website again to request access.')
            return dict(row)

    def issue_handoff(self,entry_id,browser_token,now=None):
        from .core import GateError
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            now=time.time() if now is None else now
            entry=db.execute('SELECT * FROM gateway_entries WHERE id=? AND expires>? AND used=0',(entry_id,now)).fetchone()
            grant=db.execute('''SELECT g.* FROM grants g JOIN codes c ON c.id=g.code JOIN batches b ON b.id=c.batch
                WHERE g.browser_hash=? AND g.expires>? AND g.revoked=0 AND c.revoked=0 AND b.revoked=0''',(self.browser_digest(browser_token),now)).fetchone()
            if not entry or not grant: raise GateError('Active browser access and a valid website request are required.')
            ticket=secrets.token_hex(32)
            db.execute('UPDATE gateway_entries SET ticket_hash=?,session_id=?,ticket_expires=? WHERE id=?',
                       (self.browser_digest(ticket),grant['session_id'],min(now+60,entry['expires'],grant['expires']),entry_id))
            db.commit()
        return entry['origin'],ticket

    def accept_handoff(self,ticket,nonce,target,now=None,gateway_id=None):
        from .core import GateError
        target=origin(target)
        ticket_hash=self.browser_digest(ticket); nonce_hash=self.browser_digest(nonce)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            now=time.time() if now is None else now
            row=db.execute('''SELECT e.*,g.expires AS access_end FROM gateway_entries e JOIN grants g ON g.session_id=e.session_id
                JOIN codes c ON c.id=g.code JOIN batches b ON b.id=c.batch
                WHERE e.gateway_id IS ? AND e.ticket_hash=? AND e.nonce_hash=? AND e.origin=? AND e.used=0 AND e.expires>? AND e.ticket_expires>?
                AND g.expires>? AND g.revoked=0 AND c.revoked=0 AND b.revoked=0''',(gateway_id,ticket_hash,nonce_hash,target,now,now,now)).fetchone()
            if not row: raise GateError('The website handoff is invalid, expired or already used.')
            token=secrets.token_hex(32)
            db.execute('INSERT INTO gateway_tokens(digest,session_id,origin,gateway_id) VALUES(?,?,?,?)',(self.browser_digest(token),row['session_id'],target,gateway_id))
            db.execute('UPDATE gateway_entries SET used=1 WHERE id=?',(row['id'],))
            db.commit()
            return {'token':token,'expires':row['access_end'],'session_id':row['session_id']}

    def gateway_grant(self,token,target,now=None,gateway_id=None):
        now=time.time() if now is None else now
        target=origin(target); digest=self.browser_digest(token)
        with self.connect() as db:
            row=db.execute('''SELECT g.session_id,g.expires FROM gateway_tokens t JOIN grants g ON g.session_id=t.session_id
                JOIN codes c ON c.id=g.code JOIN batches b ON b.id=c.batch WHERE t.gateway_id IS ? AND t.digest=? AND t.origin=?
                AND g.expires>? AND g.revoked=0 AND c.revoked=0 AND b.revoked=0''',(gateway_id,digest,target,now)).fetchone()
            return dict(row) if row else None
