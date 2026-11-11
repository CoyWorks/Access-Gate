"""Live CIDR exclusions and revocable, sliding administrator browser sessions."""
import hashlib
import hmac
import ipaddress
import json
import secrets
import time
from .browser import TOKEN,origin

ADMIN_IDLE_SECONDS=7*86400


def exclusion_networks(value):
    from .core import GateError
    if not isinstance(value,str) or len(value)>4096: raise GateError('Enter at most 64 exclusion networks.')
    parts=value.replace(',',' ').split()
    if len(parts)>64: raise GateError('Enter at most 64 exclusion networks.')
    try:
        # Require network-aligned CIDRs so a mistyped /24 cannot silently expand access.
        return list(dict.fromkeys(str(ipaddress.ip_network(p,strict=True)) for p in parts))
    except ValueError: raise GateError('Use valid network-aligned CIDRs such as 192.168.20.20/32 or 192.168.20.0/24.')


class Exclusions:
    @staticmethod
    def initialize_exclusions(db):
        columns={r['name'] for r in db.execute('PRAGMA table_info(administrator_policy)')}
        if 'exclusions' not in columns: db.execute("ALTER TABLE administrator_policy ADD COLUMN exclusions TEXT NOT NULL DEFAULT '[]'")
        for sql in (
            '''CREATE TABLE IF NOT EXISTS admin_logins(id TEXT PRIMARY KEY,token_hash TEXT UNIQUE NOT NULL,
                browser_hash TEXT NOT NULL,version TEXT NOT NULL,expires REAL NOT NULL,last_seen REAL NOT NULL,
                created REAL NOT NULL,revoked INTEGER NOT NULL DEFAULT 0)''',
            'CREATE INDEX IF NOT EXISTS admin_login_browser ON admin_logins(browser_hash)',
            '''CREATE TABLE IF NOT EXISTS admin_handoffs(ticket_hash TEXT PRIMARY KEY,entry_id TEXT UNIQUE NOT NULL REFERENCES gateway_entries(id) ON DELETE CASCADE,
                login_id TEXT NOT NULL REFERENCES admin_logins(id) ON DELETE CASCADE,expires REAL NOT NULL)''',
            '''CREATE TABLE IF NOT EXISTS admin_site_tokens(digest TEXT PRIMARY KEY,
                login_id TEXT NOT NULL REFERENCES admin_logins(id) ON DELETE CASCADE,origin TEXT NOT NULL)''',
        ):db.execute(sql)

    def admin_login_digest(self,token):
        from .core import GateError
        if not isinstance(token,str) or not TOKEN.fullmatch(token):raise GateError('Invalid administrator login.')
        return hmac.new(self.pepper,b'admin-login:'+token.encode(),hashlib.sha256).hexdigest()

    def ip_excluded(self,address,config):
        try: ip=ipaddress.ip_address(address)
        except (ValueError,TypeError):return False
        return any(ip in ipaddress.ip_network(n) for n in self.admin_security(config)['exclusions'])

    def new_admin_login(self,browser_token,config,expected_version=None,now=None):
        from .core import GateError
        now=time.time() if now is None else now
        token=secrets.token_hex(32);login_id=secrets.token_hex(16)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            security=self._admin_security(db,config)
            if expected_version is not None and expected_version!=security['version']:raise GateError('Administrator settings changed. Sign in again.')
            # A new login in this browser invalidates its previous site proofs.
            db.execute('UPDATE admin_logins SET revoked=1 WHERE browser_hash=?',(self.browser_digest(browser_token),))
            db.execute('DELETE FROM admin_logins WHERE expires<=?',(now,))
            db.execute('INSERT INTO admin_logins(id,token_hash,browser_hash,version,expires,last_seen,created) VALUES(?,?,?,?,?,?,?)',
                (login_id,self.admin_login_digest(token),self.browser_digest(browser_token),security['version'],now+ADMIN_IDLE_SECONDS,now,now))
            db.commit()
        return token,dict(id=login_id,expires=now+ADMIN_IDLE_SECONDS)

    def admin_login(self,token,browser_token,config,touch=False,now=None):
        now=time.time() if now is None else now
        try:digest=self.admin_login_digest(token);browser_hash=self.browser_digest(browser_token)
        except ValueError:return None
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE' if touch else 'BEGIN')
            version=self._admin_security(db,config)['version']
            row=db.execute('SELECT id,expires FROM admin_logins WHERE token_hash=? AND browser_hash=? AND version=? AND revoked=0 AND expires>?',(digest,browser_hash,version,now)).fetchone()
            if not row:return None
            end=max(row['expires'],now+ADMIN_IDLE_SECONDS) if touch else row['expires']
            if touch:db.execute('UPDATE admin_logins SET expires=?,last_seen=? WHERE id=?',(end,now,row['id']))
            db.commit()
        return dict(id=row['id'],expires=end)

    def end_admin_login(self,token,browser_token):
        try:digest=self.admin_login_digest(token);browser_hash=self.browser_digest(browser_token)
        except ValueError:return
        with self.connect() as db:
            db.execute('UPDATE admin_logins SET revoked=1 WHERE token_hash=? AND browser_hash=?',(digest,browser_hash))

    def issue_admin_handoff(self,entry_id,login_id,config,now=None):
        from .core import GateError
        now=time.time() if now is None else now
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            version=self._admin_security(db,config)['version']
            entry=db.execute('SELECT * FROM gateway_entries WHERE id=? AND used=0 AND expires>?',(entry_id,now)).fetchone()
            login=db.execute('SELECT * FROM admin_logins WHERE id=? AND version=? AND revoked=0 AND expires>?',(login_id,version,now)).fetchone()
            if not entry or not login:raise GateError('An active administrator login and website request are required.')
            ticket=secrets.token_hex(32)
            db.execute('DELETE FROM admin_handoffs WHERE entry_id=?',(entry_id,))
            db.execute('INSERT INTO admin_handoffs VALUES(?,?,?,?)',(self.browser_digest(ticket),entry_id,login_id,min(now+60,entry['expires'],login['expires'])))
            db.commit()
        return entry['origin'],ticket

    def accept_admin_handoff(self,ticket,nonce,target,config,now=None,gateway_id=None):
        from .core import GateError
        now=time.time() if now is None else now
        target=origin(target);digest=self.browser_digest(ticket)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if not db.execute('SELECT 1 FROM admin_handoffs WHERE ticket_hash=?',(digest,)).fetchone():return None
            version=self._admin_security(db,config)['version']
            row=db.execute('''SELECT l.id,l.expires FROM admin_handoffs h JOIN gateway_entries e ON e.id=h.entry_id JOIN admin_logins l ON l.id=h.login_id
                WHERE e.gateway_id IS ? AND h.ticket_hash=? AND h.expires>? AND e.expires>? AND e.used=0 AND e.nonce_hash=? AND e.origin=?
                AND l.version=? AND l.revoked=0 AND l.expires>?''',(gateway_id,digest,now,now,self.browser_digest(nonce),target,version,now)).fetchone()
            if not row:raise GateError('The administrator website handoff is invalid, expired or already used.')
            token=secrets.token_hex(32)
            db.execute('INSERT INTO admin_site_tokens(digest,login_id,origin,gateway_id) VALUES(?,?,?,?)',(self.browser_digest(token),row['id'],target,gateway_id))
            db.execute('UPDATE gateway_entries SET used=1 WHERE id=(SELECT entry_id FROM admin_handoffs WHERE ticket_hash=?)',(digest,))
            db.commit()
        return dict(token=token,expires=row['expires'],session_id='admin:'+row['id'],kind='admin')

    def admin_site_grant(self,token,target,config,activity=False,now=None,gateway_id=None):
        now=time.time() if now is None else now
        target=origin(target);digest=self.browser_digest(token)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE' if activity else 'BEGIN')
            version=self._admin_security(db,config)['version']
            row=db.execute('''SELECT l.id,l.expires FROM admin_site_tokens t JOIN admin_logins l ON l.id=t.login_id
                WHERE t.gateway_id IS ? AND t.digest=? AND t.origin=? AND l.version=? AND l.revoked=0 AND l.expires>?''',(gateway_id,digest,target,version,now)).fetchone()
            if not row:return None
            end=max(row['expires'],now+ADMIN_IDLE_SECONDS) if activity else row['expires']
            if activity:db.execute('UPDATE admin_logins SET expires=?,last_seen=? WHERE id=?',(end,now,row['id']))
            db.commit()
        return dict(expires=end,session_id='admin:'+row['id'],kind='admin')
