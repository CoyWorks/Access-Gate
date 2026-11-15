"""Independent integration identities; no browser or gateway privileges."""
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import time

SCOPES = ('batches:create',)
TOKEN = re.compile(r'ag_([a-f0-9]{16})_([A-Za-z0-9_-]{43})')


def networks(value):
    from .administration import management_networks
    return management_networks(value) if value.strip() else []


class Integrations:
    @staticmethod
    def initialize_integrations(db):
        db.execute('''CREATE TABLE IF NOT EXISTS api_credentials(
            id TEXT PRIMARY KEY,name TEXT NOT NULL,digest TEXT NOT NULL,scopes TEXT NOT NULL,
            networks TEXT NOT NULL,created REAL NOT NULL,expires REAL NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0,last_used REAL)''')
        db.execute('''CREATE TABLE IF NOT EXISTS api_policy(
            id INTEGER PRIMARY KEY CHECK(id=1),enabled INTEGER NOT NULL DEFAULT 0,
            networks TEXT NOT NULL DEFAULT '[]')''')
        db.execute('INSERT OR IGNORE INTO api_policy(id) VALUES(1)')

    def api_digest(self, token):
        return hmac.new(self.pepper,b'access-gate/integration/v1\0'+token.encode(),hashlib.sha256).hexdigest()

    def create_integration(self,name,scopes,days=90,cidrs='',now=None):
        from .core import GateError,positive_int
        now=time.time() if now is None else now
        if not isinstance(name,str) or not 1<=len(name.strip())<=80 or any(ord(c)<32 for c in name):
            raise GateError('Enter an integration name of 1–80 characters without controls.')
        if not scopes or len(scopes)!=len(set(scopes)) or any(s not in SCOPES for s in scopes):
            raise GateError('Choose valid integration scopes.')
        days=positive_int(days,'Credential lifetime in days',365)
        allowed=networks(cidrs)
        identity=secrets.token_hex(8)
        token='ag_'+identity+'_'+secrets.token_urlsafe(32)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT count(*) FROM api_credentials').fetchone()[0]>=1000:
                raise GateError('Integration credential capacity reached. Reuse existing integrations or contact local maintenance.')
            db.execute('INSERT INTO api_credentials(id,name,digest,scopes,networks,created,expires) VALUES(?,?,?,?,?,?,?)',
                       (identity,name.strip(),self.api_digest(token),json.dumps(scopes),json.dumps(allowed),now,now+days*86400))
            self._event(db,'integration.created',details=dict(reason=identity),now=now)
            db.commit()
        return identity,token

    def integration_list(self):
        with self.connect() as db:
            return [dict(r) for r in db.execute('SELECT id,name,scopes,networks,created,expires,revoked,last_used FROM api_credentials ORDER BY created DESC,id DESC')]

    def revoke_integration(self,identity):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            changed=db.execute('UPDATE api_credentials SET revoked=1 WHERE id=? AND revoked=0',(identity,)).rowcount
            if changed:self._event(db,'integration.revoked',details=dict(reason=identity))
            db.commit()

    def authenticate_integration(self,token,address,now=None):
        now=time.time() if now is None else now
        match=TOKEN.fullmatch(token)
        if not match:return None
        with self.connect() as db:
            row=db.execute('SELECT * FROM api_credentials WHERE id=?',(match[1],)).fetchone()
            expected=row['digest'] if row else '0'*64
            valid=hmac.compare_digest(self.api_digest(token),expected)
            if not row or not valid or row['revoked'] or row['expires']<=now:return None
            result=dict(row);result.pop('digest')
            result['scopes']=json.loads(result['scopes'])
            result['networks']=json.loads(result['networks'])
            result['source_allowed']=not result['networks'] or any(ipaddress.ip_address(address) in ipaddress.ip_network(n) for n in result['networks'])
            if result['source_allowed']:
                db.execute('UPDATE api_credentials SET last_used=? WHERE id=? AND (last_used IS NULL OR last_used<?)',(now,row['id'],now-60))
            return result

    def api_policy(self):
        with self.connect() as db:
            row=dict(db.execute('SELECT * FROM api_policy WHERE id=1').fetchone())
        row['networks']=json.loads(row['networks'])
        return row
