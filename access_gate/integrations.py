"""Independent integration identities; no browser or gateway privileges."""
import hashlib
import base64
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
        db.execute('''CREATE TABLE IF NOT EXISTS api_batches(
            batch_id TEXT PRIMARY KEY REFERENCES batches(id),credential_id TEXT NOT NULL REFERENCES api_credentials(id),created REAL NOT NULL)''')
        db.execute('''CREATE TABLE IF NOT EXISTS api_requests(
            credential_id TEXT NOT NULL REFERENCES api_credentials(id),key_hash TEXT NOT NULL,
            fingerprint TEXT NOT NULL,batch_id TEXT NOT NULL,created REAL NOT NULL,payload BLOB,
            PRIMARY KEY(credential_id,key_hash))''')

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

    def api_origin(self,batch):
        with self.connect() as db:
            row=db.execute('SELECT credential_id FROM api_batches WHERE batch_id=?',(batch,)).fetchone()
        return row['credential_id'] if row else None

    def api_create_batch(self,credential,address,key,values):
        from .core import GateError,TZ
        from .rest_api import APIError
        import datetime as dt
        fingerprint=hashlib.sha256(json.dumps(values,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        key_hash=hashlib.sha256(key.encode()).hexdigest()
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            now=time.time()
            current=db.execute('SELECT * FROM api_credentials WHERE id=?',(credential,)).fetchone()
            if not current or current['revoked'] or current['expires']<=now:raise APIError(401,'unauthorized','A valid integration credential is required.')
            if 'batches:create' not in json.loads(current['scopes']):raise APIError(403,'forbidden','This operation is not permitted.')
            self._cleanup_api(db,now)
            existing=db.execute('SELECT * FROM api_requests WHERE credential_id=? AND key_hash=?',(credential,key_hash)).fetchone()
            if existing:
                if existing['fingerprint']!=fingerprint:raise APIError(409,'idempotency_conflict','This key was used with a different request.')
                if now>=existing['created']+86400:raise APIError(409,'replay_expired','The original codes are no longer available for replay.',batch_id=existing['batch_id'])
                try:
                    saved=json.loads(self.api_cipher().decrypt(existing['payload']))
                    if (saved['credential'],saved['key'],saved['fingerprint'])!=(credential,key_hash,fingerprint):raise ValueError()
                    response=saved['response']
                except Exception:raise APIError(503,'service_unavailable','The saved response is temporarily unavailable.')
                db.commit()
                return response,True
            if db.execute('SELECT count(*) FROM api_requests').fetchone()[0]>=50000:
                raise APIError(503,'service_unavailable','API retry-record capacity is temporarily exhausted.')
            batch,codes=self._insert_batch(db,now,now+values['validity_seconds'],values['access_seconds'],values['count'],values['name'],'duration',now,dt.datetime.fromtimestamp(now,TZ).date().isoformat())
            db.execute('INSERT INTO api_batches VALUES(?,?,?)',(batch,credential,now))
            db.execute('INSERT INTO api_requests VALUES(?,?,?,?,?,NULL)',(credential,key_hash,fingerprint,batch,now))
            rows=db.execute('SELECT id,digest FROM codes WHERE batch=?',(batch,)).fetchall()
            ids={r['digest']:r['id'] for r in rows}
            name=db.execute('SELECT name FROM batches WHERE id=?',(batch,)).fetchone()[0]
            response=dict(batch_id=batch,name=name,count=len(codes),created_at=utc(now),valid_from=utc(now),valid_until=utc(now+values['validity_seconds']),
                    validity_seconds=values['validity_seconds'],access_seconds=values['access_seconds'],
                    replay_until=utc(now+86400),key_retained_until=utc(now+30*86400),codes=[dict(id=ids[self.digest(c)],code=c) for c in codes])
            saved=dict(credential=credential,key=key_hash,fingerprint=fingerprint,response=response)
            payload=self.api_cipher().encrypt(json.dumps(saved,separators=(',',':')).encode())
            db.execute('UPDATE api_requests SET payload=? WHERE credential_id=? AND key_hash=?',(payload,credential,key_hash))
            db.commit()
        return response,False

    def api_cipher(self):
        from cryptography.fernet import Fernet
        key=hmac.new(self.pepper,b'access-gate/api-replay/v1',hashlib.sha256).digest()
        return Fernet(base64.urlsafe_b64encode(key))

    @staticmethod
    def _cleanup_api(db,now):
        db.execute('UPDATE api_requests SET payload=NULL WHERE rowid IN(SELECT rowid FROM api_requests WHERE created<=? AND payload IS NOT NULL LIMIT 5000)',(now-86400,))
        db.execute('DELETE FROM api_requests WHERE rowid IN(SELECT rowid FROM api_requests WHERE created<=? LIMIT 5000)',(now-30*86400,))


def utc(stamp):
    import datetime as dt
    return dt.datetime.fromtimestamp(stamp,dt.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00','Z')
