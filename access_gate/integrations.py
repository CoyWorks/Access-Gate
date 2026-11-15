"""Independent integration identities; no browser or gateway privileges."""
import hashlib
import base64
import hmac
import ipaddress
import json
import re
import secrets
import time

SCOPES = ('batches:create','batches:read','batches:revoke')
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
        db.execute('CREATE TABLE IF NOT EXISTS api_limits(scope TEXT PRIMARY KEY,expires REAL NOT NULL,value INTEGER NOT NULL)')
        db.execute('''CREATE TABLE IF NOT EXISTS api_audit(id INTEGER PRIMARY KEY AUTOINCREMENT,
            created REAL NOT NULL,credential_id TEXT,action TEXT NOT NULL,batch_id TEXT,request_id TEXT NOT NULL,source TEXT NOT NULL,outcome INTEGER NOT NULL)''')

    def save_api_policy(self,enabled,cidrs):
        from .core import GateError
        allowed=networks(cidrs)
        if enabled and not allowed:raise GateError('Choose API source networks before enabling API access.')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('UPDATE api_policy SET enabled=?,networks=? WHERE id=1',(bool(enabled),json.dumps(allowed)))
            self._event(db,'integration.policy',details=dict(state='enabled' if enabled else 'disabled'))
            db.commit()

    @staticmethod
    def _api_limit(db,scope,limit,window,amount,now):
        row=db.execute('SELECT * FROM api_limits WHERE scope=?',(scope,)).fetchone()
        if row and row['expires']>now:
            if row['value']+amount>limit:return False
            db.execute('UPDATE api_limits SET value=value+? WHERE scope=?',(amount,scope))
        else:
            if not row and db.execute('SELECT count(*) FROM api_limits').fetchone()[0]>=4096:return False
            db.execute('INSERT OR REPLACE INTO api_limits VALUES(?,?,?)',(scope,now+window,amount))
        return True

    def api_request_budget(self,address,credential=None):
        now=time.time()
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('DELETE FROM api_limits WHERE expires<=?',(now,))
            if credential:allowed=self._api_limit(db,'credential-request:'+credential,120,60,1,now)
            else:
                allowed=self._api_limit(db,'global-request',600,60,1,now)
                if allowed:allowed=self._api_limit(db,'source:'+hashlib.sha256(address.encode()).hexdigest(),60,60,1,now)
            db.commit()
            return allowed

    @staticmethod
    def _api_audit(db,credential,action,batch,request_id,source,status,now):
        db.execute('INSERT INTO api_audit(created,credential_id,action,batch_id,request_id,source,outcome) VALUES(?,?,?,?,?,?,?)',
                   (now,credential,action,batch,request_id,source,status))
        db.execute('DELETE FROM api_audit WHERE created<?',(now-30*86400,))
        db.execute('DELETE FROM api_audit WHERE id<(SELECT id FROM api_audit ORDER BY id DESC LIMIT 1 OFFSET 9999)')

    def api_audit(self,credential,action,batch,request_id,source,status):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            self._api_audit(db,credential,action,batch,request_id,source,status,time.time())
            db.commit()

    def api_audit_list(self):
        with self.connect() as db:return [dict(r) for r in db.execute('SELECT * FROM api_audit ORDER BY id DESC LIMIT 100')]

    def api_summary(self):
        with self.connect() as db:
            enabled=bool(db.execute('SELECT enabled FROM api_policy WHERE id=1').fetchone()[0])
            count=db.execute('SELECT count(*) FROM api_credentials WHERE revoked=0 AND expires>?',(time.time(),)).fetchone()[0]
        return dict(enabled=enabled,active_credentials=count)

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

    def _api_authorize(self,db,credential,address,scope,now):
        from .rest_api import APIError
        policy=db.execute('SELECT * FROM api_policy WHERE id=1').fetchone()
        if not policy['enabled'] or not any(ipaddress.ip_address(address) in ipaddress.ip_network(n) for n in json.loads(policy['networks'])):
            raise APIError(403,'forbidden','This source is not permitted.')
        current=db.execute('SELECT * FROM api_credentials WHERE id=?',(credential,)).fetchone()
        if not current or current['revoked'] or current['expires']<=now:raise APIError(401,'unauthorized','A valid integration credential is required.')
        if scope not in json.loads(current['scopes']):raise APIError(403,'forbidden','This operation is not permitted.')
        cidrs=json.loads(current['networks'])
        if cidrs and not any(ipaddress.ip_address(address) in ipaddress.ip_network(n) for n in cidrs):raise APIError(403,'forbidden','This source is not permitted.')

    def api_create_batch(self,credential,address,key,values,request_id=None):
        from .core import GateError,TZ
        from .rest_api import APIError
        import datetime as dt
        fingerprint=hashlib.sha256(json.dumps(values,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        key_hash=hashlib.sha256(key.encode()).hexdigest()
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            now=time.time()
            self._api_authorize(db,credential,address,'batches:create',now)
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
            if not self._api_limit(db,'global-code',10000,3600,values['count'],now) or not self._api_limit(db,'credential-code:'+credential,1000,3600,values['count'],now):
                raise APIError(429,'rate_limited','The new-code budget was reached.')
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
            self._api_audit(db,credential,'create',batch,request_id or secrets.token_hex(16),address,201,now)
            db.commit()
        return response,False

    def api_cipher(self):
        from cryptography.fernet import Fernet
        key=hmac.new(self.pepper,b'access-gate/api-replay/v1',hashlib.sha256).digest()
        return Fernet(base64.urlsafe_b64encode(key))

    def _api_cursor(self,context,created,identity):
        raw=json.dumps([*context,created,identity],separators=(',',':')).encode()
        payload=base64.urlsafe_b64encode(raw).rstrip(b'=')
        signature=hmac.new(self.pepper,b'access-gate/api-cursor/v1\0'+payload,hashlib.sha256).digest()
        return (payload+b'.'+base64.urlsafe_b64encode(signature).rstrip(b'=')).decode()

    def _api_cursor_read(self,value,context):
        from .rest_api import APIError
        if value is None:return None
        try:
            if not 1<=len(value)<=256:raise ValueError()
            payload,signature=value.encode().split(b'.')
            expected=hmac.new(self.pepper,b'access-gate/api-cursor/v1\0'+payload,hashlib.sha256).digest()
            if not hmac.compare_digest(base64.urlsafe_b64decode(signature+b'='*(-len(signature)%4)),expected):raise ValueError()
            decoded=json.loads(base64.urlsafe_b64decode(payload+b'='*(-len(payload)%4)))
            if decoded[:-2]!=list(context) or type(decoded[-2]) not in (int,float) or not re.fullmatch('[a-f0-9]{16}',decoded[-1]):raise ValueError()
            return decoded[-2],decoded[-1]
        except (ValueError,TypeError,IndexError,UnicodeError):raise APIError(400,'invalid_request','Invalid cursor for this collection.')

    @staticmethod
    def _api_batch(row):
        return dict(batch_id=row['id'],name=row['name'],count=row['total'],created_at=utc(row['created']),valid_from=utc(row['starts']),
                    valid_until=utc(row['ends']),access_seconds=row['access_seconds'],revoked=bool(row['revoked']),removed=row['removed_at'] is not None,
                    counts={key:int(row[key+'_count'] or 0) for key in ('unused','redeemed','revoked','expired','future','cleared','active')})

    def api_lifecycle(self,credential,address,kind,batch=None,code=None,page_size=25,cursor=None,request_id=None):
        from .core import STATUS_SQL
        from .rest_api import APIError
        mutation=kind=='revoke'
        scope='batches:revoke' if mutation else 'batches:read'
        context=(credential,'codes' if kind=='codes' else 'batches',batch,page_size)
        after=self._api_cursor_read(cursor,context)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE' if mutation else 'BEGIN')
            now=time.time();self._api_authorize(db,credential,address,scope,now)
            if code:
                owned=db.execute('SELECT c.batch FROM codes c JOIN api_batches a ON a.batch_id=c.batch WHERE c.id=? AND a.credential_id=?',(code,credential)).fetchone()
                if not owned:raise APIError(404,'not_found','The requested API resource was not found.')
                batch=owned['batch']
            if batch and not db.execute('SELECT 1 FROM api_batches WHERE batch_id=? AND credential_id=?',(batch,credential)).fetchone():
                raise APIError(404,'not_found','The requested API resource was not found.')
            if mutation:
                if code:self._revoke_code(db,code)
                else:self._revoke_batch(db,batch,now)
                self._api_audit(db,credential,'revoke',batch,request_id or secrets.token_hex(16),address,200,now)
                db.commit()
                return dict(code_id=code,revoked=True) if code else dict(batch_id=batch,revoked=True)
            values=dict(now=now,owner=credential,limit=page_size+1,batch=batch)
            if kind=='codes':
                sql='SELECT c.id,c.hint,c.used,c.cleared_at,b.created AS cursor_created,'+STATUS_SQL+''' AS status,
                    EXISTS(SELECT 1 FROM grants g WHERE g.code=c.id AND g.revoked=0 AND g.expires>:now AND c.revoked=0 AND b.revoked=0) AS active
                    FROM codes c JOIN batches b ON b.id=c.batch JOIN api_batches a ON a.batch_id=b.id
                    WHERE a.credential_id=:owner AND b.id=:batch'''
                if after:
                    sql+=' AND c.id<:after_id';values['after_id']=after[1]
                rows=db.execute(sql+' ORDER BY c.id DESC LIMIT :limit',values).fetchall()
                items=[dict(id=r['id'],hint=r['hint'],status=r['status'],redeemed_at=utc(r['used']) if r['used'] is not None else None,cleared=r['cleared_at'] is not None,active=bool(r['active'])) for r in rows[:page_size]]
            else:
                sql=self._batch_query()+' JOIN api_batches a ON a.batch_id=b.id WHERE a.credential_id=:owner'
                if batch:sql+=' AND b.id=:batch'
                if after:
                    sql+=' AND (b.created<:after_time OR (b.created=:after_time AND b.id<:after_id))'
                    values.update(after_time=after[0],after_id=after[1])
                rows=db.execute(sql+' GROUP BY b.id ORDER BY b.created DESC,b.id DESC LIMIT :limit',values).fetchall()
                items=[self._api_batch(r) for r in rows[:page_size]]
            if kind=='detail':return dict(batch=items[0])
            next_cursor=None
            if len(rows)>page_size:
                last=rows[page_size-1]
                next_cursor=self._api_cursor(context,last['cursor_created'] if kind=='codes' else last['created'],last['id'])
            return dict(items=items,next_cursor=next_cursor)

    @staticmethod
    def _cleanup_api(db,now):
        db.execute('UPDATE api_requests SET payload=NULL WHERE rowid IN(SELECT rowid FROM api_requests WHERE created<=? AND payload IS NOT NULL LIMIT 5000)',(now-86400,))
        db.execute('DELETE FROM api_requests WHERE rowid IN(SELECT rowid FROM api_requests WHERE created<=? LIMIT 5000)',(now-30*86400,))
        db.execute('DELETE FROM api_limits WHERE expires<=?',(now,))
        db.execute('DELETE FROM api_audit WHERE created<?',(now-30*86400,))


def utc(stamp):
    import datetime as dt
    return dt.datetime.fromtimestamp(stamp,dt.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00','Z')
