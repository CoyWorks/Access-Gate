import datetime as dt
import hashlib
import hmac
import ipaddress
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from zoneinfo import ZoneInfo

TZ = ZoneInfo('Europe/Amsterdam')
ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ'
SCHEMA_VERSION = 2
STATUSES = ('unused', 'redeemed', 'revoked', 'expired', 'future')
STATUS_SQL = "CASE WHEN c.revoked=1 THEN 'revoked' WHEN c.used IS NOT NULL THEN 'redeemed' WHEN b.ends<=:now THEN 'expired' WHEN b.starts>:now THEN 'future' ELSE 'unused' END"


class GateError(ValueError):
    pass


def positive_int(value, label, maximum):
    if isinstance(value, bool) or not re.fullmatch(r'[0-9]+', str(value)):
        raise GateError(f'{label} must be a positive whole number.')
    digits = str(value).lstrip('0') or '0'
    if len(digits) > len(str(maximum)):
        raise GateError(f'{label} must be between 1 and {maximum}.')
    number = int(digits)
    if not 1 <= number <= maximum:
        raise GateError(f'{label} must be between 1 and {maximum}.')
    return number


def duration_seconds(value, unit, kind):
    units = {'hours': 3600, 'days': 86400} if kind == 'validity' else {'minutes': 60, 'hours': 3600}
    if unit not in units:
        raise GateError('Invalid duration unit.')
    maximum = 365*86400 if kind == 'validity' else 7*86400
    return positive_int(value, 'Duration', maximum // units[unit]) * units[unit]


def status_of(code, now):
    if code['revoked']: return 'revoked'
    if code['used'] is not None: return 'redeemed'
    if code['ends'] <= now: return 'expired'
    if code['starts'] > now: return 'future'
    return 'unused'


from .operations import Operations


class Store(Operations):
    def __init__(self, path, pepper):
        self.path, self.pepper = str(path), pepper.encode()

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        db.execute('PRAGMA busy_timeout=10000')
        try:
            yield db
        finally:
            if db.in_transaction: db.rollback()
            db.close()

    def initialize(self):
        """Transactional, versioned upgrade of legacy databases; never replace code digests."""
        with self.connect() as db:
            version = db.execute('PRAGMA user_version').fetchone()[0]
            if version > SCHEMA_VERSION:
                raise GateError('This database requires a newer Access Gate version.')
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('BEGIN IMMEDIATE')
            version = db.execute('PRAGMA user_version').fetchone()[0]
            if version > SCHEMA_VERSION:
                raise GateError('This database requires a newer Access Gate version.')
            for statement in (
                'CREATE TABLE IF NOT EXISTS batches(id TEXT PRIMARY KEY, week TEXT NOT NULL, starts REAL NOT NULL, ends REAL NOT NULL, minutes INTEGER NOT NULL, created REAL NOT NULL)',
                'CREATE TABLE IF NOT EXISTS codes(id TEXT PRIMARY KEY, batch TEXT NOT NULL REFERENCES batches(id), digest TEXT UNIQUE NOT NULL, hint TEXT NOT NULL, used REAL, used_ip TEXT, revoked INTEGER NOT NULL DEFAULT 0)',
                'CREATE TABLE IF NOT EXISTS grants(ip TEXT PRIMARY KEY, code TEXT NOT NULL REFERENCES codes(id), expires REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0)',
                'CREATE TABLE IF NOT EXISTS attempts(scope TEXT NOT NULL, stamp REAL NOT NULL)',
                'CREATE INDEX IF NOT EXISTS attempts_scope ON attempts(scope,stamp)',
            ): db.execute(statement)
            if version < 1:
                additions = {
                    'batches': [('name', "TEXT NOT NULL DEFAULT ''"), ('access_seconds', 'INTEGER'), ('validity_seconds', 'INTEGER'), ('timing_mode', "TEXT NOT NULL DEFAULT 'legacy-week'"), ('revoked', 'INTEGER NOT NULL DEFAULT 0')],
                    'codes': [('cleared_at', 'REAL')],
                    'grants': [('started', 'REAL'), ('session_id', 'TEXT')],
                }
                for table, columns in additions.items():
                    existing = {r['name'] for r in db.execute(f'PRAGMA table_info({table})')}
                    for name, declaration in columns:
                        if name not in existing: db.execute(f'ALTER TABLE {table} ADD COLUMN {name} {declaration}')
                db.execute('UPDATE batches SET access_seconds=minutes*60 WHERE access_seconds IS NULL')
                db.execute('UPDATE batches SET validity_seconds=CAST(ends-starts AS INTEGER) WHERE validity_seconds IS NULL')
                db.execute("UPDATE batches SET name='Week starting '||week WHERE name=''")
                db.execute('UPDATE grants SET started=(SELECT used FROM codes WHERE codes.id=grants.code) WHERE started IS NULL')
                for r in db.execute('SELECT ip FROM grants WHERE session_id IS NULL').fetchall():
                    db.execute('UPDATE grants SET session_id=? WHERE ip=?', (secrets.token_hex(16),r['ip']))
                db.execute('PRAGMA user_version=1')
            db.execute('CREATE UNIQUE INDEX IF NOT EXISTS grants_session ON grants(session_id)')
            db.execute('CREATE INDEX IF NOT EXISTS codes_batch ON codes(batch)')
            db.execute('CREATE INDEX IF NOT EXISTS grants_code ON grants(code)')
            db.execute('''CREATE TABLE IF NOT EXISTS extensions(
                request_id TEXT PRIMARY KEY, session_id TEXT NOT NULL, code TEXT NOT NULL REFERENCES codes(id),
                ip TEXT NOT NULL, seconds INTEGER NOT NULL CHECK(seconds>0), previous_expires REAL NOT NULL,
                new_expires REAL NOT NULL, created REAL NOT NULL, actor TEXT NOT NULL)''')
            self.initialize_operations(db,version)
            db.commit()

    def digest(self, code):
        raw = code.strip().upper().replace('-', '').replace(' ', '')
        return hmac.new(self.pepper, raw.encode(), hashlib.sha256).hexdigest()

    def _make_batch(self, start, end, access, count, name, mode, now, week):
        count = positive_int(count, 'Number of codes', 1000)
        if not isinstance(name,str) or len(name.strip()) > 80 or any(ord(c)<32 for c in name):
            raise GateError('Batch names must be at most 80 characters without control characters.')
        name = name.strip() or dt.datetime.fromtimestamp(now,TZ).strftime('Batch %Y-%m-%d %H:%M')
        batch, raw_codes = secrets.token_hex(8), []
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('''INSERT INTO batches(id,week,starts,ends,minutes,created,name,access_seconds,validity_seconds,timing_mode)
                          VALUES(?,?,?,?,?,?,?,?,?,?)''',
                       (batch,week,start,end,access//60,now,name,access,int(end-start),mode))
            for _ in range(count):
                raw = ''.join(secrets.choice(ALPHABET) for _ in range(12))
                db.execute('INSERT INTO codes(id,batch,digest,hint) VALUES(?,?,?,?)',
                           (secrets.token_hex(8),batch,self.digest(raw),raw[-4:]))
                raw_codes.append('-'.join(raw[i:i+4] for i in range(0,12,4)))
            db.commit()
        return batch, raw_codes

    def create_batch(self, name='', count=10, validity_value=7, validity_unit='days', access_value=15, access_unit='minutes', now=None):
        now = time.time() if now is None else now
        validity = duration_seconds(validity_value,validity_unit,'validity')
        access = duration_seconds(access_value,access_unit,'access')
        return self._make_batch(now,now+validity,access,count,name,'duration',now,dt.datetime.fromtimestamp(now,TZ).date().isoformat())

    def new_batch(self, monday, count=10, minutes=15, now=None):
        """Legacy API retained for old callers and regression tests."""
        now = time.time() if now is None else now
        day = dt.date.fromisoformat(monday)
        if day.weekday()!=0 or minutes!=15: raise GateError('Legacy batches require a Monday and 15 minutes of access.')
        start = dt.datetime.combine(day,dt.time(),TZ).timestamp()
        end = dt.datetime.combine(day+dt.timedelta(days=7),dt.time(),TZ).timestamp()
        if end<=now: raise GateError('This week has already ended.')
        return self._make_batch(start,end,900,count,'Week starting '+monday,'legacy-week',now,monday)

    def attempt(self, scope, limit, period=900, now=None):
        now = time.time() if now is None else now
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('DELETE FROM attempts WHERE stamp<?',(now-86400,))
            total = db.execute('SELECT count(*) FROM attempts WHERE scope=? AND stamp>?',(scope,now-period)).fetchone()[0]
            allowed = total<limit
            if allowed: db.execute('INSERT INTO attempts VALUES(?,?)',(scope,now))
            db.commit()
        return allowed

    def grant(self, ip, now=None):
        now = time.time() if now is None else now
        with self.connect() as db:
            row = db.execute('''SELECT g.*, b.name AS batch_name FROM grants g JOIN codes c ON c.id=g.code
                JOIN batches b ON b.id=c.batch WHERE g.ip=? AND g.expires>? AND g.revoked=0 AND c.revoked=0 AND b.revoked=0''',
                (str(ipaddress.ip_address(ip)),now)).fetchone()
            return dict(row) if row else None

    def redeem(self, code, ip, now=None, identity=None, enforce=False):
        live_clock = now is None
        now = time.time() if live_clock else now
        ip = str(ipaddress.ip_address(ip))
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if live_clock: now=time.time()
            if enforce:
                state=db.execute('SELECT * FROM policy_state WHERE id=1').fetchone()
                age=time.monotonic()-state['heartbeat']
                if not state['healthy'] or not 0<=age<=3 or state['applying']:
                    raise GateError('Access enforcement is unavailable. Your code has not been used.')
            if identity is not None:
                device=db.execute('SELECT * FROM devices WHERE id=?',(identity['device_id'],)).fetchone()
                if not device or not device['enabled']: raise GateError('This VPN device is disabled.')
                if device['binding']!=identity['binding'] or device['last_ip']!=ip:
                    raise GateError('The VPN session changed. Reload the page; your code has not been used.')
            old = db.execute('SELECT * FROM grants WHERE ip=?',(ip,)).fetchone()
            if old:
                if old['expires']>now and not old['revoked']:
                    raise GateError('Access is already active. Your code has not been used.')
                raise GateError('The previous session is closing. Please try again in a few seconds.')
            item = db.execute('''SELECT c.*,b.starts,b.ends,b.access_seconds,b.revoked AS batch_revoked
                FROM codes c JOIN batches b ON c.batch=b.id WHERE c.digest=?''',(self.digest(code),)).fetchone()
            if not item or item['used'] is not None or item['revoked'] or item['batch_revoked'] or not item['starts']<=now<item['ends']:
                raise GateError('This code is invalid, already used, revoked or outside its validity period.')
            expires = now+item['access_seconds']
            db.execute('UPDATE codes SET used=?,used_ip=? WHERE id=?',(now,ip,item['id']))
            db.execute('INSERT INTO grants(ip,code,expires,started,session_id,device_id,vpn_binding) VALUES(?,?,?,?,?,?,?)',
                       (ip,item['id'],expires,now,secrets.token_hex(16),identity['device_id'] if identity else None,identity['binding'] if identity else None))
            db.commit()
        return expires

    def revoke(self, code_id):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('UPDATE codes SET revoked=1 WHERE id=?',(code_id,))
            db.execute('UPDATE grants SET revoked=1 WHERE code=?',(code_id,))
            db.commit()

    def revoke_batch(self, batch_id, now=None):
        now = time.time() if now is None else now
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if not db.execute('SELECT id FROM batches WHERE id=?',(batch_id,)).fetchone(): raise GateError('Batch not found.')
            count = db.execute('SELECT count(*) FROM codes WHERE batch=? AND revoked=0',(batch_id,)).fetchone()[0]
            active = db.execute('''SELECT count(*) FROM grants WHERE code IN(SELECT id FROM codes WHERE batch=?)
                AND revoked=0 AND expires>?''',(batch_id,now)).fetchone()[0]
            db.execute('UPDATE batches SET revoked=1 WHERE id=?',(batch_id,))
            db.execute('UPDATE codes SET revoked=1 WHERE batch=?',(batch_id,))
            db.execute('UPDATE grants SET revoked=1 WHERE code IN(SELECT id FROM codes WHERE batch=?)',(batch_id,))
            db.commit()
        return count, active

    def clear_revoked(self, batch_id=None, now=None):
        now = time.time() if now is None else now
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            clause, params = (' AND batch=?',[now,batch_id]) if batch_id else ('',[now])
            count = db.execute('UPDATE codes SET cleared_at=? WHERE revoked=1 AND cleared_at IS NULL'+clause,params).rowcount
            db.commit()
        return count

    def extend(self, session_id, value, unit, request_id, actor='Administrator', now=None):
        live_clock = now is None
        now = time.time() if live_clock else now
        seconds = duration_seconds(value,unit,'access')
        if not re.fullmatch(r'[a-f0-9]{32}',str(request_id)): raise GateError('Invalid extension request. Reload the page.')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            # The writer lock can outlast the original expiry. Check time after acquiring it.
            if live_clock: now = time.time()
            prior = db.execute('SELECT * FROM extensions WHERE request_id=?',(request_id,)).fetchone()
            if prior:
                if prior['session_id']!=session_id or prior['seconds']!=seconds: raise GateError('This extension request was already used for a different action.')
                return dict(prior)
            grant = db.execute('''SELECT g.*,c.used,c.revoked AS code_revoked,b.revoked AS batch_revoked
                FROM grants g JOIN codes c ON c.id=g.code JOIN batches b ON b.id=c.batch WHERE g.session_id=?''',(session_id,)).fetchone()
            if not grant or grant['expires']<=now or grant['revoked'] or grant['code_revoked'] or grant['batch_revoked'] or grant['used'] is None:
                raise GateError('Only active, non-revoked access can be extended. Expired access cannot be reopened.')
            expires = grant['expires']+seconds
            if expires-now>365*86400: raise GateError('The resulting access window cannot exceed 365 days.')
            db.execute('UPDATE grants SET expires=? WHERE session_id=?',(expires,session_id))
            db.execute('INSERT INTO extensions VALUES(?,?,?,?,?,?,?,?,?)',
                       (request_id,session_id,grant['code'],grant['ip'],seconds,grant['expires'],expires,now,actor))
            event = dict(db.execute('SELECT * FROM extensions WHERE request_id=?',(request_id,)).fetchone())
            db.commit()
        return event

    def _batch_query(self):
        return '''SELECT b.*, count(c.id) AS total,
            sum(CASE WHEN c.id IS NOT NULL AND c.revoked=1 THEN 1 ELSE 0 END) AS revoked_count,
            sum(CASE WHEN c.id IS NOT NULL AND c.revoked=0 AND c.used IS NOT NULL THEN 1 ELSE 0 END) AS redeemed_count,
            sum(CASE WHEN c.id IS NOT NULL AND c.revoked=0 AND c.used IS NULL AND b.ends<=:now THEN 1 ELSE 0 END) AS expired_count,
            sum(CASE WHEN c.id IS NOT NULL AND c.revoked=0 AND c.used IS NULL AND b.starts>:now THEN 1 ELSE 0 END) AS future_count,
            sum(CASE WHEN c.id IS NOT NULL AND c.revoked=0 AND c.used IS NULL AND b.starts<=:now AND b.ends>:now THEN 1 ELSE 0 END) AS unused_count,
            sum(CASE WHEN c.cleared_at IS NOT NULL THEN 1 ELSE 0 END) AS cleared_count,
            (SELECT count(*) FROM grants g JOIN codes z ON z.id=g.code WHERE z.batch=b.id AND g.expires>:now AND g.revoked=0 AND z.revoked=0 AND b.revoked=0) AS active_count
            FROM batches b LEFT JOIN codes c ON c.batch=b.id'''

    def batch_detail(self, batch_id, now=None):
        now = time.time() if now is None else now
        with self.connect() as db:
            row = db.execute(self._batch_query()+' WHERE b.id=:batch GROUP BY b.id',{'now':now,'batch':batch_id}).fetchone()
            if not row: raise GateError('Batch not found.')
            return dict(row)

    def list_batches(self, page=1, per_page=10, now=None):
        now = time.time() if now is None else now
        page = positive_int(page,'Page',1000000)
        with self.connect() as db:
            db.execute('BEGIN')
            total = db.execute('SELECT count(*) FROM batches').fetchone()[0]
            pages = max(1,(total+per_page-1)//per_page)
            page = min(page,pages)
            rows = db.execute(self._batch_query()+' GROUP BY b.id ORDER BY b.created DESC,b.id LIMIT :limit OFFSET :offset',
                              {'now':now,'limit':per_page,'offset':(page-1)*per_page}).fetchall()
            return {'items':[dict(r) for r in rows],'total':total,'page':page,'pages':pages}

    def list_codes(self, batch_id=None, status='', page=1, per_page=25, now=None):
        now = time.time() if now is None else now
        page = positive_int(page,'Page',1000000)
        if status and status not in STATUSES: raise GateError('Invalid code status filter.')
        where = ' WHERE c.cleared_at IS NULL'
        params = {'now':now,'limit':per_page}
        if batch_id:
            where+=' AND c.batch=:batch'
            params['batch']=batch_id
        if status:
            where+=' AND ('+STATUS_SQL+')=:status'
            params['status']=status
        join = ' FROM codes c JOIN batches b ON b.id=c.batch'
        with self.connect() as db:
            db.execute('BEGIN')
            total = db.execute('SELECT count(*)'+join+where,params).fetchone()[0]
            pages = max(1,(total+per_page-1)//per_page)
            page = min(page,pages)
            params['offset']=(page-1)*per_page
            rows = db.execute('SELECT c.id,c.batch AS batch_id,c.hint,c.used,c.used_ip,c.revoked,c.cleared_at,b.week,b.name AS batch_name,b.starts,b.ends,b.access_seconds,(SELECT g.session_id FROM grants g WHERE g.code=c.id AND g.revoked=0 AND g.expires>:now AND c.revoked=0 AND b.revoked=0 LIMIT 1) AS active_session_id,'+STATUS_SQL+' AS status'+join+where+' ORDER BY b.created DESC,b.id,c.hint,c.id LIMIT :limit OFFSET :offset',params).fetchall()
            return {'items':[dict(r) for r in rows],'total':total,'page':page,'pages':pages}

    def list_grants(self):
        with self.connect() as db:
            return [dict(r) for r in db.execute('''SELECT g.*,b.name AS batch_name,b.id AS batch_id,c.hint
                FROM grants g JOIN codes c ON c.id=g.code JOIN batches b ON b.id=c.batch ORDER BY g.expires''')]

    def extension_history(self, batch_id=None):
        with self.connect() as db:
            return [dict(r) for r in db.execute('''SELECT e.*,c.hint,b.name AS batch_name FROM extensions e
                JOIN codes c ON c.id=e.code JOIN batches b ON b.id=c.batch'''+(' WHERE b.id=?' if batch_id else '')+' ORDER BY e.created DESC,e.request_id LIMIT 20', [batch_id] if batch_id else [])]

    def revoked_visible(self, batch_id=None):
        with self.connect() as db:
            return db.execute('SELECT count(*) FROM codes WHERE revoked=1 AND cleared_at IS NULL'+(' AND batch=?' if batch_id else ''),[batch_id] if batch_id else []).fetchone()[0]

    def dashboard(self):
        # Compatibility for existing callers; the web UI uses paginated queries.
        return self.list_codes(per_page=1000000)['items'], self.list_grants()


def domains(path):
    result = []
    with open(path, encoding='utf-8') as f:
        for line in f:
            domain = line.split('#')[0].strip().lstrip('.').lower()
            if not domain:
                continue
            try:
                domain = domain.encode('idna').decode('ascii')
            except UnicodeError as exc:
                raise GateError('Invalid domain name.') from exc
            if len(domain) > 253 or not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', domain):
                raise GateError('Invalid domain in the restricted domain list.')
            if '.' not in domain or any(not label or len(label)>63 or label.startswith('-') or label.endswith('-') for label in domain.split('.')):
                raise GateError('Use full domain names, for example example.org.')
            try:
                ipaddress.ip_address(domain)
            except ValueError:
                result.append(domain)
            else:
                raise GateError('Use a domain name instead of an IP address.')
    return sorted(set(result))


def matches(host, entries):
    return any(host == d or host.endswith('.'+d) for d in entries)
