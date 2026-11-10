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


class GateError(ValueError):
    pass


class Store:
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
            if db.in_transaction:
                db.rollback()
            db.close()

    def initialize(self):
        with self.connect() as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.executescript('''
                CREATE TABLE IF NOT EXISTS batches(
                    id TEXT PRIMARY KEY, week TEXT NOT NULL, starts REAL NOT NULL,
                    ends REAL NOT NULL, minutes INTEGER NOT NULL, created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS codes(
                    id TEXT PRIMARY KEY, batch TEXT NOT NULL REFERENCES batches(id),
                    digest TEXT UNIQUE NOT NULL, hint TEXT NOT NULL, used REAL,
                    used_ip TEXT, revoked INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS grants(
                    ip TEXT PRIMARY KEY, code TEXT NOT NULL REFERENCES codes(id),
                    expires REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS attempts(
                    scope TEXT NOT NULL, stamp REAL NOT NULL);
                CREATE INDEX IF NOT EXISTS attempts_scope ON attempts(scope, stamp);
            ''')

    def digest(self, code):
        raw = code.strip().upper().replace('-', '').replace(' ', '')
        return hmac.new(self.pepper, raw.encode(), hashlib.sha256).hexdigest()

    def new_batch(self, monday, count=10, minutes=15, now=None):
        now = time.time() if now is None else now
        day = dt.date.fromisoformat(monday)
        if day.weekday() != 0 or not 1 <= count <= 100 or minutes != 15:
            raise GateError('Choose a Monday, 1–100 codes and 15 minutes of access.')
        start = dt.datetime.combine(day, dt.time(), TZ).timestamp()
        end = dt.datetime.combine(day + dt.timedelta(days=7), dt.time(), TZ).timestamp()
        if end <= now:
            raise GateError('This week has already ended.')
        batch, raw_codes = secrets.token_hex(8), []
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('INSERT INTO batches VALUES(?,?,?,?,?,?)',
                       (batch, monday, start, end, minutes, now))
            for _ in range(count):
                raw = ''.join(secrets.choice(ALPHABET) for _ in range(12))
                display = '-'.join(raw[i:i+4] for i in range(0, 12, 4))
                db.execute('INSERT INTO codes(id,batch,digest,hint) VALUES(?,?,?,?)',
                           (secrets.token_hex(8), batch, self.digest(raw), raw[-4:]))
                raw_codes.append(display)
            db.commit()
        return batch, raw_codes

    def attempt(self, scope, limit, period=900, now=None):
        now = time.time() if now is None else now
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('DELETE FROM attempts WHERE stamp < ?', (now-86400,))
            total = db.execute('SELECT count(*) FROM attempts WHERE scope=? AND stamp>?',
                               (scope, now-period)).fetchone()[0]
            allowed = total < limit
            if allowed:
                db.execute('INSERT INTO attempts VALUES(?,?)', (scope, now))
            db.commit()
        return allowed

    def grant(self, ip, now=None):
        now = time.time() if now is None else now
        with self.connect() as db:
            row = db.execute('SELECT * FROM grants WHERE ip=? AND expires>? AND revoked=0',
                             (str(ipaddress.ip_address(ip)), now)).fetchone()
            return dict(row) if row else None

    def redeem(self, code, ip, now=None):
        now = time.time() if now is None else now
        ip = str(ipaddress.ip_address(ip))
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            old = db.execute('SELECT * FROM grants WHERE ip=?', (ip,)).fetchone()
            if old:
                if old['expires'] > now and not old['revoked']:
                    raise GateError('Access is already active. Your code has not been used.')
                raise GateError('The previous session is closing. Please try again in a few seconds.')
            item = db.execute('''SELECT codes.*, batches.starts, batches.ends, batches.minutes
                 FROM codes JOIN batches ON codes.batch=batches.id WHERE digest=?''',
                              (self.digest(code),)).fetchone()
            if not item or item['used'] is not None or item['revoked'] or not item['starts'] <= now < item['ends']:
                raise GateError('This code is invalid, already used, revoked or outside its valid week.')
            expires = now + item['minutes']*60
            db.execute('UPDATE codes SET used=?,used_ip=? WHERE id=?', (now, ip, item['id']))
            db.execute('INSERT INTO grants(ip,code,expires) VALUES(?,?,?)', (ip, item['id'], expires))
            db.commit()
        return expires

    def revoke(self, code_id):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('UPDATE codes SET revoked=1 WHERE id=?', (code_id,))
            db.execute('UPDATE grants SET revoked=1 WHERE code=?', (code_id,))
            db.commit()

    def dashboard(self):
        with self.connect() as db:
            codes = [dict(r) for r in db.execute('''SELECT codes.id,codes.hint,codes.used,
                     codes.used_ip,codes.revoked,batches.week,batches.starts,batches.ends
                     FROM codes JOIN batches ON codes.batch=batches.id ORDER BY batches.created DESC,codes.hint''')]
            grants = [dict(r) for r in db.execute('SELECT * FROM grants ORDER BY expires')]
        return codes, grants


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
