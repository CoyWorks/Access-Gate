"""Durable recurring batches with public-key-only generation and one-time collection."""
import datetime as dt
import json
import re
import secrets
import time
from zoneinfo import ZoneInfo
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ZONES=('Europe/Amsterdam','UTC')


def upcoming(spec,after,count=3):
    zone=ZoneInfo(spec['timezone']);date=dt.datetime.fromtimestamp(after,zone).date();result=[]
    hour,minute=map(int,spec['clock'].split(':'))
    for offset in range(40):
        day=date+dt.timedelta(days=offset)
        if spec['recurrence']=='weekly' and day.weekday()!=spec['weekday']:continue
        wall=dt.datetime.combine(day,dt.time(hour,minute));candidate=wall.replace(tzinfo=zone,fold=0);stamp=candidate.timestamp()
        # Nonexistent local times are skipped. An autumn fold runs only its first occurrence.
        if dt.datetime.fromtimestamp(stamp,zone).replace(tzinfo=None)!=wall:continue
        if stamp>after:result.append(stamp)
        if len(result)>=count:return result
    raise ValueError('Unable to calculate schedule.')


def latest_due(spec,now):
    zone=ZoneInfo(spec['timezone']);date=dt.datetime.fromtimestamp(now,zone).date()
    hour,minute=map(int,spec['clock'].split(':'));candidates=[]
    for offset in range(10):
        day=date-dt.timedelta(days=offset)
        if spec['recurrence']=='weekly' and day.weekday()!=spec['weekday']:continue
        wall=dt.datetime.combine(day,dt.time(hour,minute));stamp=wall.replace(tzinfo=zone,fold=0).timestamp()
        if stamp<=now and dt.datetime.fromtimestamp(stamp,zone).replace(tzinfo=None)==wall:candidates.append(stamp)
    return max(candidates)


def validate_schedule(values):
    from .core import GateError,positive_int,duration_seconds
    name=values.get('name','').strip()
    if not name or len(name)>80 or any(ord(c)<32 for c in name):raise GateError('Use a schedule name of 1–80 characters.')
    recurrence=values.get('recurrence','')
    if recurrence not in ('daily','weekly'):raise GateError('Choose daily or weekly.')
    clock=values.get('clock','')
    if not re.fullmatch(r'(?:[01][0-9]|2[0-3]):[0-5][0-9]',clock):raise GateError('Choose a local time in HH:MM format.')
    timezone=values.get('timezone','Europe/Amsterdam')
    if timezone not in ZONES:raise GateError('Choose Europe/Amsterdam or UTC.')
    try:weekday=int(values.get('weekday',0))
    except (ValueError,TypeError):raise GateError('Choose a weekday.') from None
    if weekday not in range(7):raise GateError('Choose a weekday.')
    return dict(name=name,recurrence=recurrence,clock=clock,timezone=timezone,weekday=weekday,
        count=positive_int(values.get('count',10),'Number of codes',1000),
        validity_seconds=duration_seconds(values.get('validity_value',7),values.get('validity_unit','days'),'validity'),
        access_seconds=duration_seconds(values.get('access_value',15),values.get('access_unit','minutes'),'access'))


def raw_private(key):return key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
def raw_public(key):return key.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)

def seal(public,payload,schedule):
    ephemeral=X25519PrivateKey.generate();shared=ephemeral.exchange(X25519PublicKey.from_public_bytes(public))
    key=HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=('access-gate-schedule:'+schedule).encode()).derive(shared)
    nonce=secrets.token_bytes(12)
    return raw_public(ephemeral.public_key())+nonce+AESGCM(key).encrypt(nonce,payload,schedule.encode())


def unseal(private,payload,schedule):
    shared=private.exchange(X25519PublicKey.from_public_bytes(payload[:32]))
    key=HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=('access-gate-schedule:'+schedule).encode()).derive(shared)
    return AESGCM(key).decrypt(payload[32:44],payload[44:],schedule.encode())


class Scheduling:
    @staticmethod
    def initialize_schedules(db):
        db.execute('''CREATE TABLE IF NOT EXISTS schedules(id TEXT PRIMARY KEY,name TEXT NOT NULL,recurrence TEXT NOT NULL,
            weekday INTEGER NOT NULL,clock TEXT NOT NULL,timezone TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,
            count INTEGER NOT NULL,validity_seconds INTEGER NOT NULL,access_seconds INTEGER NOT NULL,created REAL NOT NULL,
            next_due REAL NOT NULL,public_key BLOB NOT NULL,private_key BLOB NOT NULL,version TEXT NOT NULL,last_message TEXT NOT NULL DEFAULT '')''')
        db.execute('''CREATE TABLE IF NOT EXISTS schedule_runs(id TEXT PRIMARY KEY,schedule TEXT NOT NULL REFERENCES schedules(id),
            occurrence TEXT NOT NULL,due REAL NOT NULL,created REAL NOT NULL,status TEXT NOT NULL,batch TEXT REFERENCES batches(id),
            payload BLOB,expires REAL NOT NULL,collected REAL,UNIQUE(schedule,occurrence))''')
        db.execute('CREATE INDEX IF NOT EXISTS schedule_run_time ON schedule_runs(schedule,created)')

    def create_schedule(self,values,password,now=None):
        from .recovery import encrypt
        now=time.time() if now is None else now;spec=validate_schedule(values)
        key=X25519PrivateKey.generate();private=encrypt(raw_private(key),password)
        schedule=secrets.token_hex(16);version=secrets.token_hex(16)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('''INSERT INTO schedules(id,name,recurrence,weekday,clock,timezone,count,validity_seconds,access_seconds,created,next_due,public_key,private_key,version)
                VALUES(:id,:name,:recurrence,:weekday,:clock,:timezone,:count,:validity_seconds,:access_seconds,:created,:next_due,:public_key,:private_key,:version)''',
                dict(spec,id=schedule,created=now,next_due=upcoming(spec,now,1)[0],public_key=raw_public(key.public_key()),private_key=private,version=version))
            self._event(db,'schedule.created',details=dict(count=spec['count']),now=now);db.commit()
        return schedule

    @staticmethod
    def _safe_schedule(row):return {k:row[k] for k in row.keys() if k not in ('private_key','public_key')}

    def schedules_page(self,page=1):
        from .core import positive_int
        page=positive_int(page,'Page',1000000)
        with self.connect() as db:
            total=db.execute('SELECT count(*) FROM schedules').fetchone()[0];pages=max(1,(total+49)//50);page=min(page,pages)
            rows=db.execute('SELECT * FROM schedules ORDER BY created DESC LIMIT 50 OFFSET ?',((page-1)*50,)).fetchall()
        return dict(items=[self._safe_schedule(row) for row in rows],page=page,pages=pages,total=total)

    def schedule_detail(self,schedule):
        from .core import GateError
        with self.connect() as db:
            row=db.execute('SELECT * FROM schedules WHERE id=?',(schedule,)).fetchone()
            if not row:raise GateError('Schedule not found.')
            runs=[dict(r) for r in db.execute('SELECT id,occurrence,due,created,status,batch,expires,collected FROM schedule_runs WHERE schedule=? ORDER BY created DESC LIMIT 100',(schedule,))]
        return dict(**self._safe_schedule(row),runs=runs,preview=upcoming(row,time.time()))

    def change_schedule(self,schedule,enabled,version,now=None):
        from .core import GateError
        now=time.time() if now is None else now
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE');row=db.execute('SELECT * FROM schedules WHERE id=?',(schedule,)).fetchone()
            if not row or row['version']!=version:raise GateError('Schedule changed. Reload and try again.')
            if enabled not in (True,False):raise GateError('Invalid schedule state.')
            db.execute('UPDATE schedules SET enabled=?,version=?,next_due=?,last_message=? WHERE id=?',(int(enabled),secrets.token_hex(16),upcoming(row,now,1)[0], 'Resumed; paused occurrences are skipped.' if enabled else 'Paused.',schedule))
            self._event(db,'schedule.changed',details=dict(state='enabled' if enabled else 'paused'),now=now);db.commit()

    def _schedule_run(self,db,row,occurrence,due,now):
        prior=db.execute('SELECT id FROM schedule_runs WHERE schedule=? AND occurrence=?',(row['id'],occurrence)).fetchone()
        if prior:return prior['id']
        batch,codes=self._insert_batch(db,now,now+row['validity_seconds'],row['access_seconds'],row['count'],row['name'],'scheduled',now,dt.datetime.fromtimestamp(now,ZoneInfo(row['timezone'])).date().isoformat())
        run=secrets.token_hex(16)
        payload=seal(row['public_key'],json.dumps(dict(batch=batch,codes=codes)).encode(),row['id'])
        db.execute('INSERT INTO schedule_runs(id,schedule,occurrence,due,created,status,batch,payload,expires) VALUES(?,?,?,?,?,?,?,?,?)',
            (run,row['id'],occurrence,due,now,'ready',batch,payload,min(now+7*86400,now+row['validity_seconds'])))
        db.execute("UPDATE schedules SET last_message='Codes ready for one-time collection.' WHERE id=?",(row['id'],))
        self._event(db,'schedule.generated',batch_id=batch,details=dict(count=len(codes)),now=now)
        return run

    def run_schedule_now(self,schedule,request_id,now=None):
        from .core import GateError
        if not re.fullmatch('[a-f0-9]{32}',request_id or ''):raise GateError('Reload the schedule before running it.')
        now=time.time() if now is None else now
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE');row=db.execute('SELECT * FROM schedules WHERE id=?',(schedule,)).fetchone()
            if not row:raise GateError('Schedule not found.')
            result=self._schedule_run(db,row,'manual:'+request_id,now,now);db.commit()
        return result

    def run_schedules(self,now=None):
        now=time.time() if now is None else now
        with self.connect() as db:ids=[row[0] for row in db.execute('SELECT id FROM schedules WHERE enabled=1 AND next_due<=? ORDER BY next_due LIMIT 50',(now,))]
        for schedule in ids:
            try:
                with self.connect() as db:
                    db.execute('BEGIN IMMEDIATE');row=db.execute('SELECT * FROM schedules WHERE id=? AND enabled=1 AND next_due<=?',(schedule,now)).fetchone()
                    if not row:continue
                    due=latest_due(row,now);occurrence='scheduled:'+str(int(due))
                    if now-due<=86400:self._schedule_run(db,row,occurrence,due,now)
                    else:
                        db.execute("INSERT OR IGNORE INTO schedule_runs(id,schedule,occurrence,due,created,status,expires) VALUES(?,?,?,?,?,'skipped',?)",(secrets.token_hex(16),schedule,occurrence,due,now,now))
                        db.execute("UPDATE schedules SET last_message='Missed run older than 24 hours was skipped.' WHERE id=?",(schedule,))
                    db.execute('UPDATE schedules SET next_due=? WHERE id=?',(upcoming(row,now,1)[0],schedule));db.commit()
            except Exception:
                # Roll back both codes and encrypted output on any failure. Bound retries to the next occurrence.
                with self.connect() as db:
                    db.execute('BEGIN IMMEDIATE');row=db.execute('SELECT * FROM schedules WHERE id=?',(schedule,)).fetchone()
                    if row and row['next_due']<=now:
                        occurrence='scheduled:'+str(int(row['next_due']))
                        db.execute("INSERT OR IGNORE INTO schedule_runs(id,schedule,occurrence,due,created,status,expires) VALUES(?,?,?,?,?,'failed',?)",(secrets.token_hex(16),schedule,occurrence,row['next_due'],now,now))
                        db.execute("UPDATE schedules SET next_due=?,last_message='Generation failed; no codes were retained. Use Run now to retry.' WHERE id=?",(upcoming(row,now,1)[0],schedule))
                        self._event(db,'schedule.failed',actor='System',now=now)
                    db.commit()
        self.expire_schedule_outputs(now)

    def expire_schedule_outputs(self,now=None):
        now=time.time() if now is None else now
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            for row in db.execute("SELECT id,batch FROM schedule_runs WHERE status='ready' AND expires<=? LIMIT 1000",(now,)).fetchall():
                db.execute("UPDATE schedule_runs SET status='expired',payload=NULL WHERE id=?",(row['id'],))
                db.execute('UPDATE batches SET revoked=1 WHERE id=?',(row['batch'],));db.execute('UPDATE codes SET revoked=1 WHERE batch=?',(row['batch'],))
            db.commit()

    def collect_schedule_run(self,schedule,run,password,now=None):
        from .core import GateError
        from .recovery import decrypt
        now=time.time() if now is None else now
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT r.*,s.private_key,s.public_key FROM schedule_runs r JOIN schedules s ON s.id=r.schedule WHERE r.id=? AND s.id=?',(run,schedule)).fetchone()
            if not row or row['status']!='ready' or row['expires']<=now or not row['payload']:raise GateError('This output is unavailable, expired or already collected.')
            batch=db.execute('SELECT revoked,removed_at FROM batches WHERE id=?',(row['batch'],)).fetchone()
            if not batch or batch['revoked'] or batch['removed_at']:raise GateError('The generated batch is revoked or removed.')
            try:
                private=X25519PrivateKey.from_private_bytes(decrypt(row['private_key'],password))
                if raw_public(private.public_key())!=row['public_key']:raise ValueError()
                payload=json.loads(unseal(private,row['payload'],schedule))
            except Exception:raise GateError('Export passphrase is incorrect or the encrypted output is damaged.') from None
            if payload.get('batch')!=row['batch']:raise GateError('Encrypted output does not match its batch.')
            db.execute("UPDATE schedule_runs SET status='collected',collected=?,payload=NULL WHERE id=?",(now,run))
            self._event(db,'schedule.collected',batch_id=row['batch'],now=now);db.commit()
        return row['batch'],payload['codes']
