"""Requests, bounded activity/visit history and safe batch removal."""
import ipaddress
import json
import math
import re
import secrets
import time
from urllib.parse import urlsplit

EVENTS=frozenset(('schedule.created','schedule.changed','schedule.generated','schedule.collected','schedule.failed','recovery.backup','recovery.restored','batch.created','batch.revoked','batch.removed','codes.cleared','code.activated','code.failed','code.revoked','session.extended','session.terminated','session.expired','admin.login','admin.login_failed','admin.logout','admin.policy_changed','domains.merged','domain.changed','request.created','request.read','request.resolved','request.dismissed','request.expired','request.approved','request.denied','activity.settings'))


def page_path(value):
    if not isinstance(value,str) or len(value)>8192 or not value.startswith('/') or value.startswith('//'):return None
    if any(ord(c)<32 or ord(c)==127 for c in value):return None
    parsed=urlsplit(value)
    if parsed.scheme or parsed.netloc:return None
    path=parsed.path
    if path.startswith(('/__access_gate','/internal/')):return None
    return path[:512]


class Operations:
    @staticmethod
    def initialize_operations(db):
        if 'removed_at' not in {r['name'] for r in db.execute('PRAGMA table_info(batches)')}:db.execute('ALTER TABLE batches ADD COLUMN removed_at REAL')
        for sql in (
            '''CREATE TABLE IF NOT EXISTS activity_policy(id INTEGER PRIMARY KEY CHECK(id=1),mode TEXT NOT NULL,
                retention_days INTEGER NOT NULL,version TEXT NOT NULL,cleaned_at REAL NOT NULL DEFAULT 0)''',
            '''CREATE TABLE IF NOT EXISTS activity_events(id INTEGER PRIMARY KEY AUTOINCREMENT,created REAL NOT NULL,event TEXT NOT NULL,
                actor TEXT NOT NULL,code_id TEXT,batch_id TEXT,session_id TEXT,details TEXT NOT NULL)''',
            'CREATE TABLE IF NOT EXISTS session_end_events(session_id TEXT PRIMARY KEY)',
            'CREATE INDEX IF NOT EXISTS activity_time ON activity_events(created)',
            'CREATE INDEX IF NOT EXISTS activity_code ON activity_events(code_id,created)',
            '''CREATE TABLE IF NOT EXISTS website_visits(id TEXT PRIMARY KEY,created REAL NOT NULL,code_id TEXT NOT NULL REFERENCES codes(id),
                session_id TEXT NOT NULL,domain TEXT NOT NULL,path TEXT,status INTEGER NOT NULL)''',
            'CREATE INDEX IF NOT EXISTS visit_code_time ON website_visits(code_id,created)',
            'CREATE INDEX IF NOT EXISTS visit_time ON website_visits(created)',
            '''CREATE TABLE IF NOT EXISTS access_requests(id TEXT PRIMARY KEY,browser_hash TEXT NOT NULL,domain TEXT NOT NULL,label TEXT NOT NULL,
                reason TEXT NOT NULL,address TEXT NOT NULL,created REAL NOT NULL,status TEXT NOT NULL DEFAULT 'pending',read_at REAL,resolved_at REAL)''',
            'CREATE INDEX IF NOT EXISTS request_owner ON access_requests(browser_hash,created)',
            'CREATE INDEX IF NOT EXISTS request_state ON access_requests(status,read_at,created)',
        ):db.execute(sql)
        request_columns={r['name'] for r in db.execute('PRAGMA table_info(access_requests)')}
        for name,kind in (('approval_seconds','INTEGER'),('approval_expires','REAL'),('approval_session_id','TEXT'),('approval_code_id','TEXT REFERENCES codes(id)')):
            if name not in request_columns:db.execute('ALTER TABLE access_requests ADD COLUMN '+name+' '+kind)
        db.execute("INSERT OR IGNORE INTO activity_policy(id,mode,retention_days,version) VALUES(1,'domains',30,?)",(secrets.token_hex(16),))

    @staticmethod
    def _event(db,event,actor='Administrator',code_id=None,batch_id=None,session_id=None,details=None,now=None):
        if event not in EVENTS:raise ValueError('Unknown activity event.')
        if actor not in ('Administrator','Visitor','Gateway','System','Local recovery'):actor='Administrator'
        allowed={'count','active','seconds','mode','retention_days','state','reason','domain'}
        safe={k:v for k,v in (details or {}).items() if k in allowed and (isinstance(v,(int,float,bool)) or (isinstance(v,str) and len(v)<=(253 if k=='domain' else 64)))}
        db.execute('INSERT INTO activity_events(created,event,actor,code_id,batch_id,session_id,details) VALUES(?,?,?,?,?,?,?)',
            (time.time() if now is None else now,event,actor,code_id,batch_id,session_id,json.dumps(safe)))

    def audit(self,event,**kwargs):
        with self.connect() as db:self._event(db,event,**kwargs)

    def activity_settings(self):
        with self.connect() as db:return dict(db.execute('SELECT * FROM activity_policy WHERE id=1').fetchone())

    def save_activity_settings(self,mode,days,version):
        from .core import GateError,positive_int
        if mode not in ('off','domains','pages'):raise GateError('Choose Off, Domains or Pages.')
        days=positive_int(days,'Retention days',365)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT version FROM activity_policy WHERE id=1').fetchone()[0]!=version:raise GateError('Activity settings changed. Reload and try again.')
            db.execute('UPDATE activity_policy SET mode=?,retention_days=?,version=?,cleaned_at=0 WHERE id=1',(mode,days,secrets.token_hex(16)))
            self._event(db,'activity.settings',details=dict(mode=mode,retention_days=days))
            # Disabling page logging also removes previously retained page paths.
            if mode!='pages':db.execute('UPDATE website_visits SET path=NULL WHERE path IS NOT NULL')
            db.commit()
        self.cleanup_activity(force=True)

    def cleanup_activity(self,now=None,force=False):
        now=time.time() if now is None else now
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            policy=db.execute('SELECT * FROM activity_policy WHERE id=1').fetchone()
            if not force and policy['cleaned_at']>now-60:return
            cutoff=now-policy['retention_days']*86400
            for table,key in (('activity_events','id'),('website_visits','id')):
                db.execute(f'DELETE FROM {table} WHERE {key} IN(SELECT {key} FROM {table} WHERE created<? LIMIT 5000)',(cutoff,))
            for row in db.execute('SELECT g.session_id,g.code,g.expires FROM grants g WHERE g.revoked=0 AND g.expires<=? AND g.expires>=? AND NOT EXISTS(SELECT 1 FROM session_end_events e WHERE e.session_id=g.session_id) LIMIT 1000',(now,cutoff)).fetchall():
                db.execute('INSERT INTO session_end_events VALUES(?)',(row['session_id'],))
                self._event(db,'session.expired',actor='System',code_id=row['code'],session_id=row['session_id'],now=row['expires'])
            expired=db.execute("UPDATE access_requests SET status='expired',resolved_at=?,read_at=coalesce(read_at,?) WHERE id IN(SELECT id FROM access_requests WHERE status='pending' AND created<=? LIMIT 5000)",(now,now,now-86400)).rowcount
            if expired:self._event(db,'request.expired',actor='System',details=dict(count=expired),now=now)
            db.execute('DELETE FROM access_requests WHERE id IN(SELECT id FROM access_requests WHERE created<? LIMIT 5000)',(cutoff,))
            db.execute('DELETE FROM attempts WHERE rowid IN(SELECT rowid FROM attempts WHERE stamp<? LIMIT 5000)',(now-86400,))
            db.execute('UPDATE activity_policy SET cleaned_at=? WHERE id=1',(now,))
            db.commit()

    def record_visit(self,record,now=None):
        from .core import GateError
        from .browser import origin
        now=time.time() if now is None else now
        if not isinstance(record,dict):raise GateError('Invalid visit record.')
        rid=record.get('id','');sid=record.get('session_id','')
        if not isinstance(rid,str) or not isinstance(sid,str) or not re.fullmatch('[a-f0-9]{32}',rid) or not re.fullmatch('[a-f0-9]{32}',sid):raise GateError('Invalid visit identity.')
        host=origin(record.get('origin'))[8:]
        stamp=record.get('created',now)
        if not isinstance(stamp,(int,float)) or isinstance(stamp,bool) or not math.isfinite(stamp) or not now-365*86400<=stamp<=now+60:raise GateError('Invalid visit timestamp.')
        status=record.get('status')
        if not isinstance(status,int) or isinstance(status,bool) or not 100<=status<=599:raise GateError('Invalid response status.')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            policy=db.execute('SELECT * FROM activity_policy WHERE id=1').fetchone()
            if policy['mode']=='off':return False
            grant=db.execute('SELECT code FROM grants WHERE session_id=?',(sid,)).fetchone()
            if not grant:return False
            path=page_path(record.get('path')) if policy['mode']=='pages' and record.get('navigation') is True else None
            changed=db.execute('INSERT OR IGNORE INTO website_visits VALUES(?,?,?,?,?,?,?)',(rid,stamp,grant['code'],sid,host,path,status)).rowcount
            db.commit()
        return bool(changed)

    def code_detail(self,code_id):
        from .core import GateError
        with self.connect() as db:
            row=db.execute('SELECT c.id,c.hint,c.used,c.used_ip,c.revoked,c.cleared_at,b.id AS batch_id,b.name AS batch_name,b.removed_at,b.starts,b.ends,b.access_seconds FROM codes c JOIN batches b ON b.id=c.batch WHERE c.id=?',(code_id,)).fetchone()
            if not row:raise GateError('Code not found.')
            grants=[dict(r) for r in db.execute('SELECT session_id,started,expires,revoked FROM grants WHERE code=? ORDER BY started DESC',(code_id,))]
        return dict(row,grants=grants)

    def history(self,kind='events',code_id=None,event='',domain='',page=1,now=None,since=None,until=None,actor='',batch_id=None):
        from .core import GateError,positive_int
        now=time.time() if now is None else now;page=positive_int(page,'Page',1000000)
        if kind not in ('events','domains','pages'):raise GateError('Invalid history view.')
        if event and event not in EVENTS:raise GateError('Invalid event filter.')
        if not isinstance(domain,str) or len(domain)>253:raise GateError('Invalid domain filter.')
        cutoff=now-self.activity_settings()['retention_days']*86400
        params={'cutoff':cutoff};where=' WHERE created>=:cutoff'
        if since is not None:where+=' AND created>=:since';params['since']=since
        if until is not None:where+=' AND created<:until';params['until']=until
        if code_id:
            where+=(' AND (code_id=:code OR (code_id IS NULL AND batch_id=(SELECT batch FROM codes WHERE id=:code)))' if kind=='events' else ' AND code_id=:code');params['code']=code_id
        if actor and kind=='events':
            if actor not in ('Administrator','Visitor','Gateway','System','Local recovery'):raise GateError('Invalid actor filter.')
            where+=' AND actor=:actor';params['actor']=actor
        if batch_id:
            where+=(' AND (batch_id=:batch OR code_id IN(SELECT id FROM codes WHERE batch=:batch))' if kind=='events' else ' AND code_id IN(SELECT id FROM codes WHERE batch=:batch)');params['batch']=batch_id
        if kind=='events':
            table='activity_events';query='SELECT * FROM '+table+where
            if event:query+=' AND event=:event';params['event']=event
            query+=' ORDER BY created DESC,id DESC'
        else:
            table='website_visits'
            if domain:where+=' AND instr(domain,:domain)>0';params['domain']=domain.lower()
            if kind=='pages':where+=' AND path IS NOT NULL'
            group='domain,path' if kind=='pages' else 'domain'
            query='SELECT domain,'+('path' if kind=='pages' else 'NULL AS path')+',count(*) AS requests,min(created) AS first_seen,max(created) AS last_seen FROM '+table+where+' GROUP BY '+group+' ORDER BY last_seen DESC'
        with self.connect() as db:
            db.execute('BEGIN')
            total=db.execute('SELECT count(*) FROM ('+query+')',params).fetchone()[0]
            pages=max(1,(total+99)//100);page=min(page,pages);params['offset']=(page-1)*100
            rows=[dict(r) for r in db.execute(query+' LIMIT 100 OFFSET :offset',params)]
        if kind=='events':
            with self.connect() as db:
                ids=list({r['code_id'] for r in rows if r['code_id']})
                codes={r['id']:dict(r) for r in db.execute('SELECT id,hint,batch FROM codes WHERE id IN('+','.join('?' for _ in ids)+')',ids)} if ids else {}
                bids=list({r['batch_id'] or codes.get(r['code_id'],{}).get('batch') for r in rows}- {None})
                batches={r['id']:r['name'] for r in db.execute('SELECT id,name FROM batches WHERE id IN('+','.join('?' for _ in bids)+')',bids)} if bids else {}
                for row in rows:
                    row['summary']=' · '.join(k.replace('_',' ').capitalize()+': '+str(v).replace('_',' ') for k,v in json.loads(row['details']).items()) or '—'
                    item=codes.get(row['code_id'])
                    row['code_hint']=item['hint'] if item else None
                    row['batch_id']=row['batch_id'] or (item['batch'] if item else None)
                    row['batch_name']=batches.get(row['batch_id'])
        return dict(items=rows,total=total,page=page,pages=pages,kind=kind,event=event,domain=domain)

    def submit_request(self,browser_token,address,domain='',label='',reason='',now=None):
        from .core import GateError
        from .browser import origin
        now=time.time() if now is None else now;owner=self.browser_digest(browser_token)
        address=str(ipaddress.ip_address(address))
        if domain:domain=origin('https://'+domain)[8:]
        for text,limit in ((label,80),(reason,500)):
            if not isinstance(text,str) or len(text)>limit or any(ord(c)<32 and c not in '\n\r\t' for c in text):raise GateError('Use a label of at most 80 characters and a reason of at most 500 characters.')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            old=db.execute("SELECT id FROM access_requests WHERE browser_hash=? AND domain=? AND status='pending' AND created>?",(owner,domain,now-86400)).fetchone()
            if old:return old['id'],False
            for scope,limit in (('access-request-ip:'+address,5),('access-request-browser:'+owner,3)):
                if db.execute('SELECT count(*) FROM attempts WHERE scope=? AND stamp>?',(scope,now-900)).fetchone()[0]>=limit:raise GateError('Too many requests. Please wait 15 minutes.')
            for scope in ('access-request-ip:'+address,'access-request-browser:'+owner):db.execute('INSERT INTO attempts VALUES(?,?)',(scope,now))
            rid=secrets.token_hex(16)
            db.execute('INSERT INTO access_requests(id,browser_hash,domain,label,reason,address,created) VALUES(?,?,?,?,?,?,?)',(rid,owner,domain,label.strip(),reason.strip(),address,now))
            self._event(db,'request.created',actor='Visitor',details=dict(state='pending'),now=now)
            db.commit()
        return rid,True

    def requests_page(self,browser_token=None,state='all',page=1,now=None):
        from .core import GateError,positive_int
        now=time.time() if now is None else now;page=positive_int(page,'Page',1000000)
        if state not in ('all','pending','approved','denied','resolved','dismissed','expired'):raise GateError('Invalid request state.')
        cutoff=now-self.activity_settings()['retention_days']*86400
        expression="CASE WHEN status='pending' AND created<=:expired THEN 'expired' ELSE status END"
        where=' WHERE created>=:cutoff';params=dict(cutoff=cutoff,expired=now-86400)
        if browser_token:where+=' AND browser_hash=:owner';params['owner']=self.browser_digest(browser_token)
        if state!='all':where+=' AND ('+expression+')=:state';params['state']=state
        fields='id,domain,label,reason,created,read_at,resolved_at,approval_expires,'+expression+' AS state'+('' if browser_token else ',address')
        with self.connect() as db:
            db.execute('BEGIN')
            total=db.execute('SELECT count(*) FROM access_requests'+where,params).fetchone()[0]
            pages=max(1,(total+49)//50);page=min(page,pages);params['offset']=(page-1)*50
            rows=[dict(r) for r in db.execute('SELECT '+fields+' FROM access_requests'+where+' ORDER BY created DESC,id LIMIT 50 OFFSET :offset',params)]
        return dict(items=rows,total=total,page=page,pages=pages)

    def notifications(self,now=None):
        now=time.time() if now is None else now
        with self.connect() as db:
            where=" FROM access_requests WHERE status='pending' AND read_at IS NULL AND created>?"
            unread=db.execute('SELECT count(*)'+where,(now-86400,)).fetchone()[0]
            rows=db.execute('SELECT id,domain,created'+where+' ORDER BY created DESC LIMIT 5',(now-86400,)).fetchall()
        return dict(unread=unread,items=[dict(r) for r in rows])

    def change_request(self,request_id,action,now=None):
        from .core import GateError
        now=time.time() if now is None else now
        if action not in ('read','resolve','dismiss'):raise GateError('Invalid request action.')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT * FROM access_requests WHERE id=?',(request_id,)).fetchone()
            if not row:raise GateError('Request not found.')
            if action=='read':changed=db.execute('UPDATE access_requests SET read_at=? WHERE id=? AND read_at IS NULL',(now,request_id)).rowcount
            else:
                state='resolved' if action=='resolve' else 'dismissed'
                changed=db.execute("UPDATE access_requests SET status=?,read_at=coalesce(read_at,?),resolved_at=? WHERE id=? AND status='pending' AND created>?",(state,now,now,request_id,now-86400)).rowcount
            if changed:self._event(db,{'read':'request.read','resolve':'request.resolved','dismiss':'request.dismissed'}[action],details=dict(count=1),now=now)
            db.commit()
        return bool(changed)

    def removable_batches(self):
        with self.connect() as db:return [dict(r) for r in db.execute('SELECT id,name FROM batches WHERE revoked=1 AND removed_at IS NULL ORDER BY created,id LIMIT 100')]

    def remove_batches(self,ids,revoked_only=False,now=None):
        from .core import GateError
        now=time.time() if now is None else now
        if not isinstance(ids,list) or not 1<=len(ids)<=100 or any(not isinstance(i,str) or not re.fullmatch('[a-f0-9]{16}',i) for i in ids):raise GateError('Select between 1 and 100 valid batches.')
        count=0
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            for bid in dict.fromkeys(ids):
                row=db.execute('SELECT * FROM batches WHERE id=?',(bid,)).fetchone()
                if not row:raise GateError('Batch not found.')
                if row['removed_at'] is not None or (revoked_only and not row['revoked']):continue
                db.execute('UPDATE batches SET removed_at=?,revoked=1 WHERE id=?',(now,bid))
                db.execute('UPDATE codes SET revoked=1 WHERE batch=?',(bid,))
                db.execute('UPDATE grants SET revoked=1 WHERE code IN(SELECT id FROM codes WHERE batch=?)',(bid,))
                self._event(db,'batch.removed',batch_id=bid,now=now);count+=1
            db.commit()
        return count

    def request_detail(self,request_id):
        from .core import GateError
        with self.connect() as db:
            row=db.execute('SELECT id,domain,label,reason,address,created,status,read_at,resolved_at,approval_seconds,approval_expires,approval_session_id,approval_code_id FROM access_requests WHERE id=?',(request_id,)).fetchone()
            if not row or row['created']<time.time()-self.activity_settings()['retention_days']*86400:raise GateError('Request not found.')
            item=dict(row)
            active=db.execute('SELECT g.expires FROM grants g JOIN codes c ON c.id=g.code JOIN batches b ON b.id=c.batch WHERE g.session_id=? AND g.expires>? AND g.revoked=0 AND c.revoked=0 AND b.revoked=0',(item['approval_session_id'],time.time())).fetchone() if item['status']=='approved' else None
            item['session_active']=bool(active);item['current_expires']=active['expires'] if active else item['approval_expires']
            if item['status']=='pending' and item['created']<=time.time()-86400:item['status']='expired'
            return item

    def decide_request(self,request_id,decision,value=15,unit='minutes',now=None):
        from .core import GateError,duration_seconds,TZ
        import datetime as dt
        if decision not in ('approve','deny'):raise GateError('Choose Approve or Deny.')
        seconds=duration_seconds(value,unit,'access') if decision=='approve' else 0
        live_clock=now is None
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            now=time.time() if live_clock else now
            row=db.execute('SELECT * FROM access_requests WHERE id=?',(request_id,)).fetchone()
            if not row:raise GateError('Request not found.')
            if row['status']=='approved' and decision=='approve':
                if row['approval_seconds']!=seconds:raise GateError('This request was already approved with a different duration.')
                return dict(state='approved',changed=False,expires=row['approval_expires'],session_id=row['approval_session_id'],code_id=row['approval_code_id'])
            if row['status']=='denied' and decision=='deny':return dict(state='denied',changed=False)
            if row['status']!='pending':raise GateError('This request has already been decided. Reload the inbox.')
            if row['created']<=now-86400:raise GateError('This request expired. The visitor must send a new request.')
            if decision=='deny':
                db.execute("UPDATE access_requests SET status='denied',read_at=coalesce(read_at,?),resolved_at=? WHERE id=?",(now,now,request_id))
                self._event(db,'request.denied',details=dict(state='denied'),now=now)
                db.commit()
                return dict(state='denied',changed=True)
            old=db.execute('SELECT * FROM grants WHERE browser_hash=?',(row['browser_hash'],)).fetchone()
            active=db.execute('''SELECT g.*,c.batch FROM grants g JOIN codes c ON c.id=g.code JOIN batches b ON b.id=c.batch
                WHERE g.browser_hash=? AND g.expires>? AND g.revoked=0 AND c.revoked=0 AND b.revoked=0 AND c.used IS NOT NULL''',(row['browser_hash'],now)).fetchone()
            if active:
                end=active['expires']+seconds
                if end-now>365*86400:raise GateError('The resulting access window cannot exceed 365 days.')
                sid=active['session_id'];code_id=active['code'];batch=active['batch']
                db.execute('UPDATE grants SET expires=? WHERE session_id=?',(end,sid))
                db.execute('INSERT INTO extensions VALUES(?,?,?,?,?,?,?,?,?)',(secrets.token_hex(16),sid,code_id,active['ip'],seconds,active['expires'],end,now,'Administrator (request approval)'))
                self._event(db,'session.extended',code_id=code_id,batch_id=batch,session_id=sid,details=dict(seconds=seconds,reason='request_approval'),now=now)
            else:
                if old:db.execute('UPDATE grants SET browser_hash=NULL WHERE session_id=?',(old['session_id'],))
                sid=secrets.token_hex(16);code_id=secrets.token_hex(8);batch=secrets.token_hex(8);end=now+seconds
                name='Approved request '+request_id[:8]
                week=dt.datetime.fromtimestamp(now,TZ).date().isoformat()
                db.execute('''INSERT INTO batches(id,week,starts,ends,minutes,created,name,access_seconds,validity_seconds,timing_mode)
                    VALUES(?,?,?,?,?,?,?,?,?,?)''',(batch,week,now,end,seconds//60,now,name,seconds,seconds,'approval'))
                # An already-consumed approval token reuses normal grant/history/revocation machinery.
                # Its unexported random digest can never be entered as an unused access code.
                db.execute('INSERT INTO codes(id,batch,digest,hint,used,used_ip) VALUES(?,?,?,?,?,?)',(code_id,batch,self.digest(secrets.token_hex(32)),'AUTO',now,row['address']))
                db.execute('INSERT INTO grants(session_id,ip,code,expires,started,browser_hash) VALUES(?,?,?,?,?,?)',(sid,row['address'],code_id,end,now,row['browser_hash']))
                self._event(db,'batch.created',batch_id=batch,details=dict(count=1,reason='request_approval'),now=now)
                self._event(db,'code.activated',code_id=code_id,batch_id=batch,session_id=sid,details=dict(reason='request_approval'),now=now)
            db.execute("UPDATE access_requests SET status='approved',read_at=coalesce(read_at,?),resolved_at=?,approval_seconds=?,approval_expires=?,approval_session_id=?,approval_code_id=? WHERE id=?",(now,now,seconds,end,sid,code_id,request_id))
            self._event(db,'request.approved',code_id=code_id,batch_id=batch,session_id=sid,details=dict(seconds=seconds,state='approved'),now=now)
            db.commit()
        return dict(state='approved',changed=True,expires=end,session_id=sid,code_id=code_id)

    def own_request_status(self,request_id,browser_token,now=None):
        from .core import GateError
        now=time.time() if now is None else now
        owner=self.browser_digest(browser_token)
        with self.connect() as db:
            row=db.execute('SELECT id,domain,created,status,approval_session_id,approval_expires FROM access_requests WHERE id=? AND browser_hash=?',(request_id,owner)).fetchone()
            if not row or row['created']<now-self.activity_settings()['retention_days']*86400:raise GateError('Request not found.')
        state='expired' if row['status']=='pending' and row['created']<=now-86400 else row['status']
        grant=self.browser_grant(browser_token,now)
        active=bool(state=='approved' and grant and grant['session_id']==row['approval_session_id'])
        return dict(id=row['id'],domain=row['domain'],state=state,active=active,expires=grant['expires'] if active else row['approval_expires'])
