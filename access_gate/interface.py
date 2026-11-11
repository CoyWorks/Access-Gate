"""Bounded view models for the request-first administration UI."""
import time


class Interface:
    def ui_sessions(self,state='active',page=1,now=None):
        now=time.time() if now is None else now
        result=self.session_overview(state,page,now)
        if not result['items']:return result
        ids=[item['session_id'] for item in result['items']];marks=','.join('?' for _ in ids)
        cutoff=now-self.activity_settings()['retention_days']*86400
        with self.connect() as db:
            codes={r['session_id']:dict(r) for r in db.execute('SELECT session_id,code AS code_id FROM grants WHERE session_id IN('+marks+')',ids)}
            requests={}
            for row in db.execute('SELECT approval_session_id AS session_id,label,domain FROM access_requests WHERE approval_session_id IN('+marks+') AND created>=? ORDER BY created,id',[*ids,cutoff]):requests[row['session_id']]=dict(row)
        for item in result['items']:
            item.update(codes.get(item['session_id'],{}));details=requests.get(item['session_id'],{})
            item['label']=details.get('label') or ('Approved access' if item['hint']=='AUTO' else item['batch_name'])
            item['requested_domain']=details.get('domain','')
        return result

    def ui_session(self,sid,now=None):
        from .core import GateError
        now=time.time() if now is None else now
        with self.connect() as db:
            row=db.execute('SELECT code FROM grants WHERE session_id=?',(sid,)).fetchone()
        if not row:raise GateError('Browser session not found.')
        code=self.code_detail(row['code'])
        grant=next(g for g in code['grants'] if g['session_id']==sid)
        state='revoked' if code['revoked'] else ('terminated' if grant['revoked'] else ('expired' if grant['expires']<=now else 'active'))
        with self.connect() as db:
            batch_revoked=db.execute('SELECT revoked FROM batches WHERE id=?',(code['batch_id'],)).fetchone()[0]
            approved=db.execute('SELECT id,label,domain FROM access_requests WHERE approval_session_id=? AND created>=? ORDER BY created DESC LIMIT 1',(sid,now-self.activity_settings()['retention_days']*86400)).fetchone()
        if batch_revoked:state='revoked'
        return dict(grant,code_id=code['id'],hint=code['hint'],batch_id=code['batch_id'],batch_name=code['batch_name'],ip=code['used_ip'],state=state,
                    label=(approved['label'] if approved and approved['label'] else ('Approved access' if code['hint']=='AUTO' else code['batch_name'])),
                    requested_domain=approved['domain'] if approved else '',request_id=approved['id'] if approved else None)

    def ui_requests(self,result):
        for item in result['items']:
            if item['state']=='pending':item.update(self.request_detail(item['id']))
        return result

    def ui_home(self,now=None):
        now=time.time() if now is None else now
        with self.connect() as db:
            pending_count=db.execute("SELECT count(*) FROM access_requests WHERE status='pending' AND created>?",(now-86400,)).fetchone()[0]
            ids=[r[0] for r in db.execute("SELECT id FROM access_requests WHERE status='pending' AND created>? ORDER BY created,id LIMIT 4",(now-86400,))]
            available=db.execute("SELECT count(*) FROM codes c JOIN batches b ON b.id=c.batch WHERE b.timing_mode!='approval' AND b.removed_at IS NULL AND c.used IS NULL AND c.revoked=0 AND b.revoked=0 AND b.starts<=? AND b.ends>?",(now,now)).fetchone()[0]
            outputs=[dict(r) for r in db.execute("SELECT s.id,s.name,count(*) AS ready FROM schedule_runs r JOIN schedules s ON s.id=r.schedule JOIN batches b ON b.id=r.batch WHERE r.status='ready' AND r.expires>? AND b.revoked=0 AND b.removed_at IS NULL GROUP BY s.id ORDER BY min(r.created) LIMIT 5",(now,))]
        sessions=self.ui_sessions(now=now)
        return dict(pending_count=pending_count,requests=[self.request_detail(rid) for rid in ids],sessions=sessions['items'][:4],active_count=sessions['total'],available_count=available,outputs=outputs)
