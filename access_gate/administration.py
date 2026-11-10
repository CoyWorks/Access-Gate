"""Persistent administrator policy and bounded browser-session administration."""
import hashlib
import ipaddress
import json
import secrets
import time


def management_networks(value):
    from .core import GateError
    if not isinstance(value,str) or len(value)>4096: raise GateError('Enter at most 64 management networks.')
    parts=value.replace(',',' ').split()
    if not parts or len(parts)>64: raise GateError('Enter between 1 and 64 management networks.')
    try: return list(dict.fromkeys(str(ipaddress.ip_network(p,strict=False)) for p in parts))
    except ValueError: raise GateError('Use valid IPv4 or IPv6 networks, one per line.')


class Administration:
    @staticmethod
    def initialize_administration(db):
        db.execute('''CREATE TABLE IF NOT EXISTS administrator_policy(
            id INTEGER PRIMARY KEY CHECK(id=1), password_hash TEXT, version TEXT NOT NULL,
            networks TEXT)''')

    def admin_security(self,config):
        with self.connect() as db:return self._admin_security(db,config)

    def _admin_security(self,db,config):
        row=db.execute('SELECT * FROM administrator_policy WHERE id=1').fetchone()
        fallback=hashlib.sha256((config['secret']+'\0'+config['admin_hash']).encode()).hexdigest()
        return dict(password_hash=row['password_hash'] if row and row['password_hash'] else config['admin_hash'],
                    version=row['version'] if row else fallback,
                    exclusions=json.loads(row['exclusions']) if row else [],
                    networks=json.loads(row['networks']) if row and row['networks'] else config.get('admin_networks',config.get('client_networks',['10.40.0.0/16','127.0.0.1/32','::1/128'])))

    def save_admin_security(self,config,expected_version=None,password_hash=None,networks=None,reset_networks=False,exclusions=None):
        from .core import GateError
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT * FROM administrator_policy WHERE id=1').fetchone()
            fallback=hashlib.sha256((config['secret']+'\0'+config['admin_hash']).encode()).hexdigest()
            current_version=row['version'] if row else fallback
            if expected_version is not None and expected_version!=current_version:
                raise GateError('Administrator settings changed. Reload and try again.')
            saved_hash=password_hash if password_hash is not None else (row['password_hash'] if row else None)
            saved_networks=None if reset_networks else (json.dumps(networks) if networks is not None else (row['networks'] if row else None))
            version=secrets.token_hex(32)
            saved_exclusions=json.dumps(exclusions) if exclusions is not None else (row['exclusions'] if row else '[]')
            db.execute('INSERT OR REPLACE INTO administrator_policy(id,password_hash,version,networks,exclusions) VALUES(1,?,?,?,?)',(saved_hash,version,saved_networks,saved_exclusions))
            self._event(db,'admin.policy_changed',details=dict(reason='password' if password_hash is not None else ('exclusions' if exclusions is not None else 'networks')))
            db.commit()
        return version

    def terminate_session(self,session_id,now=None):
        from .core import GateError
        now=time.time() if now is None else now
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT session_id FROM grants WHERE session_id=?',(session_id,)).fetchone()
            if not row: raise GateError('Browser session not found.')
            changed=db.execute('UPDATE grants SET revoked=1 WHERE session_id=? AND revoked=0 AND expires>?',(session_id,now)).rowcount
            if changed:self._event(db,'session.terminated',session_id=session_id,code_id=db.execute('SELECT code FROM grants WHERE session_id=?',(session_id,)).fetchone()[0],now=now)
            db.commit()
        return bool(changed)

    def session_overview(self,state='active',page=1,now=None):
        from .core import GateError,positive_int
        now=time.time() if now is None else now
        if state not in ('active','expired','revoked','terminated','all'): raise GateError('Invalid session state.')
        page=positive_int(page,'Page',1000000)
        expression="CASE WHEN c.revoked=1 OR b.revoked=1 THEN 'revoked' WHEN g.revoked=1 THEN 'terminated' WHEN g.expires<=:now THEN 'expired' ELSE 'active' END"
        join=' FROM grants g JOIN codes c ON c.id=g.code JOIN batches b ON b.id=c.batch'
        where='' if state=='all' else ' WHERE ('+expression+')=:state'
        values=dict(now=now,state=state)
        with self.connect() as db:
            db.execute('BEGIN')
            total=db.execute('SELECT count(*)'+join+where,values).fetchone()[0]
            counts={r['state']:r['total'] for r in db.execute('SELECT '+expression+' AS state,count(*) AS total'+join+' GROUP BY state',values)}
            pages=max(1,(total+99)//100); page=min(page,pages); values['offset']=(page-1)*100
            rows=db.execute('SELECT g.session_id,g.ip,g.started,g.expires,b.name AS batch_name,b.id AS batch_id,c.hint,'+expression+' AS state'+join+where+' ORDER BY g.started DESC,g.session_id LIMIT 100 OFFSET :offset',values).fetchall()
        return dict(items=[dict(r) for r in rows],total=total,counts=counts,page=page,pages=pages,server_time=now)
