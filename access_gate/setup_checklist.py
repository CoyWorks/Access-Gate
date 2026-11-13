"""Explicit administrator setup acknowledgements, never inferred client trust."""
import hashlib
import json
import secrets
import time

STEPS = (('server','Server health'),('dns','Client DNS'),('domain','First restricted hostname'),
         ('device','Client certificate setup'),('client','End-to-end client test'))


class SetupChecklist:
    @staticmethod
    def initialize_setup(db):
        db.execute("CREATE TABLE IF NOT EXISTS setup_progress(id INTEGER PRIMARY KEY CHECK(id=1),hidden INTEGER NOT NULL DEFAULT 0,revision TEXT NOT NULL,hostname TEXT NOT NULL DEFAULT '')")
        db.execute("CREATE TABLE IF NOT EXISTS setup_steps(step TEXT PRIMARY KEY,state TEXT NOT NULL DEFAULT 'pending',confirmed_at REAL,context TEXT NOT NULL DEFAULT '')")
        db.execute('INSERT OR IGNORE INTO setup_progress(id,revision) VALUES(1,?)',(secrets.token_hex(16),))
        db.executemany('INSERT OR IGNORE INTO setup_steps(step) VALUES(?)',[(key,) for key,_ in STEPS])

    def setup_summary(self):
        with self.connect() as db:
            meta=dict(db.execute('SELECT * FROM setup_progress WHERE id=1').fetchone())
            meta['show']=not meta['hidden']
            return meta

    def setup_contexts(self,config,ca,hostname):
        # No version number: an ordinary software update must retain progress.
        from .deployment import FIELDS
        values={key:config.get(key) for key in FIELDS+('dns_mode','dns_upstreams','web_mode','public_portal','remote_gateway')}
        base=json.dumps(values,sort_keys=True,separators=(',',':'))
        restricted=bool(hostname and self.restricted_host(hostname))
        security=self.admin_security(config)
        extras={'server':'','dns':'','domain':(hostname,restricted),'device':ca,
                'client':(hostname,restricted,ca,security['exclusions'])}
        return {key:hashlib.sha256((base+json.dumps(extras[key],sort_keys=True)).encode()).hexdigest() for key,_ in STEPS}

    def setup_checklist(self,config,ca):
        meta=self.setup_summary()
        contexts=self.setup_contexts(config,ca,meta['hostname'])
        with self.connect() as db:rows={r['step']:dict(r) for r in db.execute('SELECT * FROM setup_steps')}
        steps=[]
        for key,title in STEPS:
            row=rows[key]
            if row['state']=='done' and row['context']!=contexts[key]:row['state']='needs-review'
            steps.append(dict(row,title=title))
        meta.update(steps=steps,confirmed=sum(r['state']=='done' for r in steps),skipped=sum(r['state']=='skipped' for r in steps))
        meta['complete']=meta['confirmed']==len(STEPS)
        return meta

    def change_setup(self,config,ca,revision,action,step='',hostname='',ack=''):
        from .core import GateError
        from .dns_export import hostname as normalize_hostname
        if action not in ('done','skip','reset','hide','show'):raise GateError('Unknown setup action.')
        if action not in ('hide','show') and step not in dict(STEPS):raise GateError('Unknown setup step.')
        if action=='done' and ack!='1':raise GateError('Confirm the described check before marking this step complete.')
        if action=='done' and step=='domain':
            hostname=normalize_hostname(hostname)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            meta=dict(db.execute('SELECT * FROM setup_progress WHERE id=1').fetchone())
            if revision!=meta['revision']:raise GateError('Setup changed in another tab. Refresh before saving.')
            if action=='done' and step=='domain' and not self.restricted_host(hostname):
                raise GateError('Choose an enabled restricted hostname from Restricted domains.')
            selected=hostname if action=='done' and step=='domain' else meta['hostname']
            if action=='done' and step=='client' and (not selected or not self.restricted_host(selected)):
                raise GateError('Select an enabled restricted hostname in step 3 first.')
            if action=='done' and step in ('device','client') and not config['public_portal'] and not ca:
                raise GateError('The public device CA is unavailable. Check System status before confirming client setup.')
            if action in ('hide','show'):
                db.execute('UPDATE setup_progress SET hidden=? WHERE id=1',(int(action=='hide'),))
            else:
                context=self.setup_contexts(config,ca,selected)[step] if action=='done' else ''
                state={'done':'done','skip':'skipped','reset':'pending'}[action]
                db.execute('UPDATE setup_steps SET state=?,confirmed_at=?,context=? WHERE step=?',
                           (state,time.time() if action=='done' else None,context,step))
                if action=='done' and step=='domain':db.execute('UPDATE setup_progress SET hostname=? WHERE id=1',(selected,))
            db.execute('UPDATE setup_progress SET revision=? WHERE id=1',(secrets.token_hex(16),))
            self._event(db,'setup.changed',details=dict(reason=(step+':'+action) if step in dict(STEPS) else action))
            db.commit()
