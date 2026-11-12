"""Reviewed blocklist snapshots with independent manual/source ownership."""
import secrets
import time
from .blocklist import source_url,download_blocklist,parse_blocklist
from .dns_export import MAX_DOMAINS

MAX_SOURCES=10


class Subscriptions:
    @staticmethod
    def initialize_subscriptions(db,version):
        for sql in (
            '''CREATE TABLE IF NOT EXISTS domain_manual(domain TEXT PRIMARY KEY,enabled INTEGER NOT NULL,
               include_subdomains INTEGER NOT NULL,deleted INTEGER NOT NULL DEFAULT 0)''',
            '''CREATE TABLE IF NOT EXISTS blocklist_sources(id TEXT PRIMARY KEY,name TEXT NOT NULL,url TEXT NOT NULL UNIQUE,
               scope TEXT NOT NULL,interval INTEGER NOT NULL,enabled INTEGER NOT NULL DEFAULT 0,paused INTEGER NOT NULL DEFAULT 0,
               applied TEXT,previous TEXT,pending TEXT,status TEXT NOT NULL DEFAULT 'new',last_success REAL,
               next_due REAL NOT NULL,lease TEXT,lease_until REAL NOT NULL DEFAULT 0)''',
            '''CREATE TABLE IF NOT EXISTS blocklist_revisions(id TEXT PRIMARY KEY,source_id TEXT NOT NULL REFERENCES blocklist_sources(id) ON DELETE CASCADE,
               created REAL NOT NULL,domains INTEGER NOT NULL,added INTEGER NOT NULL,removed INTEGER NOT NULL,skipped INTEGER NOT NULL,duplicates INTEGER NOT NULL)''',
            '''CREATE TABLE IF NOT EXISTS blocklist_members(revision TEXT NOT NULL REFERENCES blocklist_revisions(id) ON DELETE CASCADE,
               domain TEXT NOT NULL,PRIMARY KEY(revision,domain))''',
            'CREATE INDEX IF NOT EXISTS blocklist_domain_owner ON blocklist_members(domain,revision)',
        ):db.execute(sql)
        if version<12:
            # Legacy manual imports remain manual; source ownership is never guessed.
            db.execute('INSERT OR IGNORE INTO domain_manual(domain,enabled,include_subdomains) SELECT domain,enabled,include_subdomains FROM dns_export_domains')

    @staticmethod
    def own_manual(db,names):
        db.executemany('''INSERT OR REPLACE INTO domain_manual(domain,enabled,include_subdomains,deleted)
            SELECT domain,enabled,include_subdomains,0 FROM dns_export_domains WHERE domain=?''',((n,) for n in names))

    @staticmethod
    def materialize_domains(db,now):
        from .core import GateError
        db.execute('DROP TABLE IF EXISTS temp.effective_domains')
        db.execute('CREATE TEMP TABLE effective_domains(domain TEXT PRIMARY KEY,enabled INTEGER NOT NULL,include_subdomains INTEGER NOT NULL)')
        db.execute('''INSERT INTO effective_domains
            SELECT m.domain,1,max(s.scope='subdomains') FROM blocklist_sources s
            JOIN blocklist_members m ON m.revision=s.applied
            WHERE s.enabled=1 AND NOT EXISTS(SELECT 1 FROM domain_manual d WHERE d.domain=m.domain)
            GROUP BY m.domain''')
        db.execute('INSERT INTO effective_domains SELECT domain,enabled,include_subdomains FROM domain_manual WHERE deleted=0')
        if db.execute('SELECT count(*) FROM effective_domains').fetchone()[0]>MAX_DOMAINS:raise GateError('Combined rules exceed the global domain limit; existing rules were kept.')
        db.execute('DELETE FROM dns_export_domains WHERE domain NOT IN(SELECT domain FROM effective_domains)')
        db.execute('''INSERT INTO dns_export_domains(domain,enabled,include_subdomains,created)
            SELECT domain,enabled,include_subdomains,? FROM effective_domains WHERE true
            ON CONFLICT(domain) DO UPDATE SET enabled=excluded.enabled,include_subdomains=excluded.include_subdomains''',(now,))
        db.execute('DROP TABLE effective_domains')

    def create_subscription(self,name,url,scope='subdomains',interval=86400,now=None):
        from .core import GateError,positive_int
        if not isinstance(name,str) or not 1<=len(name.strip())<=80 or any(ord(c)<32 for c in name):raise GateError('Use a source name of 1 to 80 characters.')
        host,path=source_url(url);url='https://'+host+path
        if scope not in ('exact','subdomains'):raise GateError('Choose a valid source scope.')
        interval=positive_int(interval,'Refresh interval',86400)
        if interval not in (3600,21600,86400):raise GateError('Choose hourly, six-hourly or daily refresh.')
        now=time.time() if now is None else now;sid=secrets.token_hex(16)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT count(*) FROM blocklist_sources').fetchone()[0]>=MAX_SOURCES:raise GateError('At most ten blocklist subscriptions are supported.')
            if db.execute('SELECT 1 FROM blocklist_sources WHERE url=?',(url,)).fetchone():raise GateError('That source is already configured.')
            db.execute('INSERT INTO blocklist_sources(id,name,url,scope,interval,next_due) VALUES(?,?,?,?,?,?)',(sid,name.strip(),url,scope,interval,now))
            self._event(db,'subscription.created',details={'state':'review required'});db.commit()
        return sid

    @staticmethod
    def prune_revisions(db,sid):
        db.execute('''DELETE FROM blocklist_revisions WHERE source_id=? AND id NOT IN(
            SELECT applied FROM blocklist_sources WHERE id=? AND applied IS NOT NULL UNION
            SELECT previous FROM blocklist_sources WHERE id=? AND previous IS NOT NULL UNION
            SELECT pending FROM blocklist_sources WHERE id=? AND pending IS NOT NULL)''',(sid,sid,sid,sid))

    def refresh_subscription(self,sid,*,scheduled=False,fetcher=None,now=None):
        from .core import GateError
        now=time.time() if now is None else now;lease=secrets.token_hex(16)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE');source=db.execute('SELECT * FROM blocklist_sources WHERE id=?',(sid,)).fetchone()
            if not source:raise GateError('Source not found.')
            if source['pending'] or source['lease_until']>now:raise GateError('Review the pending snapshot or wait for the active refresh.')
            if scheduled and (not source['enabled'] or source['paused'] or source['next_due']>now):return False
            db.execute('UPDATE blocklist_sources SET lease=?,lease_until=? WHERE id=?',(lease,now+120,sid));db.commit();source=dict(source)
        try:
            parsed=parse_blocklist((fetcher or download_blocklist)(source['url']),source['scope']);revision=secrets.token_hex(16)
            with self.connect() as db:
                db.execute('BEGIN IMMEDIATE');live=db.execute('SELECT * FROM blocklist_sources WHERE id=? AND lease=?',(sid,lease)).fetchone()
                if not live:return False
                # Pausing/removing invalidates a refresh lease. No response can revive it.
                db.execute('INSERT INTO blocklist_revisions VALUES(?,?,?,?,?,?,?,?)',(revision,sid,now,len(parsed['domains']),0,0,parsed['skipped'],parsed['duplicates']))
                db.executemany('INSERT INTO blocklist_members VALUES(?,?)',((revision,n) for n in sorted(parsed['domains'])))
                added=db.execute('SELECT count(*) FROM blocklist_members n WHERE revision=? AND NOT EXISTS(SELECT 1 FROM blocklist_members o WHERE o.revision=? AND o.domain=n.domain)',(revision,live['applied'])).fetchone()[0]
                removed=db.execute('SELECT count(*) FROM blocklist_members o WHERE revision=? AND NOT EXISTS(SELECT 1 FROM blocklist_members n WHERE n.revision=? AND n.domain=o.domain)',(live['applied'],revision)).fetchone()[0]
                if live['applied'] and not added and not removed:
                    # A no-op poll must not replace the last meaningful rollback point.
                    db.execute('DELETE FROM blocklist_revisions WHERE id=?',(revision,))
                    db.execute('UPDATE blocklist_revisions SET skipped=?,duplicates=? WHERE id=?',(parsed['skipped'],parsed['duplicates'],live['applied']))
                    db.execute("UPDATE blocklist_sources SET status='healthy',last_success=?,next_due=?,lease=NULL,lease_until=0 WHERE id=?",(now,now+source['interval'],sid))
                    db.commit();return True
                old_count=db.execute('SELECT domains FROM blocklist_revisions WHERE id=?',(live['applied'],)).fetchone();old_count=old_count[0] if old_count else 0
                review=not scheduled or not old_count or removed>old_count*.20 or added+removed>old_count*.25 or added+removed>10000
                db.execute('UPDATE blocklist_revisions SET added=?,removed=? WHERE id=?',(added,removed,revision))
                db.execute("UPDATE blocklist_sources SET pending=?,status='review required',last_success=?,next_due=?,lease=NULL,lease_until=0 WHERE id=?",(revision,now,now+source['interval'],sid))
                if not review:self.apply_subscription(db,sid,revision,now)
                self.prune_revisions(db,sid);db.commit()
            return True
        except Exception:
            with self.connect() as db:
                db.execute("UPDATE blocklist_sources SET status='refresh failed',next_due=?,lease=NULL,lease_until=0 WHERE id=? AND lease=?",(now+min(source['interval'],900),sid,lease))
            raise GateError('Source download, parsing or application failed. Last applied rules were retained; retry or inspect the source.') from None

    def apply_subscription(self,db,sid,revision,now):
        from .core import GateError
        source=db.execute('SELECT * FROM blocklist_sources WHERE id=?',(sid,)).fetchone()
        if not source or not revision or source['pending']!=revision:raise GateError('The review changed. Reload before applying.')
        db.execute("UPDATE blocklist_sources SET previous=applied,applied=pending,pending=NULL,enabled=1,status='healthy' WHERE id=?",(sid,))
        self.materialize_domains(db,now)
        self._event(db,'subscription.applied',details={'state':'applied'},now=now)

    def subscription_action(self,sid,action,revision='',now=None):
        from .core import GateError
        now=time.time() if now is None else now
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE');source=db.execute('SELECT * FROM blocklist_sources WHERE id=?',(sid,)).fetchone()
            if not source:raise GateError('Source not found.')
            if action=='approve':self.apply_subscription(db,sid,revision,now)
            elif action=='discard':
                if not revision or source['pending']!=revision:raise GateError('The pending review changed.')
                db.execute("UPDATE blocklist_sources SET pending=NULL,status=?,next_due=? WHERE id=?",('healthy' if source['applied'] else 'new',now+source['interval'],sid))
            elif action in ('pause','resume'):
                db.execute('UPDATE blocklist_sources SET paused=?,next_due=?,lease=NULL,lease_until=0 WHERE id=?',(action=='pause',now,sid))
            elif action=='rollback':
                if not revision or source['applied']!=revision or not source['previous']:raise GateError('No matching previous applied snapshot is available.')
                db.execute("UPDATE blocklist_sources SET applied=previous,previous=applied,pending=NULL,paused=1,status='rolled back',lease=NULL,lease_until=0 WHERE id=?",(sid,))
                self.materialize_domains(db,now)
            elif action=='remove':
                db.execute('DELETE FROM blocklist_sources WHERE id=?',(sid,));self.materialize_domains(db,now)
            else:raise GateError('Unknown subscription action.')
            if action!='remove':self.prune_revisions(db,sid)
            self._event(db,'subscription.changed',details={'reason':action},now=now);db.commit()

    def subscriptions(self):
        with self.connect() as db:return [dict(r) for r in db.execute('SELECT * FROM blocklist_sources ORDER BY name,id')]

    def subscription_detail(self,sid):
        from .core import GateError
        with self.connect() as db:
            row=db.execute('SELECT * FROM blocklist_sources WHERE id=?',(sid,)).fetchone()
            if not row:raise GateError('Source not found.')
            item=dict(row);item['revisions']={}
            for key in ('applied','previous','pending'):
                if item[key]:item['revisions'][key]=dict(db.execute('SELECT * FROM blocklist_revisions WHERE id=?',(item[key],)).fetchone())
            item['samples']={}
            for key,first,second in (('additions',item['pending'],item['applied']),('removals',item['applied'],item['pending'])):
                item['samples'][key]=[r[0] for r in db.execute('SELECT domain FROM blocklist_members n WHERE revision=? AND NOT EXISTS(SELECT 1 FROM blocklist_members o WHERE o.revision=? AND o.domain=n.domain) ORDER BY domain LIMIT 20',(first,second))] if item['pending'] else []
            return item

    def refresh_due_subscriptions(self,now=None,fetcher=None):
        now=time.time() if now is None else now
        with self.connect() as db:
            row=db.execute('SELECT id FROM blocklist_sources WHERE enabled=1 AND paused=0 AND pending IS NULL AND next_due<=? AND lease_until<=? ORDER BY next_due LIMIT 1',(now,now)).fetchone()
        if row:
            from .core import GateError
            try:return self.refresh_subscription(row[0],scheduled=True,fetcher=fetcher,now=now)
            except GateError:return False
        return False
