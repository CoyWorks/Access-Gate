"""Persistent domain policy, verified VPN bindings and restricted socket tracking."""
import ipaddress
import json
import re
import secrets
import time


def normalize_domain(value):
    from .core import GateError
    if not isinstance(value,str): raise GateError('Enter a domain name.')
    value=value.strip().rstrip('.').lower()
    if value.startswith('.') or any(c in value for c in '/:*@?#\\'):
        raise GateError('Use a domain without a scheme, path, port or wildcard.')
    try: value=value.encode('idna').decode('ascii')
    except UnicodeError: raise GateError('Invalid domain name.')
    if len(value)>253 or '.' not in value or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',part) for part in value.split('.')):
        raise GateError('Use a valid full domain name, for example example.org.')
    try: ipaddress.ip_address(value)
    except ValueError: return value
    raise GateError('Use a domain name instead of an IP address.')


def rule_matches(host,rules):
    try: host=normalize_domain(host)
    except ValueError: return False
    return any(r['enabled'] and (host==r['domain'] or r['subdomains'] and host.endswith('.'+r['domain'])) for r in rules)


def validate_rule(domain,subdomains,description,portal_hosts=('toegang.coyseinri.nl',)):
    from .core import GateError
    domain=normalize_domain(domain)
    if any(h==domain or subdomains and h.endswith('.'+domain) for h in portal_hosts):
        raise GateError('This rule would restrict the portal itself.')
    if not isinstance(description,str) or len(description)>240 or any(ord(c)<32 for c in description):
        raise GateError('Descriptions must be at most 240 characters without control characters.')
    return domain,description.strip()


class Operations:
    def initialize_operations(self,db,version):
        if version<2:
            for name in ('device_id','vpn_binding'):
                if name not in {r['name'] for r in db.execute('PRAGMA table_info(grants)')}:
                    db.execute(f'ALTER TABLE grants ADD COLUMN {name} TEXT')
        for sql in (
            "CREATE TABLE IF NOT EXISTS domain_rules(id TEXT PRIMARY KEY,domain TEXT UNIQUE NOT NULL,subdomains INTEGER NOT NULL,description TEXT NOT NULL,enabled INTEGER NOT NULL)",
            "CREATE TABLE IF NOT EXISTS policy_state(id INTEGER PRIMARY KEY CHECK(id=1),desired INTEGER NOT NULL DEFAULT 0,applied INTEGER NOT NULL DEFAULT -1,applying INTEGER NOT NULL DEFAULT 0,error TEXT NOT NULL DEFAULT '',applied_json TEXT NOT NULL DEFAULT '[]',imported INTEGER NOT NULL DEFAULT 0,heartbeat REAL NOT NULL DEFAULT 0,healthy INTEGER NOT NULL DEFAULT 0)",
            "INSERT OR IGNORE INTO policy_state(id) VALUES(1)",
            "CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY,username TEXT UNIQUE NOT NULL,label TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,last_ip TEXT,last_seen REAL,binding TEXT,state TEXT NOT NULL DEFAULT 'Not observed')",
            "CREATE TABLE IF NOT EXISTS proxy_connections(ip TEXT NOT NULL,client_port INTEGER NOT NULL,local_ip TEXT NOT NULL,local_port INTEGER NOT NULL,session_id TEXT NOT NULL REFERENCES grants(session_id) ON DELETE CASCADE,PRIMARY KEY(ip,client_port,local_ip,local_port))",
            "CREATE INDEX IF NOT EXISTS proxy_grant ON proxy_connections(session_id)",
            "CREATE INDEX IF NOT EXISTS grants_device ON grants(device_id)",
        ): db.execute(sql)
        if version<2: db.execute('PRAGMA user_version=2')

    def import_domains(self,path):
        from .core import domains
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT imported FROM policy_state WHERE id=1').fetchone()[0]: return
            for domain in domains(path):
                domain,description=validate_rule(domain,True,'Imported from domains.txt')
                db.execute('INSERT OR IGNORE INTO domain_rules VALUES(?,?,?,?,?)',(secrets.token_hex(8),domain,1,description,1))
            db.execute('UPDATE policy_state SET imported=1,desired=desired+1 WHERE id=1')
            db.commit()

    def domain_rules(self,search=''):
        with self.connect() as db:
            return [dict(r) for r in db.execute('SELECT * FROM domain_rules WHERE domain LIKE ? OR description LIKE ? ORDER BY domain',('%'+search[:100]+'%','%'+search[:100]+'%'))]

    def save_domain(self,domain,subdomains=True,description='',enabled=True,rule_id=None):
        from .core import GateError
        domain,description=validate_rule(domain,bool(subdomains),description)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            duplicate=db.execute('SELECT id FROM domain_rules WHERE domain=?',(domain,)).fetchone()
            if duplicate and duplicate['id']!=rule_id: raise GateError('This domain already has a rule.')
            if rule_id:
                if not db.execute('SELECT id FROM domain_rules WHERE id=?',(rule_id,)).fetchone(): raise GateError('Rule not found.')
                db.execute('UPDATE domain_rules SET domain=?,subdomains=?,description=?,enabled=? WHERE id=?',(domain,int(bool(subdomains)),description,int(bool(enabled)),rule_id))
            else:
                rule_id=secrets.token_hex(8)
                db.execute('INSERT INTO domain_rules VALUES(?,?,?,?,?)',(rule_id,domain,int(bool(subdomains)),description,int(bool(enabled))))
            db.execute("UPDATE policy_state SET desired=desired+1,error='' WHERE id=1")
            db.commit()
        return rule_id

    def delete_domain(self,rule_id):
        from .core import GateError
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if not db.execute('DELETE FROM domain_rules WHERE id=?',(rule_id,)).rowcount: raise GateError('Rule not found.')
            db.execute("UPDATE policy_state SET desired=desired+1,error='' WHERE id=1")
            db.commit()

    def policy_status(self):
        with self.connect() as db: return dict(db.execute('SELECT * FROM policy_state WHERE id=1').fetchone())

    def applied_rules(self):
        return json.loads(self.policy_status()['applied_json'])

    def save_device(self,username,label,enabled=True,device_id=None):
        from .core import GateError
        if not isinstance(username,str) or not re.fullmatch(r'[A-Za-z0-9_.@+\\-]{1,128}',username):
            raise GateError('Use the exact VPN username (letters, numbers, dot, hyphen, underscore, @ or +).')
        if not isinstance(label,str) or not label.strip() or len(label)>80 or any(ord(c)<32 for c in label):
            raise GateError('Enter a device label of 1–80 characters without control characters.')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            duplicate=db.execute('SELECT id FROM devices WHERE username=?',(username,)).fetchone()
            if duplicate and duplicate['id']!=device_id: raise GateError('This VPN username is already registered.')
            if device_id:
                current=db.execute('SELECT * FROM devices WHERE id=?',(device_id,)).fetchone()
                if not current: raise GateError('Device not found.')
                if current['username']!=username or not enabled:
                    db.execute('UPDATE grants SET revoked=1 WHERE device_id=?',(device_id,))
                db.execute('UPDATE devices SET username=?,label=?,enabled=? WHERE id=?',(username,label.strip(),int(bool(enabled)),device_id))
            else:
                device_id=secrets.token_hex(16)
                db.execute('INSERT INTO devices(id,username,label,enabled) VALUES(?,?,?,?)',(device_id,username,label.strip(),int(bool(enabled))))
            db.commit()
        return device_id

    def devices(self):
        with self.connect() as db:
            return [dict(r) for r in db.execute('SELECT d.*,(SELECT max(expires) FROM grants g WHERE g.device_id=d.id AND g.revoked=0) AS expires FROM devices d ORDER BY label,id')]

    def observe_identity(self,session,now=None):
        """Only call with data from the trusted live identity source, never browser input."""
        from .core import GateError
        now=time.time() if now is None else now
        ip=str(ipaddress.ip_address(session['ip']))
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            device=db.execute('SELECT * FROM devices WHERE username=?',(session['username'],)).fetchone()
            # Reassignment or reconnect never inherits or silently renews another binding.
            db.execute('UPDATE grants SET revoked=1 WHERE ip=? AND (device_id IS NULL OR device_id!=? OR vpn_binding IS NULL OR vpn_binding!=?)',
                       (ip,device['id'] if device else '',session['binding']))
            if not device or not device['enabled']:
                db.commit(); raise GateError('The verified VPN user is not registered or is disabled.')
            db.execute('UPDATE grants SET revoked=1 WHERE device_id=? AND (ip!=? OR vpn_binding!=?)',(device['id'],ip,session['binding']))
            db.execute("UPDATE devices SET last_ip=?,last_seen=?,binding=?,state='Verified' WHERE id=?",(ip,now,session['binding'],device['id']))
            db.commit()
            return dict(session,device_id=device['id'],label=device['label'])

    def authorize(self,ip,identity=None,connection=None,enforce=False,now=None):
        from .core import GateError,positive_int
        ip=str(ipaddress.ip_address(ip))
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            now=time.time() if now is None else now
            if enforce:
                state=db.execute('SELECT * FROM policy_state WHERE id=1').fetchone()
                age=time.monotonic()-state['heartbeat']
                if not state['healthy'] or not 0<=age<=3 or state['applying']: return None
            row=db.execute('''SELECT g.*,b.name AS batch_name FROM grants g JOIN codes c ON c.id=g.code JOIN batches b ON b.id=c.batch
                WHERE g.ip=? AND g.expires>? AND g.revoked=0 AND c.revoked=0 AND b.revoked=0''',(ip,now)).fetchone()
            if not row: return None
            if identity is not None:
                device=db.execute('SELECT enabled FROM devices WHERE id=?',(identity['device_id'],)).fetchone()
                if not device or not device['enabled'] or row['device_id']!=identity['device_id'] or row['vpn_binding']!=identity['binding']: return None
            if connection is not None:
                client_port=positive_int(connection['client_port'],'Client port',65535)
                local_port=positive_int(connection['local_port'],'Local port',65535)
                local_ip=str(ipaddress.ip_address(connection['local_ip']))
                if local_port not in (3128,3129,3130): raise GateError('Invalid proxy local port.')
                db.execute('INSERT OR REPLACE INTO proxy_connections VALUES(?,?,?,?,?)',(ip,client_port,local_ip,local_port,row['session_id']))
            db.commit()
            return dict(row)
