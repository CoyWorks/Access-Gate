"""An optional, persistent hostname list for Pi-hole DNS exports."""
import ipaddress
import re
import time

TARGET_IP = '10.40.22.5'
MAX_DOMAINS = 5000
LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?')


def hostname(value):
    from .core import GateError
    try:
        if not isinstance(value, str): raise ValueError()
        value = value.strip().removesuffix('.')
        if not value or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value): raise ValueError()
        name = value.encode('idna').decode('ascii').lower()
        labels = name.split('.')
        if len(name) > 253 or len(labels) < 2 or not all(LABEL.fullmatch(label) for label in labels): raise ValueError()
        if labels[-1].isdigit(): raise ValueError()
        try: ipaddress.ip_address(name)
        except ValueError: return name
        raise ValueError()
    except (ValueError, UnicodeError):
        raise GateError('Use a hostname such as example.com, without a URL, port, wildcard or IP address.')


class DNSExports:
    def initialize_dns_exports(self, db):
        db.execute('''CREATE TABLE IF NOT EXISTS dns_export_domains(
            domain TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
            include_subdomains INTEGER NOT NULL DEFAULT 1 CHECK(include_subdomains IN (0,1)),
            created REAL NOT NULL)''')

    def list_dns_domains(self):
        with self.connect() as db:
            return [dict(r) for r in db.execute('SELECT * FROM dns_export_domains ORDER BY domain')]

    def add_dns_domains(self, text, scope='subdomains'):
        from .core import GateError
        if scope not in ('subdomains', 'exact'): raise GateError('Choose a valid domain match scope.')
        if not isinstance(text, str) or len(text) > 12000:
            raise GateError('Paste at most 12,000 characters at a time.')
        names = set()
        for number, line in enumerate(text.splitlines(), 1):
            if not line.strip() or line.lstrip().startswith('#'): continue
            if scope == 'subdomains': line = line.strip().removeprefix('*.')
            try: names.add(hostname(line))
            except GateError as exc: raise GateError(f'Line {number}: {exc}') from exc
        if not names: raise GateError('Enter at least one hostname, one per line.')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            existing = {r[0] for r in db.execute('SELECT domain FROM dns_export_domains')}
            additions = names - existing
            if len(existing) + len(additions) > MAX_DOMAINS:
                raise GateError(f'The list can contain at most {MAX_DOMAINS:,} hostnames.')
            db.executemany('INSERT INTO dns_export_domains(domain,include_subdomains,created) VALUES(?,?,?)',
                           [(name, int(scope == 'subdomains'), time.time()) for name in sorted(additions)])
            db.commit()
        return len(additions), len(names & existing)

    def change_dns_domain(self, name, action):
        from .core import GateError
        name = hostname(name)
        if action not in ('enable', 'disable', 'delete', 'exact', 'subdomains'): raise GateError('Unknown domain action.')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if action == 'delete':
                changed = db.execute('DELETE FROM dns_export_domains WHERE domain=?', (name,))
            elif action in ('exact', 'subdomains'):
                changed = db.execute('UPDATE dns_export_domains SET include_subdomains=? WHERE domain=?', (int(action == 'subdomains'), name))
            else:
                changed = db.execute('UPDATE dns_export_domains SET enabled=? WHERE domain=?', (int(action == 'enable'), name))
            if not changed.rowcount: raise GateError('That hostname is no longer in the list. Reload the page.')
            db.commit()

    def export_dns_domains(self, kind):
        from .core import GateError
        if kind not in ('hosts', 'dnsmasq'): raise GateError('Unknown DNS export format.')
        rows = [r for r in self.list_dns_domains() if r['enabled']]
        if kind == 'hosts' and any(r['include_subdomains'] for r in rows):
            raise GateError('Hosts files cannot represent subdomain rules. Download the Pi-hole config to preserve wildcard coverage.')
        lines = ['# Access Gate DNS mappings: ' + TARGET_IP,
                 '# Subdomain rules cover the base domain and all subdomain levels.',
                 '# Import as local DNS configuration, not as a Pi-hole adlist.']
        for row in rows:
            name = row['domain']
            if kind == 'hosts': lines.append(f'{TARGET_IP} {name}')
            elif row['include_subdomains']:
                # local= prevents non-A queries (including AAAA/HTTPS) going upstream.
                lines += [f'address=/{name}/{TARGET_IP}', f'local=/{name}/']
            else: lines.append(f'host-record={name},{TARGET_IP}')
        return '\n'.join(lines) + '\n'
