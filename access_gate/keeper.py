"""Expire grants and close that client's proxy TCP sockets (pilot)."""
import ipaddress
import json
import subprocess
import time
from pathlib import Path
from .core import Store


def expire(store, kill, now=None):
    now = time.time() if now is None else now
    with store.connect() as db:
        db.execute('BEGIN IMMEDIATE')
        rows = db.execute('SELECT ip FROM grants WHERE expires<=? OR revoked=1', (now,)).fetchall()
        for row in rows:
            ip = str(ipaddress.ip_address(row['ip']))
            # Hold the DB write lock so no new grant can race with socket cleanup.
            kill(ip)
            db.execute('DELETE FROM grants WHERE ip=?', (ip,))
        db.commit()


def kill_sockets(ip):
    subprocess.run(['/usr/bin/ss','-K','dst',ip,
                    '( sport = :3128 or sport = :3129 or sport = :3130 )'],
                   check=True, timeout=5, stdout=subprocess.DEVNULL)


def main():
    config = json.loads(Path('/etc/access-gate/config.json').read_text())
    store = Store(config['database'], config['pepper'])
    # Startup invalidates every old grant; codes already used stay used.
    with store.connect() as db:
        db.execute('UPDATE grants SET revoked=1')
    while True:
        expire(store, kill_sockets)
        time.sleep(1)


if __name__ == '__main__':
    main()
