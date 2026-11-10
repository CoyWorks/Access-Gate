"""Expire restricted connections, apply domain rules and serve live VPN identity."""
import ipaddress
import json
import os
import socket
import subprocess
import threading
import time
from pathlib import Path
from .core import Store
from .control import ControlServer
from .identity import FortiGate,IdentityUnavailable
from .policy import apply_policy


def expire(store,kill,now=None,targeted=False):
    with store.connect() as db:
        db.execute('BEGIN IMMEDIATE')
        now=time.time() if now is None else now
        rows=db.execute('SELECT ip,session_id FROM grants WHERE expires<=? OR revoked=1',(now,)).fetchall()
        for row in rows:
            ip=str(ipaddress.ip_address(row['ip']))
            if targeted:
                sockets=db.execute('SELECT * FROM proxy_connections WHERE session_id=?',(row['session_id'],)).fetchall()
                for connection in sockets: kill(dict(connection))
            else: kill(ip)  # Compatibility for legacy callers and conservative migration cleanup.
            db.execute('DELETE FROM grants WHERE ip=?',(ip,))
        db.commit()


def kill_sockets(ip):
    subprocess.run(['/usr/bin/ss','-K','dst',str(ipaddress.ip_address(ip)),
                    '( sport = :3128 or sport = :3129 or sport = :3130 )'],
                   check=True,timeout=5,stdout=subprocess.DEVNULL)


def kill_connection(connection,run=subprocess.run):
    ip=str(ipaddress.ip_address(connection['ip']))
    local=str(ipaddress.ip_address(connection['local_ip']))
    client_port=int(connection['client_port']); local_port=int(connection['local_port'])
    if local_port not in (3128,3129,3130) or not 1<=client_port<=65535: raise ValueError('Invalid tracked socket.')
    run(['/usr/bin/ss','-K','src',local,'dst',ip,'sport','=',str(local_port),'dport','=',str(client_port)],
        check=True,timeout=5,stdout=subprocess.DEVNULL)


def close_proxy_connections():
    subprocess.run(['/usr/bin/ss','-K','( sport = :3128 or sport = :3129 or sport = :3130 )'],
                   check=True,timeout=5,stdout=subprocess.DEVNULL)


def reconcile_identity(store,sessions,now=None):
    now=time.time() if now is None else now
    live={(s['ip'],s['username'],s['binding']) for s in sessions}
    with store.connect() as db:
        db.execute('BEGIN IMMEDIATE')
        rows=db.execute('SELECT g.ip,g.device_id,g.vpn_binding,d.username,d.enabled FROM grants g LEFT JOIN devices d ON d.id=g.device_id').fetchall()
        for row in rows:
            if not row['enabled'] or (row['ip'],row['username'],row['vpn_binding']) not in live:
                db.execute('UPDATE grants SET revoked=1 WHERE ip=?',(row['ip'],))
        db.execute("UPDATE devices SET state='Not connected' WHERE enabled=1")
        for s in sessions:
            db.execute("UPDATE devices SET state='Verified',last_ip=?,last_seen=?,binding=? WHERE username=? AND enabled=1",(s['ip'],now,s['binding'],s['username']))
        db.commit()


def main():
    config=json.loads(Path('/etc/access-gate/config.json').read_text())
    store=Store(config['database'],config['pepper']); store.initialize()
    store.import_domains(config['domains'])
    with store.connect() as db:
        db.execute('UPDATE grants SET revoked=1')
        db.execute('UPDATE policy_state SET healthy=0,heartbeat=0 WHERE id=1')
    # Stop any previously permitted streams before publishing a healthy worker.
    close_proxy_connections()
    expire(store,kill_connection,targeted=True)
    source_path=Path('/etc/access-gate/fortigate.json')
    source=FortiGate(json.loads(source_path.read_text())) if source_path.exists() else None
    socket_path='/run/access-gate/control.sock'
    try: os.unlink(socket_path)
    except FileNotFoundError: pass
    server=ControlServer(socket_path,store,source)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    state={'clock_ok':False,'error':None}
    def maintenance():
        last_revision=None; clock_check=0
        try:
            while True:
                stamp=time.monotonic()
                if stamp-clock_check>30 or not clock_check:
                    state['clock_ok']=subprocess.run(['/usr/bin/timedatectl','show','-p','NTPSynchronized','--value'],capture_output=True,text=True,timeout=3,check=True).stdout.strip()=='yes'
                    clock_check=stamp
                policy=store.policy_status()
                if policy['desired']!=last_revision or policy['applying']:
                    # A changed restriction list also has to cover existing spliced tunnels.
                    close_proxy_connections()
                    apply_policy(store,close_connections=close_proxy_connections,force=True)
                    last_revision=policy['desired']
                if config.get('require_identity',False):
                    try:
                        if source is None: raise IdentityUnavailable('FortiGate reader not configured.')
                        reconcile_identity(store,source.snapshot())
                    except IdentityUnavailable:
                        reconcile_identity(store,[])
                time.sleep(1)
        except Exception as exc: state['error']=exc
    threading.Thread(target=maintenance,daemon=True).start()
    previous_clock=None
    def notify(message):
        address=os.environ.get('NOTIFY_SOCKET')
        if address:
            if address.startswith('@'): address='\0'+address[1:]
            with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as notifier:
                notifier.connect(address); notifier.sendall(message.encode())
    notify('READY=1')
    while True:
        started=time.monotonic()
        try:
            if state['error']: raise state['error']
            now=time.time()
            jumped=previous_clock and abs((now-previous_clock[0])-(started-previous_clock[1]))>2
            previous_clock=(now,started)
            if jumped or not state['clock_ok']:
                with store.connect() as db: db.execute('UPDATE grants SET revoked=1')
            expire(store,kill_connection,targeted=True)
            with store.connect() as db:
                db.execute('UPDATE policy_state SET heartbeat=?,healthy=? WHERE id=1',(time.monotonic(),int(state['clock_ok'])))
            notify('WATCHDOG=1')
        except Exception as exc:
            with store.connect() as db:
                db.execute('UPDATE policy_state SET healthy=0 WHERE id=1')
                db.execute('UPDATE grants SET revoked=1')
            close_proxy_connections()
            print('Access Gate worker failed: '+type(exc).__name__+'. Check service logs.',flush=True)
            raise
        time.sleep(max(0.05,0.5-(time.monotonic()-started)))


def stop():
    # Cleanup must still run if database/configuration state is damaged.
    try:
        config=json.loads(Path('/etc/access-gate/config.json').read_text())
        store=Store(config['database'],config['pepper'])
        with store.connect() as db:
            db.execute('UPDATE policy_state SET healthy=0,heartbeat=0 WHERE id=1')
            db.execute('UPDATE grants SET revoked=1')
    finally:
        try: close_proxy_connections()
        except Exception:
            subprocess.run(['/usr/bin/systemctl','stop','squid.service'],check=True,timeout=10)


if __name__=='__main__':
    import sys
    stop() if '--stop' in sys.argv else main()
