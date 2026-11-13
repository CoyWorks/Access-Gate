"""Read-only, bounded system health; no private keys or browsing data."""
import datetime as dt
import http.client
import json
from pathlib import Path
import ssl
import socket
import subprocess
import threading
import time
from urllib.parse import urlsplit
from cryptography import x509
from cryptography.hazmat.primitives import hashes


class Health:
    def __init__(self,config,store,clock=time.time,ca_file='/var/lib/access-gate/public/ca.crt',gateway_address=None):
        from .deployment import normalize
        self.config=normalize(config); self.store=store; self.clock=clock
        self.ca_file=ca_file; self.gateway_address=gateway_address or (self.config['listen_ipv4'],443)
        self.cached=None; self.checked=0; self.lock=threading.Lock()

    @staticmethod
    def command(args):
        result=subprocess.run(args,capture_output=True,text=True,timeout=1,check=False)
        if result.returncode: raise OSError('Status command unavailable.')
        return result.stdout.strip()

    @staticmethod
    def item(name,state,detail,action=''):
        return dict(name=name,state=state,detail=detail,action=action)

    def certificate(self,name,stamp,now,fingerprint=None):
        days=int((stamp-now)//86400)
        state='failed' if stamp<=now else ('warning' if days<30 else 'healthy')
        result=self.item(name,state,'Expires '+dt.datetime.fromtimestamp(stamp,dt.timezone.utc).isoformat()+f' ({days} days).','Renew through the documented certificate/update procedure.' if state!='healthy' else '')

        return dict(result,expires_at=stamp,sha256=fingerprint)

    def gateway(self,now):
        # Use the public CA copy, never the protected root-key directory.
        ca=Path(self.ca_file)
        root=x509.load_pem_x509_certificate(ca.read_bytes())
        context=ssl.create_default_context()
        context.load_verify_locations(cafile=str(ca))
        target=urlsplit(self.config['portal_url'])
        connection=http.client.HTTPSConnection(target.hostname,443,timeout=1,context=context)
        try:
            connection.sock=context.wrap_socket(socket.create_connection(self.gateway_address,timeout=1),server_hostname=target.hostname)
            cert=x509.load_der_x509_certificate(connection.sock.getpeercert(binary_form=True))
            connection.request('GET','/__access_gate/health',headers={'Connection':'close'})
            response=connection.getresponse(); body=response.read(8193)
            if response.status!=200 or len(body)>8192: raise ValueError('Invalid gateway health response.')
            data=json.loads(body)
            if data.get('gateway')!='ready': raise ValueError('Gateway not ready.')
            issuer=dt.datetime.fromisoformat(data['issuer_expires'])
            if issuer.tzinfo is None: raise ValueError('Invalid issuer time.')
            activity=self.item('Activity delivery','warning' if data.get('activity_dropped',0) else 'healthy',f"Queued: {data.get('activity_queue',0)}; dropped since gateway start: {data.get('activity_dropped',0)}.",'Inspect portal/gateway availability; lost visit metadata cannot be recovered.' if data.get('activity_dropped',0) else '')
            return [activity,self.item('Gateway HTTPS','healthy','Verified HTTPS listener and issuing-key setup respond. This does not test a restricted website or Pi-hole.'),
                    self.certificate('Portal certificate',cert.not_valid_after.replace(tzinfo=dt.timezone.utc).timestamp(),now,cert.fingerprint(hashes.SHA256()).hex().upper()),
                    self.certificate('Gateway issuing certificate',issuer.timestamp(),now),
                    self.certificate('Device root CA',root.not_valid_after.replace(tzinfo=dt.timezone.utc).timestamp(),now,root.fingerprint(hashes.SHA256()).hex().upper())]
        finally: connection.close()

    def performance(self):
        target=urlsplit(self.config['portal_url']);context=ssl.create_default_context();context.load_verify_locations(cafile=self.ca_file)
        connection=http.client.HTTPSConnection(target.hostname,443,timeout=1,context=context)
        try:
            connection.sock=context.wrap_socket(socket.create_connection(self.gateway_address,timeout=1),server_hostname=target.hostname)
            connection.request('GET','/__access_gate/performance',headers={'X-Gate-Metrics-Key':self.config['acl_token'],'Connection':'close'})
            response=connection.getresponse();data=response.read(32769)
            if response.status!=200 or len(data)>32768:raise ValueError('Performance snapshot unavailable.')
            result=json.loads(data)
            if result.get('format')!=1:raise ValueError('Unknown snapshot format.')
            return result
        finally:connection.close()

    def collect(self):
        now=self.clock(); checks=[]
        try:
            version=(Path(__file__).resolve().parents[1]/'VERSION').read_text().strip()
        except OSError: version='Unknown'
        checks.append(self.item('Portal','healthy','This installed portal answered the authenticated health request.'))
        try:
            with self.store.connect() as db: db.execute('SELECT 1 FROM administrator_policy LIMIT 1').fetchone()
            checks.append(self.item('Database','healthy','Application database is readable.'))
        except Exception:
            checks.append(self.item('Database','failed','Application database is unavailable.','Check portal service logs and data-directory permissions.'))
        for name in ('access-gate','access-gate-gateway','access-gate-maintenance','access-gate-scheduler','access-gate-push','nginx')+(('access-gate-dns','access-gate-dns-rules') if self.config['dns_mode']=='builtin' else ())+(('access-gate-remote-domains',) if self.config['remote_gateway'] else ()):
            try:
                # is-active returns non-zero for inactive/failed; show gives the state without that ambiguity.
                state=self.command(['systemctl','show',name+'.service','--property=ActiveState','--value'])
                if state not in ('active','inactive','failed','activating','deactivating','reloading'): raise ValueError()
                checks.append(self.item(name,'healthy' if state=='active' else 'failed','Service state: '+state+'.','Inspect this service with systemctl status.' if state!='active' else ''))
            except (OSError,ValueError,subprocess.SubprocessError):
                checks.append(self.item(name,'unknown','Service status could not be read.','Check systemd availability and service logs on the server.'))
        if self.config['remote_gateway']:
            with self.store.connect() as db:stamp=db.execute('SELECT updated FROM remote_sync_status WHERE id=1').fetchone()
            good=bool(stamp and now-stamp[0]<90)
            checks.append(self.item('Remote DNS synchronization','healthy' if good else 'warning','Remote rules synchronized.' if good else 'Remote rule synchronization is missing or stale.','Check access-gate-remote-domains.service.' if not good else ''))
        if self.config['dns_mode']=='builtin':
            try:
                from .dns_health_view import read_small
                status=read_small('/var/lib/access-gate/dns/status.json',4096)
                good=status['state']=='healthy' and 0<=now-status['updated']<15
                checks.append(self.item('DNS synchronization','healthy' if good else 'failed','Rules synchronized.' if good else 'DNS rules are stale or synchronization failed.','Check access-gate-dns-rules.service.' if not good else ''))
            except (OSError,ValueError,KeyError,TypeError):checks.append(self.item('DNS synchronization','unknown','DNS synchronization status unavailable.','Check the DNS publisher service.'))
        if self.config['dns_mode']=='builtin':
            from .dns_health_view import read_health
            dns_health=read_health(self.config)
            state={'healthy':'healthy','degraded':'warning','failed':'failed'}.get(dns_health['state'],'unknown')
            checks.append(self.item('DNS probes',state,dns_health['message'],'Open DNS health for UDP/TCP, upstream and snapshot details.'))
        try:
            synced=self.command(['timedatectl','show','--property=NTPSynchronized','--value'])
            if synced not in ('yes','no'): raise ValueError()
            checks.append(self.item('Clock synchronization','healthy' if synced=='yes' else 'warning','System clock synchronization: '+synced+'.','Check timedatectl and the configured time service.' if synced=='no' else ''))
        except (OSError,ValueError,subprocess.SubprocessError):
            checks.append(self.item('Clock synchronization','unknown','Clock synchronization could not be verified.','Check timedatectl on the server.'))
        try: checks.extend(self.gateway(now))
        except FileNotFoundError:
            checks.append(self.item('Gateway HTTPS','unknown','Public CA copy or gateway setup is missing.','Run the normal updater; verify /var/lib/access-gate/public/ca.crt.'))
        except (OSError,ValueError,KeyError,TypeError,http.client.HTTPException):
            checks.append(self.item('Gateway HTTPS','failed','Verified gateway HTTPS or certificate probe failed.','Check gateway service logs, portal certificate, public CA and server clock.'))
        overall='failed' if any(c['state']=='failed' for c in checks) else ('warning' if any(c['state'] in ('warning','unknown') for c in checks) else 'healthy')
        return dict(version=version,checked_at=now,state=overall,checks=checks,stale=False,cache_seconds=15,
                    scope='Local portal/gateway checks only. DNS sync, public-origin reachability and device enforcement require an end-to-end test.')

    def snapshot(self):
        now=time.monotonic()
        if self.cached is not None and now-self.checked<15: return dict(self.cached)
        if not self.lock.acquire(blocking=False):
            if self.cached is not None: return dict(self.cached,state='unknown',stale=True)
            return dict(version='Unknown',checked_at=None,state='unknown',checks=[],stale=True,cache_seconds=15,scope='Health checks are running. Refresh shortly.')
        try:
            result=self.collect(); self.cached=result; self.checked=time.monotonic()
            return dict(result)
        finally: self.lock.release()
