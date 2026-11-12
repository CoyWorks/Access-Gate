"""Fixed DNS probes and short aggregate health history, never client query logs."""
from collections import deque
import json
from pathlib import Path
import secrets
import threading
import time
import dns.exception
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
from .dns_health_view import fingerprint,read_small
from .settings import atomic_write


def aggregate():return dict(count=0,success=0,failure=0,total_ms=0.,max_ms=0.,last_success=None,state='unknown',reason='Not checked')


class DNSMonitor:
    def __init__(self,config,directory,*,clock=time.monotonic,wall=time.time,port=53):
        self.config=config;self.directory=Path(directory);self.clock=clock;self.wall=wall;self.port=port
        self.started=wall();self.boot_id=secrets.token_hex(8);self.configuration=fingerprint(config)
        self.local={kind:aggregate() for kind in ('UDP','TCP')}
        self.upstreams={address:aggregate() for address in config['dns_upstreams']}
        self.history=deque(maxlen=72);self.updated=self.started;self.publisher=dict(state='unknown',age_seconds=None)

    def check(self,stats,probe):
        start=self.clock();ok=False;reason='Invalid response'
        try:ok=bool(probe());reason='Valid response' if ok else 'Invalid response'
        except (dns.exception.Timeout,TimeoutError):reason='Timeout'
        except (dns.exception.DNSException,OSError,ValueError):reason='Network or DNS error'
        elapsed=max(0,1000*(self.clock()-start));stats['count']+=1;stats['success' if ok else 'failure']+=1
        stats.update(state='healthy' if ok else 'failed',reason=reason,total_ms=stats['total_ms']+elapsed,max_ms=max(stats['max_ms'],elapsed))
        if ok:stats['last_success']=self.wall()

    def probe_local(self,kind):
        query=dns.message.make_query(self.config['portal_names'][0],'A')
        send=dns.query.udp if kind=='UDP' else dns.query.tcp
        response=send(query,self.config['listen_ipv4'],port=self.port,timeout=1)
        return response.rcode()==dns.rcode.NOERROR and any(rr.name==query.question[0].name and rr.rdtype==dns.rdatatype.A and any(str(r)==self.config['dns_target_ipv4'] for r in rr) for rr in response.answer)

    @staticmethod
    def probe_upstream(address):
        # A fixed root NS probe is independent of user browsing or restricted lists.
        query=dns.message.make_query('.','NS')
        response,_=dns.query.udp_with_fallback(query,address,timeout=1)
        return response.rcode()==dns.rcode.NOERROR and any(rr.name==query.question[0].name and rr.rdtype==dns.rdatatype.NS and len(rr) for rr in response.answer)

    def publisher_status(self):
        try:
            data=read_small(self.directory/'status.json',4096);age=self.wall()-data['updated']
            if not 0<=age<=15:return dict(state='unknown',age_seconds=max(0,age))
            return dict(state='healthy' if data['state']=='healthy' else 'failed',age_seconds=age)
        except (OSError,ValueError,KeyError,TypeError):return dict(state='unknown',age_seconds=None)

    def state(self):
        rows=list(self.local.values())+list(self.upstreams.values())
        if any(row['state']=='unknown' for row in rows):return 'unknown'
        if any(row['state']=='failed' for row in self.local.values()) or self.publisher['state']=='failed':return 'failed'
        successes=sum(row['state']=='healthy' for row in self.upstreams.values())
        if not successes:return 'failed'
        if self.publisher['state']!='healthy':return 'unknown'
        return 'healthy' if successes==len(self.upstreams) else 'degraded'

    def snapshot(self):
        def export(rows):return {name:dict(row,mean_ms=row['total_ms']/row['count'] if row['count'] else None) for name,row in rows.items()}
        return dict(format=1,configuration=self.configuration,boot_id=self.boot_id,started=self.started,updated=self.updated,state=self.state(),local=export(self.local),upstreams=export(self.upstreams),publisher=self.publisher,history=list(self.history),scope='Fixed monitor probes since this monitor process started. Latencies include failed attempts. No client addresses, query names, answers or individual user queries are recorded. Restart resets these counters and history.')

    def publish(self):atomic_write(self.directory/'health.json',json.dumps(self.snapshot(),separators=(',',':'))+'\n',0o640)

    def cycle(self):
        for kind,stats in self.local.items():self.check(stats,lambda kind=kind:self.probe_local(kind))
        for address,stats in self.upstreams.items():self.check(stats,lambda address=address:self.probe_upstream(address))
        self.publisher=self.publisher_status();self.updated=self.wall()
        self.history.append(dict(at=self.updated,state=self.state(),udp=self.local['UDP']['state'],tcp=self.local['TCP']['state'],upstreams_ok=sum(r['state']=='healthy' for r in self.upstreams.values()),upstreams_total=len(self.upstreams),publisher=self.publisher['state']))
        self.publish()

    def run(self,stop):
        self.publish() # Zero samples at startup are Unknown, never Healthy.
        while not stop.is_set():
            try:self.cycle()
            except Exception:pass # Staleness is exposed by the bounded reader; no raw query/error logs.
            stop.wait(10)
