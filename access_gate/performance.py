"""Process-local aggregate timings with fixed labels and bounded histograms."""
from contextlib import contextmanager
import math
import secrets
import threading
import time

STAGES=('policy_lookup','certificate_hit','certificate_miss','certificate_generate','certificate_renew','authorization','origin_dns','origin_connect_tls','origin_response_headers','portal_response_headers')
COUNTERS=('cache_eviction','policy_error','renew_error','policy_refresh_error')
BUCKETS=(.001,.005,.01,.025,.05,.1,.25,.5,1,2,5,10,30,math.inf)


class Metrics:
    def __init__(self,mode='local',clock=time.monotonic):
        self.mode=mode;self.clock=clock;self.started=time.time();self.boot_id=secrets.token_hex(8);self.lock=threading.Lock();self.dropped=0
        self.data={s:dict(count=0,failed=0,total=0.,maximum=0.,buckets=[0]*len(BUCKETS)) for s in STAGES}
        self.counters=dict.fromkeys(COUNTERS,0)

    def observe(self,stage,seconds,failed=False):
        if stage not in self.data:raise ValueError('Unknown timing stage.')
        if not math.isfinite(seconds) or seconds<0:return
        if not self.lock.acquire(blocking=False):self.dropped+=1;return
        try:
            row=self.data[stage];row['count']+=1;row['failed']+=int(failed);row['total']+=seconds;row['maximum']=max(row['maximum'],seconds)
            row['buckets'][next(i for i,bound in enumerate(BUCKETS) if seconds<=bound)]+=1
        finally:self.lock.release()

    def increment(self,name):
        if name not in self.counters:raise ValueError('Unknown counter.')
        if not self.lock.acquire(blocking=False):self.dropped+=1;return
        try:self.counters[name]+=1
        finally:self.lock.release()

    @contextmanager
    def measure(self,stage):
        start=self.clock();state={'failed':False}
        try:yield state
        except BaseException:state['failed']=True;raise
        finally:self.observe(stage,self.clock()-start,state['failed'])

    def snapshot(self):
        with self.lock:
            data={s:dict(r,buckets=list(r['buckets'])) for s,r in self.data.items()};counters=dict(self.counters)
        result={}
        for stage,row in data.items():
            percentiles={}
            for label,fraction in (('p50_upper_ms',.5),('p95_upper_ms',.95)):
                count=0;bound=None
                for ceiling,total in zip(BUCKETS,row['buckets']):
                    count+=total
                    if row['count'] and count>=math.ceil(row['count']*fraction):bound=ceiling*1000 if math.isfinite(ceiling) else None;break
                percentiles[label]=bound
            result[stage]=dict(count=row['count'],failed=row['failed'],mean_ms=1000*row['total']/row['count'] if row['count'] else None,max_ms=1000*row['maximum'] if row['count'] else None,**percentiles)
        return dict(format=1,mode=self.mode,started=self.started,boot_id=self.boot_id,stages=result,counters=counters,dropped=self.dropped,
                    scope='Aggregates since this gateway process started. Percentiles are histogram upper bounds; null is no sample or above 30000 ms. Connect/TLS is combined and includes nested DNS time.')
