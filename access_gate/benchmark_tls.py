"""Isolated SNI callback microbenchmark; does not clear the running gateway cache."""
import argparse
import json
from pathlib import Path
import statistics
import time
from .gateway import Gateway
from .browser import origin


def benchmark(config,hostname,iterations=20):
    if not 1<=iterations<=50:raise ValueError('Choose 1 to 50 repetitions.')
    name=origin('https://'+hostname)[8:];gateway=Gateway(config)
    if not gateway.is_restricted_sync(name):raise ValueError('Choose an enabled restricted hostname; policy service must be reachable.')
    samples=[]
    class Connection:pass
    for _ in range(iterations+1):
        connection=Connection();start=time.perf_counter()
        result=gateway.tls.select(connection,name,gateway.tls.context)
        if result is not None:raise ValueError('SNI selection failed.')
        samples.append(1000*(time.perf_counter()-start))
    return dict(environment='Isolated callback on this machine, including actual policy lookup; excludes client/network TLS handshake and upstream website.',
                cold_ms=samples[0],warm_samples=iterations,warm_mean_ms=statistics.mean(samples[1:]),warm_max_ms=max(samples[1:]),metrics=gateway.performance.snapshot())


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--config',default='/etc/access-gate/gateway/gateway.json');parser.add_argument('--hostname',required=True);parser.add_argument('--iterations',type=int,default=20);args=parser.parse_args()
    print(json.dumps(benchmark(json.loads(Path(args.config).read_text()),args.hostname,args.iterations),indent=2))


if __name__=='__main__':main()
