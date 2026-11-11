"""Wait for the actual HTTPS portal, not merely an active service process."""
import ssl
import http.client
import socket
from urllib.parse import urlsplit
import sys
import time
import urllib.error
import urllib.request

from .deployment import LEGACY
URL=LEGACY['portal_url']+'/'
CAFILE='/etc/access-gate/ca/root.crt'


class ReadinessError(RuntimeError): pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl): return None


def https_probe(cafile=CAFILE,url=URL,address=None):
    context=ssl.create_default_context(cafile=cafile)
    context.load_default_certs()
    # Local checks must never travel through an environment-configured proxy.
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                     urllib.request.HTTPSHandler(context=context),NoRedirect())
    def probe(timeout):
        if address is not None:
            target=urlsplit(url)
            connection=http.client.HTTPSConnection(target.hostname,443,timeout=timeout,context=context)
            try:
                connection.sock=context.wrap_socket(socket.create_connection((address,443),timeout=timeout),server_hostname=target.hostname)
                connection.request('GET',target.path or '/',headers={'Connection':'close'})
                response=connection.getresponse(); response.read(1)
                return response.status
            finally: connection.close()
        with opener.open(url,timeout=timeout) as response:
            response.read(1)
            return response.status
    return probe


def wait_for_portal(probe,timeout=30,interval=1,clock=time.monotonic,sleep=time.sleep):
    if timeout<=0 or interval<=0: raise ValueError('Readiness timeout and interval must be positive.')
    deadline=clock()+timeout
    last='No HTTP response received.'
    while True:
        remaining=deadline-clock()
        if remaining<=0: raise ReadinessError(f'Portal did not become ready within {timeout} seconds. Last result: {last}')
        try:
            status=probe(timeout=min(3,remaining))
            if status==200: return
            last=f'HTTP {status}'
        except urllib.error.HTTPError as exc:
            last=f'HTTP {exc.code}'
        except (urllib.error.URLError,OSError) as exc:
            reason=getattr(exc,'reason',exc)
            if isinstance(reason,ssl.SSLCertVerificationError):
                raise ReadinessError('Portal TLS certificate verification failed. Check the retained CA, portal certificate and server clock.') from exc
            last=str(reason)
        remaining=deadline-clock()
        if remaining<=0: raise ReadinessError(f'Portal did not become ready within {timeout} seconds. Last result: {last}')
        sleep(min(interval,remaining))


def main():
    print('Waiting up to 30 seconds for the HTTPS portal...',flush=True)
    try:
        import json
        from pathlib import Path
        from .deployment import normalize
        config=normalize(json.loads(Path('/etc/access-gate/config.json').read_text()))
        endpoint=config.get('portal_url',URL.rstrip('/')).rstrip('/')+('/__access_gate/health' if config['remote_gateway'] else '/')
        wait_for_portal(https_probe(url=endpoint,address=config['listen_ipv4']))
    except (ReadinessError,OSError,ValueError) as exc:
        print('Portal readiness failed: '+str(exc),file=sys.stderr)
        return 1
    print('HTTPS portal is ready (HTTP 200).')
    return 0


if __name__=='__main__': sys.exit(main())
