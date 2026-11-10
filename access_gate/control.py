"""Fixed-operation Unix control socket; only the worker reads FortiGate secrets."""
import ipaddress
import json
import os
import socketserver
import threading

from .identity import IdentityUnavailable


class ControlServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads=True
    request_queue_size=8

    def __init__(self,path,store,source):
        self.store,self.source=store,source
        self.slots=threading.BoundedSemaphore(4)
        super().__init__(path,Handler)
        os.chmod(path,0o660)


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(6)
        if not self.server.slots.acquire(blocking=False): return
        try:
            request=json.loads(self.rfile.readline(4097))
            if request.get('action')!='identity': raise IdentityUnavailable('Unsupported control action.')
            ip=str(ipaddress.ip_address(request['ip']))
            if self.server.source is None: raise IdentityUnavailable('Configure the FortiGate reader first.')
            sessions=self.server.source.snapshot()  # Fresh query for every positive decision.
            found=next((s for s in sessions if s['ip']==ip),None)
            if not found: raise IdentityUnavailable('No unique established VPN session found.')
            identity=self.server.store.observe_identity(found)
            result={'identity':identity}
        except (ValueError,KeyError,OSError,TypeError,AttributeError) as exc:
            result={'error':str(exc)[:240]}
        finally:
            self.server.slots.release()
        try: self.wfile.write((json.dumps(result)+'\n').encode())
        except OSError: pass
