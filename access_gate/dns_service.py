"""Optional bounded DNS forwarder; no portal credentials or private CA access."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import socket
import socketserver
import struct
import threading
import time
import dns.exception
import dns.flags
import dns.message
import dns.opcode
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from .domain_match import match_rule

MAX_RULE_BYTES=64*1024*1024


def read_json(path,limit=MAX_RULE_BYTES):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:
        data=stream.read(limit+1)
    if len(data)>limit:raise ValueError('DNS configuration exceeds its limit.')
    return json.loads(data)


class Rules:
    def __init__(self,path):
        self.path=Path(path);self.lock=threading.Lock();self.stamp=None;self.current=(frozenset(),frozenset());self.reload(required=True)

    def reload(self,required=False):
        try:
            stamp=self.path.stat().st_mtime_ns
            if stamp==self.stamp:return
            with self.lock:
                if stamp==self.stamp:return
                data=read_json(self.path)
                exact=set();suffix=set()
                from .dns_export import hostname
                for row in data['domains']:
                    name=hostname(row['domain'])
                    (suffix if row['include_subdomains'] else exact).add(name)
                self.current=(frozenset(exact),frozenset(suffix));self.stamp=stamp
        except (OSError,ValueError,KeyError,TypeError):
            if required:raise
            # Retain the last known-good rules; publisher health exposes failures.

    def restricted(self,name):
        self.reload();exact,suffix=self.current
        name=name.rstrip('.').lower()
        return bool(match_rule(name,exact,suffix))


class Resolver:
    def __init__(self,config,rules,forward=None):
        self.config=config;self.rules=rules;self.networks=[ipaddress.ip_network(n) for n in config['client_networks']]
        self.portal_names=frozenset(config['portal_names']);self.forward=forward or self.upstream

    def upstream(self,query):
        for address in self.config['dns_upstreams']:
            try:
                # dnspython validates response identity/source and retries truncation with TCP.
                response,_=dns.query.udp_with_fallback(query,address,timeout=2)
                return response
            except (dns.exception.DNSException,OSError):continue
        raise TimeoutError('Configured DNS upstreams did not respond.')

    def answer(self,wire,peer,tcp=False):
        try:
            if not any(ipaddress.ip_address(peer) in n for n in self.networks):return None
            query=dns.message.from_wire(wire)
            if query.flags&dns.flags.QR:return None
            response=dns.message.make_response(query,recursion_available=True)
            if query.opcode()!=dns.opcode.QUERY or len(query.question)!=1:
                response.set_rcode(dns.rcode.REFUSED)
            else:
                question=query.question[0];name=question.name.to_text().rstrip('.').lower()
                if question.rdclass!=dns.rdataclass.IN:response.set_rcode(dns.rcode.REFUSED)
                elif name in self.portal_names or self.rules.restricted(name):
                    response.flags|=dns.flags.AA
                    if question.rdtype in (dns.rdatatype.A,dns.rdatatype.ANY):
                        response.answer.append(dns.rrset.from_text(question.name,30,'IN','A',self.config['dns_target_ipv4']))
                    # NOERROR/NODATA for AAAA, HTTPS, SVCB, etc; never query upstream for this name.
                else:
                    try:response=self.forward(query)
                    except (dns.exception.DNSException,OSError):response.set_rcode(dns.rcode.SERVFAIL)
            maximum=65535 if tcp else min(1232,max(512,query.payload or 512))
            return response.to_wire(max_size=maximum,prefer_truncation=True)
        except (dns.exception.DNSException,ValueError,TypeError):return None


class BoundedThreads(socketserver.ThreadingMixIn):
    daemon_threads=True
    def process_request(self,request,client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request);return
        try:super().process_request(request,client_address)
        except BaseException:self.slots.release();raise
    def process_request_thread(self,request,client_address):
        try:super().process_request_thread(request,client_address)
        finally:self.slots.release()
    def handle_error(self,request,client_address):pass


class UDPServer(BoundedThreads,socketserver.UDPServer):pass
class TCPServer(BoundedThreads,socketserver.TCPServer):
    allow_reuse_address=True


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        wire,sock=self.request
        if len(wire)>4096:return
        answer=self.server.resolver.answer(wire,self.client_address[0])
        if answer:sock.sendto(answer,self.client_address)


def read_exact(sock,size,deadline):
    data=b''
    while len(data)<size:
        remaining=deadline-time.monotonic()
        if remaining<=0:raise TimeoutError()
        sock.settimeout(remaining);part=sock.recv(size-len(data))
        if not part:raise ConnectionError()
        data+=part
    return data


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            for _ in range(16):
                deadline=time.monotonic()+3
                length=struct.unpack('!H',read_exact(self.request,2,deadline))[0]
                if not 12<=length<=4096:return
                wire=read_exact(self.request,length,deadline)
                answer=self.server.resolver.answer(wire,self.client_address[0],tcp=True)
                if not answer:return
                self.request.settimeout(3);self.request.sendall(struct.pack('!H',len(answer))+answer)
        except OSError:return


def servers(config,resolver,port=53):
    slots=threading.BoundedSemaphore(32)
    udp=UDPServer((config['listen_ipv4'],port),UDPHandler)
    try:tcp=TCPServer((config['listen_ipv4'],udp.server_address[1]),TCPHandler)
    except BaseException:udp.server_close();raise
    for service in (udp,tcp):service.slots=slots;service.resolver=resolver
    return udp,tcp


class DNSReadinessError(RuntimeError):pass


def wait_for_dns(config,timeout=30,interval=1,clock=time.monotonic,sleep=time.sleep,query=None):
    """Wait for valid local answers over both transports within one deadline."""
    if timeout<=0 or interval<=0:raise ValueError('DNS readiness timeout and interval must be positive.')
    if not config['portal_names']:raise ValueError('DNS portal name is missing.')
    if query is None:query=dns.message.make_query(config['portal_names'][0],'A')
    deadline=clock()+timeout
    last='No DNS response received.'
    while True:
        for transport_name,transport in (('UDP',dns.query.udp),('TCP',dns.query.tcp)):
            remaining=deadline-clock()
            if remaining<=0:
                raise DNSReadinessError(f'DNS listener did not become ready within {timeout} seconds. Last result: {last}')
            try:
                response=transport(query,config['listen_ipv4'],timeout=min(3,remaining))
            except (dns.exception.Timeout,OSError) as exc:
                last=f'{transport_name}: {exc or type(exc).__name__}'
                break
            if response.rcode()!=dns.rcode.NOERROR or not any(
                rrset.name==query.question[0].name and rrset.rdtype==dns.rdatatype.A
                and any(str(record)==config['dns_target_ipv4'] for record in rrset)
                for rrset in response.answer
            ):
                raise DNSReadinessError(f'{transport_name} listener returned an unexpected answer for {config["portal_names"][0]}.')
        else:
            return
        remaining=deadline-clock()
        if remaining<=0:
            raise DNSReadinessError(f'DNS listener did not become ready within {timeout} seconds. Last result: {last}')
        sleep(min(interval,remaining))


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true');parser.add_argument('--probe',action='store_true');args=parser.parse_args()
    c=read_json('/etc/access-gate/dns.json',65536)
    resolver=Resolver(c,Rules('/var/lib/access-gate/dns/rules.json'))
    if args.check:return
    if args.probe:
        try:wait_for_dns(c)
        except DNSReadinessError as exc:raise SystemExit('DNS readiness failed: '+str(exc)) from exc
        print('DNS UDP/TCP listener verification passed.')
        return
    udp,tcp=servers(c,resolver)
    threading.Thread(target=udp.serve_forever,daemon=True).start()
    try:tcp.serve_forever()
    finally:udp.shutdown();udp.server_close();tcp.server_close()


if __name__=='__main__':main()
