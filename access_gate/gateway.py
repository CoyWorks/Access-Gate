"""DNS-directed HTTPS gateway for the managed domain list and browser grants."""
import asyncio
import argparse
import contextlib
import http.client
import ipaddress
import json
import math
import signal
import socket
import ssl
import time
from pathlib import Path
from urllib.parse import urlencode, urlsplit

import aiohttp
from aiohttp import web, WSMsgType
from aiohttp.abc import AbstractResolver
from multidict import CIMultiDict
from yarl import URL

from .browser import origin
from .gateway_tls import CertificateCache, expires

HOP = {'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer',
       'transfer-encoding', 'upgrade', 'alt-svc', 'alternate-protocol', 'proxy-connection'}
RESERVED_COOKIES = {'__Host-accessgate-browser', '__Host-accessgate-site', '__Host-accessgate-challenge', '__Host-accessgate-admin'}
STARTED = getattr(web, 'RequestKey', web.AppKey)('gateway_response_started', bool)


async def read_limited(content, limit):
    data = bytearray()
    async for chunk in content.iter_chunked(16384):
        data.extend(chunk)
        if len(data) > limit: raise OSError('Response exceeded its size limit.')
    return bytes(data)


def safe_headers(headers, upstream=False):
    omit = HOP | {name.strip().lower() for name in headers.get('Connection', '').split(',')}
    return CIMultiDict((key, value) for key, value in headers.items()
        if key.lower() not in omit and not key.lower().startswith(('x-gate-', 'x-forwarded-', 'x-real-ip'))
        and not (upstream and key.lower() == 'set-cookie' and value.split('=', 1)[0].strip() in RESERVED_COOKIES))


def answer_addresses(answer):
    if not isinstance(answer, dict) or answer.get('Status') != 0 or not isinstance(answer.get('Answer'), list):
        raise OSError('Invalid public DNS answer.')
    addresses = []
    for row in answer['Answer']:
        if not isinstance(row, dict): raise OSError('Invalid public DNS record.')
        if row.get('type') != 1: continue
        value = public_ip(row.get('data', ''))
        if ipaddress.ip_address(value).version != 4: raise OSError('Invalid A record.')
        if value not in addresses: addresses.append(value)
    if not addresses: raise OSError('No public IPv4 origin address.')
    return addresses


def public_ip(value):
    address = ipaddress.ip_address(value)
    if not address.is_global or address.is_multicast or address.is_reserved:
        raise OSError('The origin resolved to a non-public address.')
    return str(address)


class BootstrapResolver(AbstractResolver):
    ADDRESSES = {'cloudflare-dns.com': ('1.1.1.1', '1.0.0.1'), 'dns.google': ('8.8.8.8', '8.8.4.4')}

    async def resolve(self, host, port=443, family=socket.AF_INET):
        if host not in self.ADDRESSES: raise OSError('Unknown bootstrap host.')
        return [dict(hostname=host, host=ip, port=port, family=socket.AF_INET, proto=socket.IPPROTO_TCP,
                     flags=socket.AI_NUMERICHOST) for ip in self.ADDRESSES[host]]

    async def close(self): pass


class PublicResolver(AbstractResolver):
    """Independent public DNS over verified HTTPS, with fixed provider bootstrap IPs."""
    def __init__(self): self.session = None

    async def resolve(self, host, port=443, family=socket.AF_INET):
        host = origin('https://' + host)[8:]
        if self.session is None:
            self.session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(resolver=BootstrapResolver(),
                ssl=ssl.create_default_context()), trust_env=False, timeout=aiohttp.ClientTimeout(total=4))
        for provider in ('https://cloudflare-dns.com/dns-query', 'https://dns.google/resolve'):
            try:
                async with self.session.get(provider, params={'name': host, 'type': 'A'},
                        headers={'Accept': 'application/dns-json'}, allow_redirects=False) as response:
                    if response.status != 200: continue
                    data = await read_limited(response.content, 65536)
                    answer = json.loads(data)
                    ips = answer_addresses(answer)
                    return [dict(hostname=host, host=ip, port=port, family=socket.AF_INET, proto=socket.IPPROTO_TCP,
                                 flags=socket.AI_NUMERICHOST) for ip in ips]
            except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, KeyError, OSError):
                continue
        raise OSError('Independent public origin DNS resolution failed.')

    async def close(self):
        if self.session is not None: await self.session.close()


class Gateway:
    def __init__(self, config, *, upstream_connector=None, upstream_port=443, poll_interval=0.5):
        self.config = config
        api = urlsplit(config['api_url'])
        if api.scheme != 'http' or api.hostname != '127.0.0.1' or not api.port or api.path or api.query or api.fragment or api.username:
            raise ValueError('The gateway API must be a fixed loopback HTTP origin.')
        self.api_host, self.api_port = api.hostname, api.port
        self.api_url = config['api_url']
        self.key = config['api_key']
        self.networks = [ipaddress.ip_network(value) for value in config['client_networks']]
        self.portal_hosts = set(config['portal_hosts'])
        self.upstream_connector = upstream_connector
        self.upstream_port = upstream_port
        self.poll_interval = poll_interval
        self.local = self.upstream = None
        self.resolver = None
        self.tls = CertificateCache(config, self.is_restricted_sync)

    def is_restricted_sync(self, host):
        connection = http.client.HTTPConnection(self.api_host, self.api_port, timeout=1)
        try:
            connection.request('GET', '/internal/gateway/domain?' + urlencode({'host': host}), headers={'X-Gate-Key': self.key})
            response = connection.getresponse()
            data = response.read(16385)
            return response.status == 200 and len(data) <= 16384 and json.loads(data).get('restricted') is True
        except (OSError, ValueError, http.client.HTTPException): return False
        finally: connection.close()

    async def start(self, app):
        self.local = aiohttp.ClientSession(trust_env=False, cookie_jar=aiohttp.DummyCookieJar(),
            auto_decompress=False, skip_auto_headers={'Accept-Encoding'}, timeout=aiohttp.ClientTimeout(total=2))
        connector = self.upstream_connector
        if connector is None:
            self.resolver = PublicResolver()
            connector = aiohttp.TCPConnector(resolver=self.resolver, family=socket.AF_INET,
                ttl_dns_cache=30, ssl=ssl.create_default_context(), limit=100, limit_per_host=12)
        self.upstream = aiohttp.ClientSession(connector=connector, trust_env=False,
            cookie_jar=aiohttp.DummyCookieJar(), auto_decompress=False,
            skip_auto_headers={'Accept-Encoding'},
            timeout=aiohttp.ClientTimeout(total=None, connect=10, sock_read=60))

    async def stop(self, app):
        if self.upstream: await self.upstream.close()
        if self.resolver: await self.resolver.close()
        if self.local: await self.local.close()

    def application(self):
        app = web.Application(client_max_size=16384)
        app.on_startup.append(self.start); app.on_cleanup.append(self.stop)
        app.router.add_route('*', '/{path:.*}', self.handle)
        return app

    def client_address(self, request, secure):
        peer = request.transport.get_extra_info('peername')
        if not peer: raise web.HTTPForbidden(text='Unknown client.')
        value = peer[0]
        if not secure:
            if value != '127.0.0.1': raise web.HTTPForbidden(text='Trusted HTTP proxy required.')
            value = request.headers.get('X-Real-IP', '')
        try: address = ipaddress.ip_address(value)
        except ValueError: raise web.HTTPForbidden(text='Invalid client address.')
        if not any(address in network for network in self.networks): raise web.HTTPForbidden(text='Client network not allowed.')
        return str(address)

    @staticmethod
    def host(request):
        try:
            value = urlsplit('https://' + request.headers.get('Host', ''))
            if value.username is not None or value.password is not None or value.port not in (None, 80, 443) or value.path or value.query or value.fragment:
                raise ValueError()
            name = (value.hostname or '').encode('idna').decode('ascii').lower().rstrip('.')
            if not name: raise ValueError()
            return name
        except (ValueError, UnicodeError): raise web.HTTPBadRequest(text='Invalid hostname.')

    async def rpc(self, path, host, cookie='', address=None, activity=False):
        headers = {'X-Gate-Key': self.key, 'X-Gate-Origin': 'https://' + host, 'Cookie': cookie}
        if address is not None:headers['X-Gate-Client-IP']=address
        if activity:headers['X-Gate-Activity']='1'
        async with self.local.get(self.api_url + path, headers=headers, allow_redirects=False) as response:
            data = await read_limited(response.content, 65536)
            return response.status, CIMultiDict(response.headers), data

    async def allowed(self, host, cookie, address=None, activity=False):
        status, headers, data = await self.rpc('/internal/gateway/check', host, cookie, address, activity)
        if status in (401, 403): return False, None, headers
        if status != 200: raise OSError('Authorization service unavailable.')
        result = json.loads(data)
        if not isinstance(result, dict) or result.get('active') is not True or not isinstance(result.get('expires'), (float, int)) or not math.isfinite(result['expires']):
            raise OSError('Invalid authorization result.')
        if result['expires'] <= time.time(): return False, None, headers
        return True, result['expires'], headers

    async def watch(self, request, host, cookie, address, task):
        try:
            while True:
                await asyncio.sleep(self.poll_interval)
                active, _, _ = await self.allowed(host, cookie, address)
                if not active: break
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError): pass
        if request.transport is not None: request.transport.abort()
        task.cancel()

    async def handle(self, request):
        if not request.raw_path.startswith('/'):
            raise web.HTTPBadRequest(text='Origin-form requests are required.')
        secure = request.transport.get_extra_info('ssl_object') is not None
        address = self.client_address(request, secure)
        host = self.host(request)
        if request.method in ('CONNECT', 'TRACE'): raise web.HTTPMethodNotAllowed(request.method, ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])
        try:
            if not secure:
                if host in self.portal_hosts:
                    return web.Response(status=308, headers={'Location': self.config['portal_url'] + request.raw_path})
                if not await asyncio.to_thread(self.is_restricted_sync, host): raise web.HTTPMisdirectedRequest(text='This hostname is not managed.')
                return web.Response(status=308, headers={'Location': 'https://' + host + request.raw_path})
            sni = getattr(request.transport.get_extra_info('ssl_object'), 'access_gate_sni', None)
            if host in self.portal_hosts:
                if sni is not None: raise web.HTTPMisdirectedRequest(text='TLS hostname mismatch.')
                if request.path.startswith('/internal'): raise web.HTTPNotFound()
                if request.path == '/__access_gate/health':
                    return web.json_response({'gateway': 'ready', 'issuer_expires': expires(self.tls.issuer).isoformat()})
                return await self.portal(request, address)
            if sni != host: raise web.HTTPMisdirectedRequest(text='TLS hostname mismatch.')
            if not await asyncio.to_thread(self.is_restricted_sync, host): raise web.HTTPMisdirectedRequest(text='This hostname is not managed.')
            cookie = request.headers.get('Cookie', '')
            if request.path == '/__access_gate/complete':
                if request.method != 'GET': raise web.HTTPMethodNotAllowed(request.method, ['GET'])
                path = '/internal/finish?' + urlencode({'ticket': request.query.get('ticket', '')})
                return await self.local_response(path, host, cookie)
            active, _, headers = await self.allowed(host, cookie, address, activity=True)
            if not active: return await self.local_response('/internal/start', host, cookie)
            watcher = asyncio.create_task(self.watch(request, host, cookie, address, asyncio.current_task()))
            try:
                if request.headers.get('Upgrade', '').lower() == 'websocket':
                    return await self.websocket(request, host, headers)
                return await self.website(request, host, headers)
            finally:
                watcher.cancel()
                with contextlib.suppress(asyncio.CancelledError): await watcher
        except web.HTTPException: raise
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError):
            if request.get(STARTED):
                if request.transport is not None: request.transport.abort()
                raise asyncio.CancelledError()
            return web.Response(status=502, text='The gateway could not reach the authorization service or verified HTTPS origin.', headers={'Cache-Control': 'no-store'})

    async def local_response(self, path, host, cookie):
        status, headers, data = await self.rpc(path, host, cookie)
        if status not in (200, 302, 303, 400): raise OSError('Gateway handoff unavailable.')
        return web.Response(status=status, body=data, headers=safe_headers(headers))

    async def portal(self, request, address):
        headers = safe_headers(request.headers)
        headers['Host'] = request.headers['Host']; headers['X-Real-IP'] = address
        async with self.local.request(request.method, self.api_url + request.raw_path, headers=headers,
                data=request.content.iter_chunked(65536) if request.can_read_body else None,
                timeout=aiohttp.ClientTimeout(total=45, connect=2, sock_read=45),
                allow_redirects=False) as response:
            result = web.StreamResponse(status=response.status, headers=safe_headers(response.headers))
            request[STARTED] = True
            await result.prepare(request)
            async for data in response.content.iter_any(): await result.write(data)
            await result.write_eof()
            return result

    def upstream_url(self, request, host):
        port = '' if self.upstream_port == 443 else ':' + str(self.upstream_port)
        return URL('https://' + host + port + request.raw_path, encoded=True)

    def website_headers(self, request, host, auth):
        headers = safe_headers(request.headers)
        headers['Host'] = host
        headers['Cookie'] = auth.get('X-Gate-Upstream-Cookie', '')
        return headers

    async def website(self, request, host, auth):
        async with self.upstream.request(request.method, self.upstream_url(request, host),
                headers=self.website_headers(request, host, auth),
                data=request.content.iter_chunked(65536) if request.can_read_body else None,
                allow_redirects=False) as upstream:
            response = web.StreamResponse(status=upstream.status, headers=safe_headers(upstream.headers, upstream=True))
            request[STARTED] = True
            await response.prepare(request)
            async for data in upstream.content.iter_any(): await response.write(data)
            await response.write_eof()
            return response

    async def websocket(self, request, host, auth):
        headers = self.website_headers(request, host, auth)
        for name in ('Sec-WebSocket-Key', 'Sec-WebSocket-Version', 'Sec-WebSocket-Extensions', 'Sec-WebSocket-Protocol'):
            headers.popall(name, None)
        protocols = [value.strip() for value in request.headers.get('Sec-WebSocket-Protocol', '').split(',') if value.strip()]
        async with self.upstream.ws_connect(self.upstream_url(request, host), headers=headers,
                protocols=protocols, autoclose=True, autoping=True) as upstream:
            client = web.WebSocketResponse(protocols=[upstream.protocol] if upstream.protocol else [], autoclose=True, autoping=True)
            request[STARTED] = True
            await client.prepare(request)
            async def relay(source, destination):
                async for message in source:
                    if message.type == WSMsgType.TEXT: await destination.send_str(message.data)
                    elif message.type == WSMsgType.BINARY: await destination.send_bytes(message.data)
                    else: break
            tasks = [asyncio.create_task(relay(client, upstream)), asyncio.create_task(relay(upstream, client))]
            try: await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            finally:
                for task in tasks: task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                await client.close()
            return client


async def serve(config):
    gateway = Gateway(config)
    runner = web.AppRunner(gateway.application(), access_log=None, shutdown_timeout=2)
    await runner.setup()
    try:
        await web.TCPSite(runner, config['listen_host'], config['listen_port'], ssl_context=gateway.tls.context).start()
        await web.TCPSite(runner, config['http_host'], config['http_port']).start()
        done = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT): loop.add_signal_handler(sig, done.set)
        await done.wait()
    finally: await runner.cleanup()


def main(argv=None, configuration_path=Path('/etc/access-gate/gateway/gateway.json')):
    parser = argparse.ArgumentParser(description='Access Gate HTTPS gateway')
    parser.add_argument('--check', action='store_true', help='Validate credential access/TLS without binding ports')
    args = parser.parse_args(argv)
    try:
        configuration = json.loads(Path(configuration_path).read_text())
        if args.check:
            for name in ('issuer_cert', 'issuer_key', 'portal_cert', 'portal_key'):
                with Path(configuration[name]).open('rb') as handle: handle.read(1)
            Gateway(configuration)
            print('Gateway credentials are readable and the TLS certificate/key pair loads successfully.')
        else:
            asyncio.run(serve(configuration))
    except (OSError, ValueError) as exc:
        raise SystemExit('Gateway startup/check failed: ' + str(exc)) from exc


if __name__ == '__main__': main()
