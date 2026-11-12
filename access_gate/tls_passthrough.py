"""TCP TLS routing: managed hosts use the Access Gate TLS endpoint; unmanaged hosts pass through unchanged.

No untrusted hostname ever goes to the OS resolver: the public-origin lookup is performed
with the independent HTTPS resolver and only globally routable IPv4 results are accepted.
"""
import asyncio
import ipaddress
import socket

from .core import GateError
import ssl
import struct

from .dns_export import hostname

MAX_HELLO = 65536
HELLO_TIMEOUT = 6
IDLE_TIMEOUT = 300
MAX_CONNECTIONS = 128


def client_hello_sni(data):
    """Parse an SNI hostname from complete TLS ClientHello records. Return (name, complete).

    An absent SNI and malformed handshakes are rejected, not treated as proxy requests.
    """
    handshakes = bytearray()
    offset = 0
    while offset + 5 <= len(data):
        typ, major, minor, length = struct.unpack('!BBBH', data[offset:offset+5])
        if typ != 22 or major != 3 or length > 16384 + 2048:
            raise ValueError('Not a TLS ClientHello record.')
        if offset + 5 + length > len(data):
            return None, False
        handshakes.extend(data[offset+5:offset+5+length])
        offset += 5 + length
        if len(handshakes) >= 4:
            if handshakes[0] != 1:
                raise ValueError('Expected TLS ClientHello.')
            hello_len = int.from_bytes(handshakes[1:4], 'big')
            if hello_len > MAX_HELLO - 4:
                raise ValueError('ClientHello too large.')
            if len(handshakes) >= hello_len + 4:
                return parse_hello_sni(bytes(handshakes[4:hello_len+4])), True
    return None, False


def parse_hello_sni(hello):
    """Parse the SNI extension from a TLS ClientHello, with strict length bounds."""
    def part(data, offset, count):
        if offset + count > len(data):
            raise ValueError('Truncated ClientHello.')
        return data[offset:offset+count], offset+count

    if len(hello) < 34:
        raise ValueError('Truncated ClientHello.')
    pos = 34  # protocol version and random
    size, pos = part(hello, pos, 1)
    _, pos = part(hello, pos, size[0])
    size, pos = part(hello, pos, 2)
    _, pos = part(hello, pos, int.from_bytes(size, 'big'))
    size, pos = part(hello, pos, 1)
    _, pos = part(hello, pos, size[0])
    if pos == len(hello):
        raise ValueError('Missing TLS SNI.')
    size, pos = part(hello, pos, 2)
    end = pos + int.from_bytes(size, 'big')
    if end != len(hello):
        raise ValueError('Invalid TLS extensions length.')
    while pos < end:
        ext, pos = part(hello, pos, 2)
        size, pos = part(hello, pos, 2)
        payload, pos = part(hello, pos, int.from_bytes(size, 'big'))
        if ext != b'\x00\x00':
            continue
        if len(payload) < 5 or int.from_bytes(payload[:2], 'big') != len(payload)-2:
            raise ValueError('Invalid SNI extension.')
        p = 2
        while p < len(payload):
            if p + 3 > len(payload):
                raise ValueError('Invalid SNI entry.')
            kind = payload[p]
            n = int.from_bytes(payload[p+1:p+3], 'big')
            p += 3
            if p+n > len(payload):
                raise ValueError('Invalid SNI entry length.')
            raw = payload[p:p+n]
            p += n
            if kind == 0:
                try:
                    return hostname(raw.decode('ascii'))
                except (ValueError, UnicodeError, GateError) as exc:
                    raise ValueError('Invalid SNI hostname.') from exc
        raise ValueError('Missing DNS SNI.')
    raise ValueError('Missing TLS SNI.')


class TLSRouter:
    """TCP-only passthrough for unlisted hostnames, preserving SNI and TLS bytes."""

    def __init__(self, gateway, internal_port, *, origin_port=443):
        self.gateway = gateway
        self.internal_port = internal_port
        self.origin_port = origin_port
        self.slots = asyncio.Semaphore(MAX_CONNECTIONS)
        self.server = None

    async def start(self, host, port):
        self.server = await asyncio.start_server(self.accept, host, port)
        return self.server

    async def close(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    async def accept(self, reader, writer):
        async with self.slots:
            upstream = None
            client_port = None
            try:
                peer = writer.get_extra_info('peername')
                if not peer:
                    return
                client_ip = ipaddress.ip_address(peer[0])
                initial = bytearray()
                deadline = asyncio.get_running_loop().time() + HELLO_TIMEOUT
                while len(initial) < MAX_HELLO:
                    name, done = client_hello_sni(initial)
                    if done:
                        break
                    remaining = deadline - asyncio.get_running_loop().time()
                    if remaining <= 0:
                        return
                    packet = await asyncio.wait_for(reader.read(min(4096, MAX_HELLO-len(initial))), remaining)
                    if not packet:
                        return
                    initial.extend(packet)
                else:
                    return

                public_portal = bool(self.gateway.config.get('public_portal') and name in self.gateway.portal_hosts)
                if not public_portal and not any(client_ip in net for net in self.gateway.networks):
                    return
                # Never treat a stale/unavailable policy as permission to proxy.
                if not self.gateway.policy or not self.gateway.policy.fresh():
                    return
                managed = name in self.gateway.portal_hosts or self.gateway.is_restricted_sync(name)
                if managed:
                    upstream = await asyncio.wait_for(
                        asyncio.open_connection('127.0.0.1', self.internal_port), 5)
                    remote_reader, remote_writer = upstream
                    client_port = remote_writer.get_extra_info('sockname')[1]
                    self.gateway.proxy_clients[client_port] = str(client_ip)
                else:
                    # DNS is looked up independently of Pi-hole/Access Gate and all origin
                    # addresses are validated by PublicResolver to prevent SSRF/loops.
                    answer = await self.gateway.resolver.resolve(name, 443)
                    for item in answer:
                        try:
                            upstream = await asyncio.wait_for(
                                asyncio.open_connection(item['host'], self.origin_port, family=socket.AF_INET), 5)
                            break
                        except (OSError, asyncio.TimeoutError):
                            continue
                    if upstream is None:
                        return
                    remote_reader, remote_writer = upstream
                remote_writer.write(initial)
                await remote_writer.drain()

                async def pump(source, destination):
                    while chunk := await asyncio.wait_for(source.read(65536), IDLE_TIMEOUT):
                        destination.write(chunk)
                        await destination.drain()

                tasks = [asyncio.create_task(pump(reader, remote_writer)),
                         asyncio.create_task(pump(remote_reader, writer))]
                done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for task in pending:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
            except (ValueError, OSError, asyncio.TimeoutError, ConnectionError, ssl.SSLError):
                pass
            finally:
                if client_port is not None:
                    self.gateway.proxy_clients.pop(client_port, None)
                if upstream:
                    upstream[1].close()
                    try: await upstream[1].wait_closed()
                    except (OSError, ConnectionError): pass
                writer.close()
                try: await writer.wait_closed()
                except (OSError, ConnectionError): pass
