"""TCP passthrough regression tests: SNI detection, routing and fail-closed behavior."""
import asyncio
import ipaddress
import ssl
import unittest
from unittest.mock import AsyncMock

from access_gate.tls_passthrough import TLSRouter, client_hello_sni, parse_hello_sni


def hello(host):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = context.wrap_bio(incoming, outgoing, server_side=False, server_hostname=host)
    try:
        client.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


class SNIParserTests(unittest.TestCase):
    def test_tls_client_hello_round_trip_and_fragmentation(self):
        wire = hello('Unlisted.Example')
        self.assertEqual(client_hello_sni(wire), ('unlisted.example', True))
        for n in (0, 1, 3, 4, 5, len(wire)-1):
            self.assertEqual(client_hello_sni(wire[:n]), (None, False))

    def test_tls_without_sni_can_use_portal_fallback(self):
        self.assertEqual(client_hello_sni(hello(None)), (None, True))

    def test_malformed_and_non_tls_fail_closed(self):
        for data in (b'GET / HTTP/1.1\r\n', b'\x16\x01\x00\x00\x00', b'\x17\x03\x03\x00\x00'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                client_hello_sni(data)
        for data in (b'', b'\x03\x03' + b'\x00'*32):
            with self.subTest(data=data), self.assertRaises(ValueError):
                parse_hello_sni(data)


class RouterTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.managed_received = []
        self.origin_received = []

        async def managed(reader, writer):
            self.managed_received.append((writer.get_extra_info('peername'), await reader.read(4096)))
            writer.write(b'MANAGED')
            await writer.drain()
            writer.close()

        async def origin(reader, writer):
            self.origin_received.append(await reader.read(4096))
            writer.write(b'ORIGIN')
            await writer.drain()
            writer.close()

        self.managed_server = await asyncio.start_server(managed, '127.0.0.1', 0)
        self.origin_server = await asyncio.start_server(origin, '127.0.0.1', 0)
        managed_port = self.managed_server.sockets[0].getsockname()[1]
        origin_port = self.origin_server.sockets[0].getsockname()[1]

        class Policy:
            ready = True
            def fresh(self): return self.ready

        class Resolver:
            async def resolve(self, host, port):
                assert host == 'unlisted.example' and port == 443
                return [dict(host='127.0.0.1')]

        class Gateway:
            config = {}
            portal_hosts = {'portal.example'}
            networks = [ipaddress.ip_network('127.0.0.0/8')]
            policy = Policy()
            resolver = Resolver()
            proxy_clients = {}
            def is_restricted_sync(self, host): return host == 'restricted.example'

        self.gateway = Gateway()
        self.router = TLSRouter(self.gateway, managed_port, origin_port=origin_port)
        self.router_tasks = set()
        accept = self.router.accept

        async def tracked_accept(reader, writer):
            task = asyncio.current_task()
            self.router_tasks.add(task)
            try:
                await accept(reader, writer)
            finally:
                self.router_tasks.discard(task)

        self.router.accept = tracked_accept
        await self.router.start('127.0.0.1', 0)
        self.port = self.router.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        await self.router.close()
        for server in (self.managed_server, self.origin_server):
            server.close()
            await server.wait_closed()

    async def send(self, host):
        reader, writer = await asyncio.open_connection('127.0.0.1', self.port)
        wire = hello(host)
        writer.write(wire)
        await writer.drain()
        response = await asyncio.wait_for(reader.read(4096), 2)
        writer.close()
        await writer.wait_closed()
        return wire, response

    async def test_unlisted_domain_is_forwarded_without_tls_termination(self):
        wire, response = await self.send('unlisted.example')
        self.assertEqual(response, b'ORIGIN')
        self.assertEqual(self.origin_received, [wire])
        self.assertEqual(self.managed_received, [])

    async def test_managed_domain_and_portal_route_to_existing_gateway(self):
        for host in ('restricted.example', 'portal.example', None):
            wire, response = await self.send(host)
            self.assertEqual(response, b'MANAGED')
            self.assertEqual(self.managed_received[-1][1], wire)
        self.assertEqual(self.origin_received, [])
        # Client wait_closed only closes its local transport. Wait for the
        # router's actual finally block, with a deadline that still detects leaks.
        await asyncio.wait_for(asyncio.gather(*tuple(self.router_tasks)), 1)
        self.assertFalse(self.gateway.proxy_clients)

    async def test_stale_policy_does_not_open_a_public_proxy(self):
        self.gateway.policy.ready = False
        wire, response = await self.send('unlisted.example')
        self.assertEqual(response, b'')
        self.assertEqual(self.origin_received, [])
        self.assertEqual(self.managed_received, [])
