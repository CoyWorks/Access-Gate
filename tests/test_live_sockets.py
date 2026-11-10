"""Opt-in root check on the target VM: real TCP stream expiry and unrelated traffic."""
import os
from pathlib import Path
import socket
import tempfile
import unittest

from access_gate.core import Store
from access_gate.keeper import expire,kill_connection


@unittest.skipUnless(os.environ.get('ACCESS_GATE_LIVE_NETWORK_TESTS')=='1','Requires explicit opt-in on the target VM with CAP_NET_ADMIN')
class LiveSocketTests(unittest.TestCase):
    def test_real_restricted_stream_closes_while_unrelated_stream_stays_open(self):
        if os.geteuid()!=0: self.fail('Run this opt-in test as root on the dedicated server.')
        with tempfile.TemporaryDirectory() as root:
            store=Store(Path(root)/'test.sqlite','temporary-test-pepper'); store.initialize()
            resources=[]
            try:
                def connection(port):
                    listener=socket.socket(); resources.append(listener)
                    listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                    listener.bind(('127.0.0.1',port)); listener.listen(1)
                    client=socket.create_connection(('127.0.0.1',port)); resources.append(client)
                    server,_=listener.accept(); resources.append(server)
                    client.settimeout(2); server.settimeout(2)
                    return client,server
                restricted,restricted_server=connection(3128)
                ordinary,ordinary_server=connection(3129)
                _,codes=store.create_batch(count=1,access_value=1,now=1000)
                store.redeem(codes[0],'127.0.0.1',1000)
                store.authorize('127.0.0.1',connection=dict(client_port=restricted.getsockname()[1],local_ip='127.0.0.1',local_port=3128),now=1000)
                restricted_server.sendall(b'before'); self.assertEqual(restricted.recv(6),b'before')
                expire(store,kill_connection,1060,targeted=True)
                try:
                    data=restricted.recv(1)
                    self.assertEqual(data,b'')
                except ConnectionResetError: pass
                ordinary_server.sendall(b'still available')
                self.assertEqual(ordinary.recv(15),b'still available')
                self.assertIsNone(store.grant('127.0.0.1',1060))
            finally:
                for resource in resources: resource.close()


if __name__=='__main__': unittest.main()
