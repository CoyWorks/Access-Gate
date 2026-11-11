import copy,json,os,tempfile
from pathlib import Path
import unittest
from access_gate.core import Store
from access_gate.deployment import normalize,render_http
from access_gate.reconfigure import updated,apply
from gateway_fixtures import settings
from test_deployment_settings import profile


class ReconfigureTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.c=normalize(dict(profile(),portal_url='https://portal.example',secret='s',pepper='p',admin_hash='h',acl_token='t',database='/var/lib/access-gate/data/gate.sqlite3'))
        settings(self.root,self.c)
        (self.root/'var/lib/access-gate/data').mkdir(parents=True)
        self.store=Store(self.root/'var/lib/access-gate/data/gate.sqlite3','p');self.store.initialize()
        self.bid,self.codes=self.store.create_batch(count=1)
        self.base=self.root/'etc/access-gate'
        (self.base/'client-networks.nginx').write_text('allow 192.168.10.0/24;\ndeny all;\n')
        nginx=self.root/'etc/nginx/sites-available/access-gate';nginx.parent.mkdir(parents=True);nginx.write_text(render_http(self.c))
    def tearDown(self):self.temp.cleanup()

    def test_address_change_preserves_ca_codes_and_rolls_out_all_listeners(self):
        ca=(self.base/'ca/root.crt').read_bytes();key=(self.base/'ca/root.key').read_bytes();calls=[]
        c=updated(self.c,dict(server_ipv4='192.168.20.20',listen_ipv4='192.168.20.20',dns_target_ipv4='192.168.20.20',client_networks=['192.168.20.0/24'],admin_networks=['192.168.20.0/24']))
        backup=apply(self.root,c,runner=calls.append,gid=os.getgid())
        self.assertTrue(backup.exists());self.assertEqual((self.base/'ca/root.crt').read_bytes(),ca);self.assertEqual((self.base/'ca/root.key').read_bytes(),key)
        self.assertEqual(json.loads((self.base/'gateway/gateway.json').read_text())['listen_host'],'192.168.20.20')
        self.assertIn('192.168.20.20:80',(self.root/'etc/nginx/sites-available/access-gate').read_text())
        self.assertEqual(self.store.dns_summary()['total'],0)
        self.assertEqual(self.store.admin_security(c)['networks'],['192.168.20.0/24'])
        with self.store.connect() as db:self.assertEqual(db.execute('SELECT count(*) FROM codes WHERE revoked=0').fetchone()[0],1)
        self.assertTrue(any('access_gate.readiness' in call for call in calls))

    def test_failed_readiness_restores_managed_files_and_preserves_database(self):
        from access_gate.reconfigure import FILES
        before={f:(self.root/f).read_bytes() for f in FILES if (self.root/f).exists()};fail=[True]
        def runner(args):
            if 'access_gate.readiness' in args and fail[0]:fail[0]=False;raise RuntimeError('not ready')
        c=updated(self.c,dict(portal_url='https://new.example'))
        with self.assertRaisesRegex(RuntimeError,'previous configuration restored'):apply(self.root,c,runner=runner,gid=os.getgid())
        self.assertEqual(before,{f:(self.root/f).read_bytes() for f in before})
        with self.store.connect() as db:self.assertEqual(db.execute('SELECT count(*) FROM codes WHERE revoked=0').fetchone()[0],1)

    def test_crypto_or_nginx_preflight_failure_leaves_live_config_untouched(self):
        before=(self.base/'config.json').read_bytes()
        def runner(args):raise RuntimeError('invalid nginx')
        with self.assertRaises(RuntimeError):apply(self.root,self.c,runner=runner,gid=os.getgid())
        self.assertEqual((self.base/'config.json').read_bytes(),before)

    def test_reconfigure_cannot_replace_secrets_or_database_path(self):
        for key in ('secret','database','admin_hash','pepper','dns_mode'):
            with self.subTest(key=key),self.assertRaises(ValueError):updated(self.c,{key:'unexpected'})

    def test_origin_change_clears_admin_and_push_without_revoking_codes(self):
        token,login=self.store.new_admin_login('a'*64,self.c)
        self.store.save_push('a'*64,login['id'],'https://fcm.googleapis.com/subscription',self.c)
        self.assertIsNotNone(self.store.admin_login(token,'a'*64,self.c))
        apply(self.root,updated(self.c,dict(portal_url='https://new.example')),runner=lambda args:None,gid=os.getgid())
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM admin_logins').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT count(*) FROM push_subscriptions').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT count(*) FROM codes WHERE revoked=0').fetchone()[0],1)
