import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from werkzeug.security import generate_password_hash,check_password_hash
from access_gate.core import Store
from configure import main


class AdminPasswordTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name)
        self.path=self.root/'config.json'; self.initial=self.root/'initial.txt'
        self.config=dict(secret='old-session-secret',pepper='retained-pepper',acl_token='retained-key',database=str(self.root/'db'),admin_hash=generate_password_hash('old-password'))
        self.path.write_text(json.dumps(self.config)); self.path.chmod(0o640)
        self.initial.write_text('Admin password: old-password'); self.initial.chmod(0o600)
        self.store=Store(self.config['database'],self.config['pepper']); self.store.initialize()
        _,self.codes=self.store.create_batch(count=2)
        self.store.redeem(self.codes[0],'10.40.22.99',browser_token='a'*64)
    def tearDown(self): self.temp.cleanup()
    def change(self,values):
        with patch('configure.os.geteuid',return_value=0),patch('configure.getpass.getpass',side_effect=values):
            main(['--set-admin-password'],str(self.path),str(self.initial))
    def test_change_preserves_codes_grants_and_permissions_and_rotates_admin_sessions(self):
        before=self.store.browser_grant('a'*64)
        self.change(['new-password','new-password'])
        config=json.loads(self.path.read_text())
        self.assertTrue(check_password_hash(config['admin_hash'],'new-password'))
        self.assertFalse(check_password_hash(config['admin_hash'],'old-password'))
        self.assertNotEqual(config['secret'],self.config['secret'])
        for name in ('database','pepper','acl_token'): self.assertEqual(config[name],self.config[name])
        self.assertEqual(self.path.stat().st_mode&0o777,0o640)
        self.assertNotIn('new-password',self.path.read_text())
        self.assertNotIn('old-password',self.initial.read_text())
        self.assertNotIn('new-password',self.initial.read_text())
        self.assertEqual(self.initial.stat().st_mode&0o777,0o600)
        self.assertEqual(before,self.store.browser_grant('a'*64))
        self.store.redeem(self.codes[1],'10.40.22.98',browser_token='b'*64)
    def test_invalid_or_cancelled_input_leaves_all_files_unchanged(self):
        before=self.path.read_bytes(); initial=self.initial.read_bytes()
        for values in (['too-short','different'],['short','short'],[KeyboardInterrupt()], [EOFError()]):
            with self.subTest(values=values):
                with self.assertRaises(SystemExit): self.change(values)
                self.assertEqual(self.path.read_bytes(),before)
                self.assertEqual(self.initial.read_bytes(),initial)
