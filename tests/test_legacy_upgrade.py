import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPTS=Path(__file__).resolve().parents[1]/'scripts'
sys.path.insert(0,str(SCRIPTS))
import legacy_upgrade as legacy
from reset_install import APPARMOR_BLOCK


class LegacyUpgradeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name)
        for directory in ('etc/access-gate','etc/squid','etc/systemd/system','etc/apparmor.d/local'):
            (self.root/directory).mkdir(parents=True,exist_ok=True)
    def tearDown(self): self.temp.cleanup()
    def test_enabled_interception_refuses_before_changes(self):
        (self.root/'etc/access-gate/network.json').write_text('{"scope":"10.40.135.0/24"}')
        with self.assertRaisesRegex(ValueError,'matching FortiGate rollback'): legacy.check(self.root)
        self.assertTrue((self.root/'etc/access-gate/network.json').exists())
    def test_known_proxy_is_retired_and_unrelated_rules_and_data_preserved(self):
        config=self.root/'etc/squid/squid.conf'; config.write_text('/opt/access-gate/access_gate/acl_helper.py')
        (self.root/'etc/squid/squid.conf.before-access-gate').write_text('original squid settings')
        profile=self.root/'etc/apparmor.d/local/usr.sbin.squid'; profile.write_text('unrelated\n'+APPARMOR_BLOCK)
        for name in ('access-gate-keeper.service','access-gate-network.service'):
            (self.root/'etc/systemd/system'/name).write_text('old unit')
        data=self.root/'etc/access-gate/config.json'; data.write_text('credentials stay')
        calls=[]; legacy.retire(self.root,lambda command,**kw:calls.append(command))
        self.assertEqual(config.read_text(),'original squid settings')
        self.assertEqual(profile.read_text(),'unrelated\n')
        self.assertEqual(data.read_text(),'credentials stay')
        self.assertEqual(len(calls),3)
    def test_custom_or_missing_legacy_restore_refuses(self):
        (self.root/'etc/squid/squid.conf').write_text('/opt/access-gate/access_gate/acl_helper.py')
        with self.assertRaisesRegex(ValueError,'backup is missing'): legacy.check(self.root)
        (self.root/'etc/squid/squid.conf.before-access-gate').write_text('old')
        (self.root/'etc/apparmor.d/local/usr.sbin.squid').write_text('# Access Gate local pilot\ncustomized block\n')
        with self.assertRaisesRegex(ValueError,'customized'): legacy.check(self.root)
    def test_unrelated_squid_is_not_stopped_or_rewritten(self):
        config=self.root/'etc/squid/squid.conf'; config.write_text('unrelated squid')
        calls=[]; legacy.retire(self.root,lambda command,**kw:calls.append(command))
        self.assertEqual(config.read_text(),'unrelated squid'); self.assertEqual(calls,[])


if __name__=='__main__': unittest.main()
