import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC=importlib.util.spec_from_file_location('reset_install',Path(__file__).resolve().parents[1]/'scripts'/'reset_install.py')
RESET=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RESET)


class ResetTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)

    def tearDown(self): self.temp.cleanup()

    def put(self,name,text='sample'):
        p=self.root/name
        p.parent.mkdir(parents=True,exist_ok=True)
        p.write_text(text)
        return p

    def test_purges_installation_and_saved_state_backups(self):
        for name in RESET.REMOVE:
            self.put(name+'/file' if name in ('opt/access-gate','etc/access-gate','var/lib/access-gate','var/lib/squid/ssl_db') else name)
        self.put('root/access-gate-resume.abcdef/config/secret')
        self.put('opt/.access-gate-previous-123/app.py')
        RESET.purge(self.root)
        self.assertFalse(any((self.root/p).exists() for p in RESET.REMOVE))
        self.assertFalse(list(self.root.glob('root/access-gate-resume.*')))

    def test_restores_squid_config(self):
        self.put('etc/squid/squid.conf','use /etc/access-gate/config\n')
        self.put('etc/squid/squid.conf.before-access-gate','original\n')
        RESET.purge(self.root)
        self.assertEqual((self.root/'etc/squid/squid.conf').read_text(),'original\n')

    def test_missing_backup_stops_before_deleting_data(self):
        self.put('etc/squid/squid.conf','use /etc/access-gate/config\n')
        keep=self.put('etc/access-gate/config.json','keep')
        with self.assertRaises(ValueError): RESET.purge(self.root)
        self.assertEqual(keep.read_text(),'keep')

    def test_preserves_other_apparmor_rules(self):
        p=self.put('etc/apparmor.d/local/usr.sbin.squid','custom before\n'+RESET.APPARMOR_BLOCK+'custom after\n')
        RESET.purge(self.root)
        self.assertEqual(p.read_text(),'custom before\ncustom after\n')

    def test_modified_apparmor_block_stops_before_deleting(self):
        self.put('etc/apparmor.d/local/usr.sbin.squid','# Access Gate local pilot\nmodified\n')
        keep=self.put('etc/access-gate/config.json')
        with self.assertRaises(ValueError): RESET.purge(self.root)
        self.assertTrue(keep.exists())

    def test_keeps_source_checkout_other_sites_and_current_custom_squid(self):
        files=[self.put('root/Access-Gate/install.sh','source'),
               self.put('etc/nginx/sites-enabled/other','other site'),
               self.put('etc/squid/squid.conf','custom independent config')]
        self.put('etc/squid/squid.conf.before-access-gate','old')
        RESET.purge(self.root)
        self.assertEqual([p.read_text() for p in files],['source','other site','custom independent config'])

    def test_check_is_read_only_and_repeat_purge_is_safe(self):
        p=self.put('etc/access-gate/config.json','sample')
        RESET.plan(self.root)
        self.assertEqual(p.read_text(),'sample')
        RESET.purge(self.root)
        RESET.purge(self.root)
        self.assertFalse(p.exists())

    def test_does_not_follow_delete_target_symlink(self):
        keep=self.put('outside/private','keep')
        target=self.root/'etc/access-gate'
        target.parent.mkdir(parents=True,exist_ok=True)
        target.symlink_to(keep.parent)
        RESET.purge(self.root)
        self.assertFalse(target.exists())
        self.assertEqual(keep.read_text(),'keep')


if __name__=='__main__': unittest.main()
