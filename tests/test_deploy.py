import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1]/'scripts'/'deploy_portal.py'
SPEC = importlib.util.spec_from_file_location('deploy_portal',SCRIPT)
DEPLOY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DEPLOY)


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root/'download with spaces'
        self.destination = self.root/'installed'
        self.source.mkdir()
        for folder in DEPLOY.DIRECTORIES:
            (self.source/folder).mkdir()
        (self.source/'access_gate'/'__init__.py').write_text('')
        (self.source/'access_gate'/'web.py').write_text('VERSION = 2\n')
        (self.source/'templates'/'index.html').write_text('New portal')
        (self.source/'static'/'gate.css').write_text('New stylesheet')
        (self.source/'wsgi.py').write_text('app = None\n')
        (self.source/'configure.py').write_text('')
        (self.source/'VERSION').write_text('test-version\n')

    def tearDown(self): self.temp.cleanup()

    def test_fresh_deploy(self):
        self.assertIsNone(DEPLOY.deploy(self.source,self.destination))
        self.assertEqual((self.destination/'templates'/'index.html').read_text(),'New portal')
        self.assertEqual((self.destination/'VERSION').read_text(),'test-version\n')
        self.assertEqual(self.destination.stat().st_mode & 0o777,0o755)

    def test_update_removes_obsolete_files_and_preserves_external_state(self):
        self.destination.mkdir()
        (self.destination/'old.py').write_text('Old application')
        (self.destination/'templates').mkdir()
        (self.destination/'templates'/'index.html').write_text('Old portal')
        state = self.root/'server-state'
        state.mkdir()
        original={'gate.sqlite3':b'database','root.key':b'private key','config.json':b'server settings'}
        for name,content in original.items(): (state/name).write_bytes(content)
        previous = DEPLOY.deploy(self.source,self.destination)
        self.assertFalse((self.destination/'old.py').exists())
        self.assertEqual((self.destination/'templates'/'index.html').read_text(),'New portal')
        self.assertEqual((previous/'templates'/'index.html').read_text(),'Old portal')
        self.assertEqual({p.name:p.read_bytes() for p in state.iterdir()},original)

    def test_invalid_python_does_not_change_existing_installation(self):
        self.destination.mkdir()
        (self.destination/'original').write_text('keep')
        (self.source/'access_gate'/'web.py').write_text('def invalid(\n')
        with self.assertRaises(SyntaxError): DEPLOY.deploy(self.source,self.destination)
        self.assertEqual((self.destination/'original').read_text(),'keep')
        self.assertFalse(list(self.root.glob('.access-gate-stage-*')))

    def test_missing_source_does_not_change_installation(self):
        self.destination.mkdir()
        (self.destination/'original').write_text('keep')
        (self.source/'wsgi.py').unlink()
        with self.assertRaises(ValueError): DEPLOY.deploy(self.source,self.destination)
        self.assertEqual((self.destination/'original').read_text(),'keep')

    def test_failed_activation_restores_previous_application(self):
        self.destination.mkdir()
        (self.destination/'original').write_text('keep')
        real_replace = DEPLOY.os.replace
        calls=[]
        def replace(src,dst):
            calls.append((src,dst))
            if len(calls)==2: raise OSError('simulated activation failure')
            return real_replace(src,dst)
        with patch.object(DEPLOY.os,'replace',replace):
            with self.assertRaises(OSError): DEPLOY.deploy(self.source,self.destination)
        self.assertEqual((self.destination/'original').read_text(),'keep')

    def test_rejects_source_inside_installed_application(self):
        with self.assertRaises(ValueError): DEPLOY.deploy(self.source,self.source/'installed')
        with self.assertRaises(ValueError): DEPLOY.deploy(self.source,self.source)

    def test_rejects_source_symlink(self):
        outside = self.root/'private.txt'
        outside.write_text('private')
        (self.source/'static'/'unexpected').symlink_to(outside)
        with self.assertRaises(ValueError): DEPLOY.deploy(self.source,self.destination)
        self.assertFalse(self.destination.exists())

    def test_ignores_compiled_cache(self):
        cached = self.source/'access_gate'/'__pycache__'
        cached.mkdir()
        (cached/'old.pyc').write_bytes(b'old bytecode')
        DEPLOY.deploy(self.source,self.destination)
        self.assertFalse((self.destination/'access_gate'/'__pycache__').exists())


if __name__=='__main__': unittest.main()
