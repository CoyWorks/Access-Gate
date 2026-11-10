import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC=importlib.util.spec_from_file_location('update_from_git',Path(__file__).resolve().parents[1]/'scripts'/'update_from_git.py')
UPDATER=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(UPDATER)


@unittest.skipUnless(shutil.which('git'),'Git is required for updater integration tests')
class UpdateTests(unittest.TestCase):
    def git(self,repo,*args):
        return subprocess.run(['git','-C',str(repo),*args],check=True,text=True,
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE).stdout.strip()

    def identity(self,repo):
        self.git(repo,'config','user.name','Updater tests')
        self.git(repo,'config','user.email','tests@example.invalid')

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.remote=self.root/'remote.git'
        self.seed=self.root/'seed'
        self.repo=self.root/'clone with spaces'
        subprocess.run(['git','init','--bare','--initial-branch=main',str(self.remote)],check=True,capture_output=True)
        subprocess.run(['git','clone',str(self.remote),str(self.seed)],check=True,capture_output=True)
        self.identity(self.seed)
        (self.seed/'README.md').write_text('initial\n')
        (self.seed/'update.sh').write_text('echo initial\n')
        self.git(self.seed,'add','.')
        self.git(self.seed,'commit','-m','Initial')
        self.git(self.seed,'push','origin','main')
        subprocess.run(['git','clone',str(self.remote),str(self.repo)],check=True,capture_output=True)
        self.identity(self.repo)
        self.initial=self.git(self.repo,'rev-parse','HEAD')

    def tearDown(self): self.temp.cleanup()

    def advance(self):
        (self.seed/'update.sh').write_text('echo updated\n')
        (self.seed/'README.md').unlink()
        (self.seed/'NEW.md').write_text('latest\n')
        self.git(self.seed,'add','-A')
        self.git(self.seed,'commit','-m','Update remote')
        self.git(self.seed,'push','origin','main')
        return self.git(self.seed,'rev-parse','HEAD')

    def test_fast_forward_downloads_latest_files_and_removes_old_files(self):
        latest=self.advance()
        self.assertEqual(UPDATER.synchronize(self.repo),latest)
        self.assertEqual(self.git(self.repo,'rev-parse','HEAD'),latest)
        self.assertEqual((self.repo/'update.sh').read_text(),'echo updated\n')
        self.assertFalse((self.repo/'README.md').exists())
        self.assertTrue((self.repo/'NEW.md').exists())

    def test_up_to_date_is_successful(self):
        self.assertEqual(UPDATER.synchronize(self.repo),self.initial)

    def test_modified_tracked_file_is_preserved(self):
        self.advance()
        (self.repo/'README.md').write_text('local edit\n')
        with self.assertRaises(UPDATER.UpdateError): UPDATER.synchronize(self.repo)
        self.assertEqual((self.repo/'README.md').read_text(),'local edit\n')
        self.assertEqual(self.git(self.repo,'rev-parse','HEAD'),self.initial)

    def test_untracked_files_are_preserved(self):
        self.advance()
        (self.repo/'notes.txt').write_text('keep\n')
        with self.assertRaises(UPDATER.UpdateError): UPDATER.synchronize(self.repo)
        self.assertEqual((self.repo/'notes.txt').read_text(),'keep\n')

    def test_divergence_does_not_rewrite_local_history(self):
        self.advance()
        self.git(self.repo,'commit','--allow-empty','-m','Local commit')
        head=self.git(self.repo,'rev-parse','HEAD')
        with self.assertRaises(UPDATER.UpdateError): UPDATER.synchronize(self.repo)
        self.assertEqual(self.git(self.repo,'rev-parse','HEAD'),head)

    def test_unpublished_local_commit_is_not_deployed(self):
        self.git(self.repo,'commit','--allow-empty','-m','Unpublished')
        with self.assertRaises(UPDATER.UpdateError): UPDATER.synchronize(self.repo)

    def test_fetch_failure_preserves_checkout(self):
        self.git(self.repo,'remote','set-url','origin',str(self.root/'missing.git'))
        with self.assertRaises(UPDATER.UpdateError): UPDATER.synchronize(self.repo)
        self.assertEqual(self.git(self.repo,'rev-parse','HEAD'),self.initial)

    def test_detached_checkout_is_rejected(self):
        self.git(self.repo,'checkout','--detach')
        with self.assertRaises(UPDATER.UpdateError): UPDATER.synchronize(self.repo)

    def test_extracted_archive_is_rejected(self):
        archive=self.root/'archive'
        archive.mkdir()
        with self.assertRaises(UPDATER.UpdateError): UPDATER.synchronize(archive)

    def test_other_branch_is_rejected(self):
        self.git(self.repo,'checkout','-b','development')
        with self.assertRaises(UPDATER.UpdateError): UPDATER.synchronize(self.repo)

    def test_main_executes_new_updater_after_fetch(self):
        self.advance()
        def execute(program,argv):
            self.assertEqual(program,'/bin/bash')
            self.assertEqual(argv,['bash',str(self.repo/'update.sh'),'--local'])
            self.assertEqual((self.repo/'update.sh').read_text(),'echo updated\n')
        with patch.object(UPDATER.sys,'argv',['update_from_git.py',str(self.repo)]), patch.object(UPDATER.os,'execv',side_effect=execute) as execute_mock:
            UPDATER.main()
            execute_mock.assert_called_once()

    def test_failed_sync_does_not_start_installer(self):
        (self.repo/'README.md').write_text('local change\n')
        with patch.object(UPDATER.sys,'argv',['update_from_git.py',str(self.repo)]), patch.object(UPDATER.os,'execv') as execute_mock:
            self.assertEqual(UPDATER.main(),1)
            execute_mock.assert_not_called()


if __name__=='__main__': unittest.main()
