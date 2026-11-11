import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class PiHoleSyncTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name)
        self.bin=self.root/'bin'; self.bin.mkdir()
        self.directory=self.root/'dnsmasq.d'; self.directory.mkdir()
        self.config=self.directory/'99-access-gate.conf'
        self.old='# Access Gate DNS mappings: 10.40.22.5\nhost-record=old.example,10.40.22.5\n'
        self.new='# Access Gate DNS mappings: 10.40.22.5\naddress=/new.example/10.40.22.5\nlocal=/new.example/\n'
        self.config.write_text(self.old)
        self.download=self.root/'download'; self.download.write_text(self.new)
        self.log=self.root/'restarts'
        # Run the unchanged command flow against isolated fixtures, not the host DNS service.
        source=(Path(__file__).resolve().parents[1]/'scripts/sync_pihole.sh').read_text()
        source=source.replace('if [[ $EUID -ne 0 ]]','if false')
        source=source.replace('/run/lock/access-gate-pihole-sync.lock',str(self.root/'lock'))
        source=source.replace('/etc/dnsmasq.d',str(self.directory))
        self.script=self.root/'sync.sh'; self.script.write_text(source)
        commands={
            'curl':'[[ ${FAIL_DOWNLOAD:-0} == 0 ]] || exit 22\ncp "$DOWNLOAD" "${@: -1}"',
            'pihole-FTL':'[[ ${FAIL_TEST:-0} == 0 ]]',
            'systemctl':'echo restart >> "$RESTART_LOG"\nif [[ ${FAIL_RESTART:-0} == 1 && ! -e "$FAIL_MARKER" ]]; then touch "$FAIL_MARKER"; exit 1; fi',
        }
        for name,body in commands.items():
            p=self.bin/name; p.write_text('#!/usr/bin/env bash\nset -eu\n'+body+'\n'); p.chmod(0o755)
        self.env=dict(os.environ,ACCESS_GATE_FEED_URL='http://10.40.22.5/pihole.conf',ACCESS_GATE_TARGET_IP='10.40.22.5',PATH=str(self.bin)+os.pathsep+os.environ['PATH'],DOWNLOAD=str(self.download),RESTART_LOG=str(self.log),FAIL_MARKER=str(self.root/'failed'))
    def tearDown(self): self.temp.cleanup()
    def run_sync(self,**env):
        return subprocess.run(['bash',str(self.script)],env=dict(self.env,**env),capture_output=True,text=True)
    def test_changed_config_is_installed_and_restarted_once(self):
        result=self.run_sync(); self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.config.read_text(),self.new)
        self.assertEqual(self.log.read_text(),'restart\n')
        self.assertEqual(self.run_sync().returncode,0)
        self.assertEqual(self.log.read_text(),'restart\n')
    def test_download_or_header_or_syntax_failure_preserves_old_config(self):
        for env in ({'FAIL_DOWNLOAD':'1'},{'FAIL_TEST':'1'}):
            with self.subTest(env=env):
                self.assertNotEqual(self.run_sync(**env).returncode,0)
                self.assertEqual(self.config.read_text(),self.old)
                self.assertFalse(self.log.exists())
        self.download.write_text('<html>Error</html>')
        self.assertNotEqual(self.run_sync().returncode,0)
        self.assertEqual(self.config.read_text(),self.old)
        self.assertFalse(self.log.exists())
    def test_restart_failure_rolls_back_and_restarts_previous_config(self):
        self.assertNotEqual(self.run_sync(FAIL_RESTART='1').returncode,0)
        self.assertEqual(self.config.read_text(),self.old)
        self.assertEqual(self.log.read_text(),'restart\nrestart\n')
    def test_empty_managed_list_clears_old_mappings(self):
        header='# Access Gate DNS mappings: 10.40.22.5\n'
        self.download.write_text(header)
        self.assertEqual(self.run_sync().returncode,0)
        self.assertEqual(self.config.read_text(),header)
    def test_first_install_failure_removes_candidate(self):
        self.config.unlink()
        self.assertNotEqual(self.run_sync(FAIL_TEST='1').returncode,0)
        self.assertFalse(self.config.exists())
