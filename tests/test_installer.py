import json,os,tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
from access_gate.installer import profile,preflight,password_file,wizard
from test_deployment_settings import profile as deployment


class InstallerTests(unittest.TestCase):
    def test_same_profile_for_interactive_and_unattended(self):
        answers=['2','192.168.10.20','access.example.net','192.168.10.0/24','192.168.10.0/24','INSTALL']
        with patch('builtins.input',side_effect=answers),patch('builtins.print'),patch('access_gate.installer.local_addresses',return_value=['192.168.10.20']),patch('access_gate.installer.preflight'),patch('getpass.getpass',return_value=''):
            c,password=wizard()
        self.assertEqual(c['dns_mode'],'external');self.assertEqual(c['portal_url'],'https://access.example.net');self.assertEqual(password,'')
        self.assertEqual(profile(c),c)

    def test_preflight_rejects_wrong_address_or_existing_listener(self):
        c=profile(deployment())
        with self.assertRaises(ValueError):preflight(c,addresses=['192.168.10.21'],listeners=[])
        for listener in ('0.0.0.0:443','[::]:80','127.0.0.1:8089'):
            with self.subTest(listener=listener),self.assertRaises(ValueError):preflight(c,addresses=['192.168.10.20'],listeners=[listener])
        preflight(c,addresses=['192.168.10.20'],listeners=['127.0.0.1:22'])

    def test_private_password_input_rejects_public_files_and_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'password';path.write_text('correct-password');path.chmod(0o600)
            self.assertEqual(password_file(path),'correct-password')
            path.chmod(0o644)
            with self.assertRaises(ValueError):password_file(path)
            alias=Path(temp)/'alias';alias.symlink_to(path)
            with self.assertRaises(OSError):password_file(alias)

    def test_cancellation_never_collects_password(self):
        answers=['1','192.168.10.20','192.168.10.20','192.168.10.0/24','192.168.10.0/24','NO']
        with patch('builtins.input',side_effect=answers),patch('builtins.print'),patch('access_gate.installer.local_addresses',return_value=['192.168.10.20']),patch('access_gate.installer.preflight'),patch('getpass.getpass') as password:
            with self.assertRaises(ValueError):wizard()
            password.assert_not_called()
