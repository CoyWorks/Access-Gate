import json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from access_gate.installer import wizard,write_plan,load_profile,installation_state,main
from test_deployment_settings import profile


class WizardTests(unittest.TestCase):
    def run_wizard(self,answers,**kwargs):
        with patch('builtins.input',side_effect=answers),patch('builtins.print') as output,patch('access_gate.installer.local_addresses',return_value=['192.168.10.20','192.168.10.21']),patch('access_gate.installer.service_conflicts'),patch('access_gate.installer.preflight'),patch('getpass.getpass',return_value='') as password:
            result=wizard(**kwargs)
        return result,output,password

    def test_field_retries_and_back_keep_other_values(self):
        answers=['bad','2','wrong','dedicated','not-ip','192.168.10.20','http://bad.example','access.example.net','bad-cidr','192.168.10.0/24','BACK','192.168.10.0/25','192.168.10.0/24','INSTALL']
        (c,_),output,_=self.run_wizard(answers)
        self.assertEqual(c['portal_url'],'https://access.example.net');self.assertIn('192.168.10.0/25',c['client_networks']);self.assertEqual(c['admin_networks'],['192.168.10.0/24'])
        self.assertTrue(any('Try again' in str(call) for call in output.call_args_list))

    def test_review_edits_address_aliases_and_profile_export_without_password(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'reviewed profile.json'
            answers=['EDIT 3','192.168.10.21','EDIT aliases','other.example','SAVE '+str(path),'FINISH']
            (c,password),_,collector=self.run_wizard(answers,seed=dict(profile(),portal_url='https://192.168.10.20'),plan_only=True)
            self.assertEqual(c['portal_url'],'https://192.168.10.21');self.assertEqual(c['portal_aliases'],['other.example']);collector.assert_not_called();self.assertEqual(password,'')
            self.assertEqual(load_profile(path)['listen_ipv4'],'192.168.10.21');self.assertEqual(path.stat().st_mode&0o777,0o600)
            self.assertNotIn('admin_password_file',path.read_text());self.assertNotIn('secret',path.read_text())

    def test_conflicts_stay_in_review_and_can_be_corrected_or_cancelled(self):
        with patch('builtins.input',side_effect=['RETRY','INSTALL']),patch('builtins.print'),patch('access_gate.installer.service_conflicts'),patch('access_gate.installer.preflight',side_effect=[ValueError('port 53 occupied'),None]) as preflight,patch('getpass.getpass',return_value=''):
            c,_=wizard(seed=profile());self.assertEqual(c['portal_url'],profile()['portal_url']);self.assertEqual(preflight.call_count,2)
        with patch('builtins.input',side_effect=['CANCEL']),patch('builtins.print'),patch('access_gate.installer.service_conflicts'),patch('access_gate.installer.preflight',side_effect=ValueError('port occupied')),patch('getpass.getpass') as password:
            with self.assertRaises(ValueError):wizard(seed=profile())
            password.assert_not_called()

    def test_dns_choice_change_requests_only_missing_upstreams(self):
        answers=['EDIT 1','4','127.0.0.1','192.168.10.20','1.1.1.1','FINISH']
        (c,_),_,_=self.run_wizard(answers,seed=profile(),plan_only=True)
        self.assertEqual(c['dns_mode'],'builtin');self.assertEqual(c['dns_upstreams'],['1.1.1.1'])

    def test_invalid_password_retries_without_losing_plan(self):
        with patch('builtins.input',return_value='INSTALL'),patch('builtins.print'),patch('access_gate.installer.service_conflicts'),patch('access_gate.installer.preflight'),patch('getpass.getpass',side_effect=['short','long-password','mismatch','correct-password','correct-password']):
            c,password=wizard(seed=profile());self.assertEqual(password,'correct-password');self.assertEqual(c['portal_url'],profile()['portal_url'])

    def test_export_refuses_overwrite_and_symlinks_and_filters_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'plan';write_plan(path,dict(profile(),secret='DO-NOT-EXPORT',admin_password_file='/private/password'),new=True)
            self.assertNotIn('DO-NOT-EXPORT',path.read_text());self.assertNotIn('/private/password',path.read_text());before=path.read_bytes()
            with self.assertRaises(OSError):write_plan(path,profile(),new=True)
            with self.assertRaises(ValueError):write_plan(path,profile())
            link=Path(directory)/'alias';link.symlink_to(path)
            with self.assertRaises(OSError):write_plan(link,profile())
            self.assertEqual(path.read_bytes(),before)
            path.write_text(json.dumps(dict(profile(),secret='no')))
            with self.assertRaises(ValueError):load_profile(path)

    def test_plan_only_profile_never_reads_password_or_changes_input(self):
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/'source';dest=Path(directory)/'plan';source.write_text(json.dumps(dict(profile(),admin_password_file='/not/read')));before=source.read_bytes()
            with patch('access_gate.installer.require_root'),patch('access_gate.installer.installation_state',return_value='new'),patch('access_gate.installer.service_conflicts'),patch('access_gate.installer.preflight'),patch('access_gate.installer.password_file',side_effect=AssertionError('Password must not be read')),patch('builtins.print'):
                main([str(dest),'--profile',str(source),'--plan-only'])
            self.assertEqual(source.read_bytes(),before);self.assertFalse(Path(str(dest)+'.password').exists());self.assertEqual(dest.stat().st_mode&0o777,0o600)

    def test_install_resume_state_preserves_existing_identity_and_missing_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);self.assertEqual(installation_state(root),'new')
            checkpoint=root/'var/lib/access-gate/installation/profile.json';checkpoint.parent.mkdir(parents=True);checkpoint.write_text('{}')
            self.assertEqual(installation_state(root),'interrupted')
            database=root/'var/lib/access-gate/data/gate.sqlite3';database.parent.mkdir(parents=True);database.write_text('retain database')
            self.assertEqual(installation_state(root),'missing-config')
            config=root/'etc/access-gate/config.json';config.parent.mkdir(parents=True);config.write_text('retain credentials')
            self.assertEqual(installation_state(root),'existing');self.assertEqual(database.read_text(),'retain database');self.assertEqual(config.read_text(),'retain credentials')
            with patch('access_gate.installer.require_root'),patch('access_gate.installer.installation_state',return_value='existing'),patch('access_gate.installer.wizard',side_effect=AssertionError('Must not re-plan existing server')):
                with self.assertRaises(ValueError):main([str(root/'output')])
