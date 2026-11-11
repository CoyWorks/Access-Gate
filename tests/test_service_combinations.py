import tempfile
from pathlib import Path
import unittest
from unittest.mock import Mock
from access_gate.services import conflicts,check_shared_nginx,refresh_nginx
from access_gate.installer import profile,preflight,service_conflicts
from test_deployment_settings import profile as settings


class ServiceCombinationTests(unittest.TestCase):
    def config(self):return profile(dict(settings(),web_mode='shared-nginx'))

    def test_shared_web_and_pihole_listeners_on_other_addresses_are_preserved(self):
        c=self.config()
        endpoints=['192.168.10.10:80','192.168.10.10:443','192.168.10.10:53','127.0.0.1:8091']
        preflight(c,addresses=['192.168.10.10','192.168.10.20'],listeners=endpoints)
        for listener in ('0.0.0.0:80','[::]:443','192.168.10.20:443','127.0.0.1:8088'):
            with self.subTest(listener=listener),self.assertRaises(ValueError):preflight(c,addresses=['192.168.10.20'],listeners=[listener])

    def test_shared_builtin_dns_allows_only_nonconflicting_dns_bindings(self):
        c=dict(self.config(),dns_mode='builtin',dns_upstreams=['1.1.1.1'])
        preflight(c,addresses=['192.168.10.20'],listeners=['127.0.0.53:53','192.168.10.10:443'])
        for listener in ('*:53','[::]:53','192.168.10.20:53'):
            with self.subTest(listener=listener),self.assertRaises(ValueError):preflight(c,addresses=['192.168.10.20'],listeners=[listener])

    def test_shared_mode_keeps_cloudpanel_and_other_sites_intact(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);sites=root/'etc/nginx/sites-enabled';sites.mkdir(parents=True)
            other=sites/'cloudpanel-site';other.write_text('keep this virtual host');(root/'etc/cloudpanel').mkdir()
            service_conflicts(root,web_mode='shared-nginx')
            self.assertEqual(other.read_text(),'keep this virtual host')
            with self.assertRaises(ValueError):service_conflicts(root)

    def test_shared_mode_reloads_without_restarting_or_enabling_nginx(self):
        runner=Mock();refresh_nginx(self.config(),runner=runner)
        self.assertEqual(runner.call_args_list[-1].args[0],['/usr/bin/systemctl','reload','nginx.service'])
        self.assertFalse(any('restart' in str(call) or 'enable' in str(call) for call in runner.call_args_list))

    def test_existing_nginx_must_validate_and_include_managed_sites(self):
        runner=Mock();runner.return_value.returncode=0;runner.return_value.stdout='http { include /etc/nginx/sites-enabled/*; }'
        # Check parser/commands against an isolated filesystem, then exercise real-root command validation.
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            with self.assertRaises(ValueError):check_shared_nginx(root,runner=runner)
            (root/'etc/nginx/sites-enabled').mkdir(parents=True);check_shared_nginx(root,runner=runner)

    def test_nginx_include_globs_match_the_managed_conf_filename(self):
        from access_gate.services import includes_managed_site
        self.assertTrue(includes_managed_site('include /etc/nginx/sites-enabled/*;'))
        self.assertTrue(includes_managed_site('include /etc/nginx/sites-enabled/*.conf;'))
        self.assertFalse(includes_managed_site('# include /etc/nginx/sites-enabled/*;\ninclude /etc/nginx/sites-enabled/other-*.conf;'))
