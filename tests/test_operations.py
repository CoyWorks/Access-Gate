import base64
import contextlib
import io
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from access_gate.core import Store,GateError
from access_gate.operations import normalize_domain,rule_matches
from access_gate.policy import apply_policy,render_acl,atomic_write
from access_gate.identity import parse_gateways,FortiGate,IdentityUnavailable
from access_gate.keeper import expire,kill_connection,reconcile_identity
from access_gate.network import nft_rules,fortigate_plan,apply,disable
from access_gate.tls_helper import visible_sni
from access_gate.web import create_app
from werkzeug.security import generate_password_hash

FIXTURE=(Path(__file__).parent/'fixtures/fortigate_ike.txt').read_text()


class OperationsTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name)
        self.store=Store(self.root/'db','test-pepper'); self.store.initialize()
        self.now=1000
    def tearDown(self): self.temp.cleanup()
    def batch(self): return self.store.create_batch(count=3,now=self.now)[1]
    def identity(self,username='vpn-android',ip='10.40.135.11',binding='first-session'):
        self.store.save_device(username,username)
        return self.store.observe_identity(dict(username=username,ip=ip,binding=binding),self.now)
    def live(self):
        with self.store.connect() as db: db.execute('UPDATE policy_state SET heartbeat=?,healthy=1 WHERE id=1',(time.monotonic(),))

    def test_import_and_repeat_migration_preserve_legacy_rules(self):
        path=self.root/'domains'; path.write_text('.Example.org\nexample.net\n')
        self.store.import_domains(path); self.store.initialize(); self.store.import_domains(path)
        self.assertEqual(len(self.store.domain_rules()),2)
        self.assertTrue(all(r['subdomains'] and r['enabled'] for r in self.store.domain_rules()))
        self.store.save_domain('another.org')
        path.write_text('changed.org\n'); self.store.import_domains(path)
        self.assertEqual(len(self.store.domain_rules()),3)

    def test_idn_normalization_exact_and_subdomain_boundaries(self):
        self.assertEqual(normalize_domain('BÜCHER.de.'),'xn--bcher-kva.de')
        self.store.save_domain('example.org',False)
        rules=self.store.domain_rules()
        self.assertTrue(rule_matches('example.org',rules)); self.assertFalse(rule_matches('www.example.org',rules))
        self.assertFalse(rule_matches('unrelatedexample.org',rules))
        r=rules[0]; self.store.save_domain(r['domain'],True,rule_id=r['id'])
        self.assertTrue(rule_matches('a.b.example.org',self.store.domain_rules()))
        self.assertEqual(render_acl(self.store.domain_rules()),'.example.org\n')

    def test_invalid_domains_and_portal_lockout_rejected(self):
        for domain in ('https://example.org','example.org/path','example.org:443','*.example.org','127.0.0.1','a..org','toegang.coyseinri.nl','coyseinri.nl'):
            with self.subTest(domain=domain),self.assertRaises(GateError): self.store.save_domain(domain)
        self.assertEqual(self.store.domain_rules(),[])
        self.store.save_domain('coyseinri.nl',False)  # Exact parent does not trap the portal.

    def test_domain_edit_disable_delete_search_and_duplicate(self):
        rule=self.store.save_domain('example.org',description='Reference')
        self.assertEqual(len(self.store.domain_rules('reference')),1)
        with self.assertRaises(GateError): self.store.save_domain('EXAMPLE.ORG')
        self.store.save_domain('new.example.org',False,'Changed',False,rule)
        self.assertFalse(rule_matches('new.example.org',self.store.domain_rules()))
        self.store.delete_domain(rule); self.assertEqual(self.store.domain_rules(),[])

    def test_apply_success_does_not_revoke_active_grants(self):
        code=self.batch()[0]; self.store.redeem(code,'10.40.135.11',self.now)
        self.store.save_domain('example.org')
        acl=self.root/'acl'; acl.write_text('.old.org\n'); calls=[]
        apply_policy(self.store,acl,run=lambda args,**kw:calls.append(args))
        self.assertEqual(acl.read_text(),'.example.org\n')
        self.assertEqual(self.store.policy_status()['applied'],self.store.policy_status()['desired'])
        self.assertIsNotNone(self.store.grant('10.40.135.11',self.now))
        self.assertTrue(rule_matches('www.example.org',self.store.applied_rules()))

    def test_reload_failure_restores_previous_file_and_applied_snapshot(self):
        self.store.save_domain('old.org'); acl=self.root/'acl'
        apply_policy(self.store,acl,run=lambda *a,**k:None)
        self.store.save_domain('new.org'); calls=[]
        def run(command,**kw):
            calls.append(command)
            if len(calls)==2: raise subprocess.CalledProcessError(1,command)
        with contextlib.redirect_stdout(io.StringIO()): self.assertFalse(apply_policy(self.store,acl,run=run))
        self.assertEqual(acl.read_text(),'.old.org\n')
        self.assertEqual(len(self.store.applied_rules()),1)
        self.assertIn('previous rules restored',self.store.policy_status()['error'])
        self.assertNotEqual(self.store.policy_status()['desired'],self.store.policy_status()['applied'])

    def test_failed_rollback_stops_proxy(self):
        self.store.save_domain('new.org'); acl=self.root/'acl'; acl.write_text('.old.org\n'); calls=[]
        def run(command,**kw):
            calls.append(command)
            if 'stop' not in command: raise subprocess.CalledProcessError(1,command)
        with contextlib.redirect_stdout(io.StringIO()): self.assertFalse(apply_policy(self.store,acl,run=run))
        self.assertEqual(calls[-1],['/usr/bin/systemctl','stop','squid.service'])

    def test_edit_during_apply_remains_pending(self):
        self.store.save_domain('old.org'); acl=self.root/'acl'; added=False
        def run(*a,**kw):
            nonlocal added
            if not added: added=True; self.store.save_domain('new.org')
        apply_policy(self.store,acl,run=run)
        state=self.store.policy_status(); self.assertLess(state['applied'],state['desired'])
        self.assertEqual(len(self.store.applied_rules()),1)

    def test_atomic_write_preserves_owner_and_requested_mode(self):
        path=self.root/'file'; path.write_text('old'); before=path.stat()
        atomic_write(path,'new',0o640)
        self.assertEqual((path.stat().st_uid,path.stat().st_gid),(before.st_uid,before.st_gid))
        self.assertEqual(path.stat().st_mode & 0o777,0o640)

    def test_address_reuse_cannot_inherit_a_grant(self):
        identity=self.identity(); code=self.batch()[0]
        self.store.redeem(code,identity['ip'],self.now,identity=identity)
        second=self.identity('vpn-iphone',binding='other-session')
        self.assertIsNone(self.store.authorize(second['ip'],second,now=self.now))
        self.assertIsNone(self.store.grant(second['ip'],self.now))
        with self.assertRaises(GateError): self.store.redeem(code,'10.40.135.12',self.now)

    def test_changed_binding_revokes_without_renewal(self):
        identity=self.identity(); code=self.batch()[0]
        self.store.redeem(code,identity['ip'],self.now,identity=identity)
        end=self.store.grant(identity['ip'],self.now)['expires']
        changed=self.store.observe_identity(dict(username='vpn-android',ip=identity['ip'],binding='new-session'),self.now+10)
        self.assertIsNone(self.store.authorize(identity['ip'],changed,now=self.now+10))
        with self.store.connect() as db: self.assertEqual(db.execute('SELECT expires FROM grants').fetchone()[0],end)
        expire(self.store,lambda c:None,self.now+10,targeted=True)
        with self.assertRaises(GateError): self.store.redeem(code,identity['ip'],self.now+11,identity=changed)

    def test_binding_changed_between_lookup_and_redeem_does_not_consume_code(self):
        identity=self.identity(); code=self.batch()[0]
        self.store.observe_identity(dict(username='vpn-android',ip=identity['ip'],binding='new-session'),self.now+1)
        with self.assertRaises(GateError): self.store.redeem(code,identity['ip'],self.now+2,identity=identity)
        self.assertIsNone(self.store.dashboard()[0][0]['used'])

    def test_same_verified_session_keeps_original_deadline(self):
        identity=self.identity(); self.store.redeem(self.batch()[0],identity['ip'],self.now,identity=identity)
        repeated=self.store.observe_identity(dict(username='vpn-android',ip=identity['ip'],binding=identity['binding']),self.now+20)
        self.assertEqual(self.store.authorize(identity['ip'],repeated,now=self.now+20)['expires'],self.now+900)

    def test_disable_device_denies_and_revokes(self):
        identity=self.identity(); self.store.redeem(self.batch()[0],identity['ip'],self.now,identity=identity)
        self.store.save_device('vpn-android','Android',False,identity['device_id'])
        self.assertIsNone(self.store.authorize(identity['ip'],identity,now=self.now))
        with self.assertRaises(GateError): self.store.observe_identity(dict(username='vpn-android',ip=identity['ip'],binding='same'),self.now)

    def test_source_failure_disconnect_and_ambiguous_users_fail_closed(self):
        identity=self.identity(); self.store.redeem(self.batch()[0],identity['ip'],self.now,identity=identity)
        reconcile_identity(self.store,[],self.now+1)
        self.assertIsNone(self.store.authorize(identity['ip'],identity,now=self.now+1))
        self.assertEqual(self.store.devices()[0]['state'],'Not connected')

    def test_distinct_devices_have_separate_access(self):
        a=self.identity(); b=self.identity('vpn-iphone','10.40.135.12','other')
        codes=self.batch(); self.store.redeem(codes[0],a['ip'],self.now,identity=a)
        self.assertIsNotNone(self.store.authorize(a['ip'],a,now=self.now))
        self.assertIsNone(self.store.authorize(b['ip'],b,now=self.now))

    def test_worker_staleness_denies_without_consuming_code(self):
        code=self.batch()[0]
        with self.assertRaises(GateError): self.store.redeem(code,'10.40.135.11',self.now,enforce=True)
        self.live(); self.store.redeem(code,'10.40.135.11',self.now,enforce=True)
        with self.store.connect() as db: db.execute('UPDATE policy_state SET heartbeat=?',(time.monotonic()-4,))
        self.assertIsNone(self.store.authorize('10.40.135.11',enforce=True,now=self.now))

    def test_only_restricted_tracked_connection_is_closed_at_deadline(self):
        self.store.redeem(self.batch()[0],'10.40.135.11',self.now)
        connection=dict(client_port=40000,local_ip='10.40.22.5',local_port=3130)
        self.store.authorize('10.40.135.11',connection=connection,now=self.now)
        killed=[]; expire(self.store,killed.append,self.now+899,targeted=True); self.assertEqual(killed,[])
        expire(self.store,killed.append,self.now+900,targeted=True)
        self.assertEqual(len(killed),1); self.assertEqual(killed[0]['client_port'],40000)
        self.assertEqual(self.store.list_grants(),[])

    def test_failed_targeted_cleanup_retains_tombstone(self):
        self.store.redeem(self.batch()[0],'10.40.135.11',self.now)
        self.store.authorize('10.40.135.11',connection=dict(client_port=40000,local_ip='10.40.22.5',local_port=3130),now=self.now)
        def fail(c): raise RuntimeError('socket failure')
        with self.assertRaises(RuntimeError): expire(self.store,fail,self.now+900,targeted=True)
        self.assertEqual(len(self.store.list_grants()),1)


class ParserTests(unittest.TestCase):
    def test_gateway_evidence_and_other_tunnel_isolation(self):
        items=parse_gateways(FIXTURE)
        self.assertEqual([(s['username'],s['ip']) for s in items],[('vpn-android','10.40.135.11'),('vpn-iphone','10.40.135.12')])
        self.assertEqual(parse_gateways(FIXTURE,'OCI-T1'),[])
    def test_missing_evidence_and_unestablished_sas_rejected(self):
        for old,new in [('assigned IPv4 address:','missing:'),('eap-user:','missing:'),('id/spi:','missing:'),('established 1/1','established 0/1')]:
            self.assertEqual(parse_gateways(FIXTURE.replace(old,new)),[])
    def test_shared_username_and_duplicate_address_are_denied(self):
        self.assertEqual(parse_gateways(FIXTURE.replace('vpn-iphone','vpn-android')),[])
        self.assertEqual(parse_gateways(FIXTURE.replace('10.40.135.12','10.40.135.11')),[])
    def test_cli_errors_denied_and_no_cache_or_untrusted_command(self):
        with self.assertRaises(IdentityUnavailable): parse_gateways('Command fail. Return code -61')
        calls=[]
        def run(command,**kw): calls.append(command); return subprocess.CompletedProcess(command,0,FIXTURE,'')
        reader=FortiGate(dict(host='10.40.22.1',username='accessgate-reader'),run)
        reader.snapshot(); reader.snapshot()
        self.assertEqual(len(calls),2); self.assertEqual(calls[0][-1],'diagnose vpn ike gateway list')
        self.assertIn('StrictHostKeyChecking=yes',calls[0])
        with self.assertRaises(IdentityUnavailable): FortiGate(dict(host='10.40.22.1',username='root; reboot'))
    def test_ssh_error_returns_no_stale_success(self):
        def fail(*a,**kw): raise subprocess.TimeoutExpired('ssh',4)
        with self.assertRaises(IdentityUnavailable): FortiGate(dict(host='10.40.22.1',username='reader'),fail).snapshot()


def client_hello(ech=False,host=b'example.org',fragment=False):
    sni=len(host+bytes(3)).to_bytes(2,'big')+b'\x00'+len(host).to_bytes(2,'big')+host
    extensions=b'\x00\x00'+len(sni).to_bytes(2,'big')+sni
    if ech: extensions+=b'\xfe\x0d\x00\x01\x00'
    body=b'\x03\x03'+bytes(32)+b'\x00\x00\x02\x13\x01\x01\x00'+len(extensions).to_bytes(2,'big')+extensions
    message=b'\x01'+len(body).to_bytes(3,'big')+body
    chunks=[message[:20],message[20:]] if fragment else [message]
    return base64.b64encode(b''.join(b'\x16\x03\x01'+len(part).to_bytes(2,'big')+part for part in chunks)).decode()


class TransportTests(unittest.TestCase):
    def test_clear_sni_allowed_and_fragmented_handshake_supported(self):
        self.assertTrue(visible_sni(client_hello())); self.assertTrue(visible_sni(client_hello(fragment=True)))
    def test_ech_grease_missing_names_and_malformed_tls_fail_closed(self):
        for value in (client_hello(ech=True),client_hello(host=b''),client_hello(host=b'bad/name.org'),'bad!','-',base64.b64encode(b'bad').decode()):
            self.assertFalse(visible_sni(value))
    def test_nft_scope_original_destination_no_flush_and_direct_intercept_guard(self):
        rules=nft_rules('10.40.135.11/32')
        self.assertIn('ip saddr 10.40.135.11/32',rules); self.assertIn('redirect to :3130',rules)
        self.assertIn('tcp dport { 3129, 3130 } counter drop',rules); self.assertNotIn('flush ruleset',rules)
        with self.assertRaises(ValueError): nft_rules('0.0.0.0/0')
    def test_fortigate_plan_preserves_nat_identity_and_has_scoped_rollback(self):
        forward,rollback=fortigate_plan('10.40.135.0/24',123)
        self.assertIn('set nat disable',forward); self.assertIn('set input-device "NATIVE-VPN"',forward)
        self.assertNotIn('config vpn ipsec',forward); self.assertNotIn('delete 123',rollback)
        self.assertIn('move 9012 before 123',forward)
        self.assertNotIn('OCI-T1',rollback)
        with self.assertRaises(ValueError): fortigate_plan('10.40.135.0/24',9010)
    def test_network_validation_before_mutation_and_no_unowned_overwrite(self):
        with tempfile.TemporaryDirectory() as root:
            state=Path(root)/'state'; calls=[]
            def run(command,**kw):
                calls.append((command,kw)); return subprocess.CompletedProcess(command,1)
            apply('10.40.135.11/32',run,state)
            self.assertIn('--check',calls[1][0]); self.assertEqual(json.loads(state.read_text())['scope'],'10.40.135.11/32')
            state.unlink()
            def exists(command,**kw): return subprocess.CompletedProcess(command,0)
            with self.assertRaises(ValueError): apply('10.40.135.11/32',exists,state)
    def test_targeted_ss_command_is_literal_and_validated(self):
        calls=[]
        kill_connection(dict(ip='10.40.135.11',client_port=40000,local_ip='10.40.22.5',local_port=3130),lambda command,**kw:calls.append(command))
        self.assertEqual(calls[0][-4:],['3130','dport','=','40000'])
        with self.assertRaises(ValueError): kill_connection(dict(ip='bad; reboot',client_port=1,local_ip='10.40.22.5',local_port=3130))


class OperationsWebTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name)
        domains=self.root/'domains'; domains.write_text('example.org\n')
        self.config=dict(secret='test',pepper='test',database=str(self.root/'db'),domains=str(domains),pilot_clients=['10.40.135.0/24'],acl_token='test-acl',admin_hash=generate_password_hash('test-password'))
        self.app=create_app(self.config); self.app.config['TESTING']=True
        self.store=self.app.extensions['store']; self.store.initialize(); self.store.import_domains(domains)
        self.client=self.app.test_client()
    def tearDown(self): self.temp.cleanup()
    def request(self,path,method='GET',data=None,headers=None):
        return self.client.open(path,method=method,data=data,base_url='https://10.40.22.5',environ_overrides={'REMOTE_ADDR':'127.0.0.1'},headers={'X-Real-IP':'10.40.135.11',**(headers or {})})
    def session(self,admin=True):
        self.request('/')
        with self.client.session_transaction(base_url='https://10.40.22.5') as session:
            session['admin']=admin; return session['csrf']
    def test_domains_and_devices_are_admin_only_and_csrf_protected(self):
        for route in ('/admin/domains','/admin/devices'):
            self.assertEqual(self.request(route).status_code,302)
        token=self.session(False)
        self.assertEqual(self.request('/admin/domains/save','POST',dict(csrf=token,domain='new.org')).status_code,302)
        self.assertEqual(self.request('/admin/domains/delete','POST',dict(csrf=token,id=self.store.domain_rules()[0]['id'])).status_code,302)
        self.assertEqual(self.request('/admin/domains/apply','POST',dict(csrf=token)).status_code,302)
        self.assertEqual(self.request('/admin/devices/save','POST',dict(csrf=token,username='vpn-android',label='Android')).status_code,302)
        self.assertEqual(self.store.devices(),[])
        token=self.session()
        for path,data in [('/admin/domains/save',dict(domain='new.org')),('/admin/domains/delete',dict(id='missing')),('/admin/domains/apply',{}),('/admin/devices/save',dict(username='vpn-android',label='Android'))]:
            self.assertEqual(self.request(path,'POST',data).status_code,400)
        self.assertEqual(self.store.domain_rules()[0]['domain'],'example.org')
    def test_domain_and_device_http_flows(self):
        token=self.session()
        self.assertEqual(self.request('/admin/domains').status_code,200)
        response=self.request('/admin/domains/save','POST',dict(csrf=token,domain='BÜCHER.de',subdomains='on',enabled='on',description='<script>safe</script>'))
        self.assertEqual(response.status_code,302)
        self.assertIn(b'xn--bcher-kva.de',self.request('/admin/domains').data)
        self.assertNotIn(b'<script>safe</script>',self.request('/admin/domains').data)
        rule=next(r for r in self.store.domain_rules() if r['domain']=='xn--bcher-kva.de')
        self.assertEqual(self.request('/admin/domains?edit='+rule['id']).status_code,200)
        self.assertEqual(self.request('/admin/domains/delete','POST',dict(csrf=token,id=rule['id'])).status_code,302)
        self.assertEqual(self.request('/admin/devices/save','POST',dict(csrf=token,username='vpn-android',label='Android',enabled='on')).status_code,302)
        self.assertIn(b'Android',self.request('/admin/devices').data)
    def test_identity_failure_does_not_consume_code_or_allow_proxy(self):
        self.config['require_identity']=True
        _,codes=self.store.create_batch(count=1)
        token=self.session(False)
        with patch('access_gate.web.lookup',side_effect=IdentityUnavailable('Reader unavailable')):
            response=self.request('/','POST',dict(csrf=token,code=codes[0]))
            self.assertIn(b'Reader unavailable',response.data)
            self.assertFalse(self.request('/status').json['active'])
        self.assertIsNone(self.store.dashboard()[0][0]['used'])
        self.store.save_device('vpn-android','Android')
        identity=self.store.observe_identity(dict(username='vpn-android',ip='10.40.135.11',binding='verified-session'))
        self.config['enforcement']=True
        with self.store.connect() as db: db.execute('UPDATE policy_state SET healthy=1,heartbeat=?',(time.monotonic(),))
        with patch('access_gate.web.lookup',return_value=identity) as lookup:
            self.assertEqual(self.request('/','POST',dict(csrf=token,code=codes[0])).status_code,302)
            endpoint='/internal/check?ip=10.40.135.11&client_port=40000&local_ip=10.40.22.5&local_port=3130'
            for _ in range(2): self.assertEqual(self.request(endpoint,headers={'X-Gate-Key':'test-acl'}).data,b'OK\n')
            self.assertEqual(lookup.call_count,3)
        with patch('access_gate.web.lookup',side_effect=IdentityUnavailable('source now unavailable')):
            self.assertEqual(self.request(endpoint,headers={'X-Gate-Key':'test-acl'}).data,b'ERR\n')
        with self.store.connect() as db: self.assertEqual(db.execute('SELECT count(*) FROM proxy_connections').fetchone()[0],1)
    def test_invalid_portal_rule_returns_actionable_error(self):
        token=self.session()
        response=self.request('/admin/domains/save','POST',dict(csrf=token,domain='toegang.coyseinri.nl',subdomains='on',enabled='on'))
        self.assertEqual(response.status_code,400); self.assertIn(b'portal itself',response.data)


class BoundaryTests(unittest.TestCase):
    def test_worker_stop_closes_streams_even_when_configuration_is_damaged(self):
        from access_gate.keeper import stop
        with patch('access_gate.keeper.Path.read_text',side_effect=OSError('missing configuration')),patch('access_gate.keeper.close_proxy_connections') as close:
            with self.assertRaises(OSError): stop()
            close.assert_called_once()

    def test_socket_cleanup_failure_stops_squid(self):
        from access_gate.keeper import stop
        with patch('access_gate.keeper.Path.read_text',side_effect=OSError('missing')),patch('access_gate.keeper.close_proxy_connections',side_effect=OSError('ss failed')),patch('access_gate.keeper.subprocess.run') as run:
            with self.assertRaises(OSError): stop()
            self.assertEqual(run.call_args.args[0],['/usr/bin/systemctl','stop','squid.service'])

    def test_failed_nft_check_does_not_activate_or_write_state(self):
        with tempfile.TemporaryDirectory() as root:
            state=Path(root)/'state'; calls=[]
            def run(command,**kw):
                calls.append(command)
                if '--check' in command: raise subprocess.CalledProcessError(1,command)
                return subprocess.CompletedProcess(command,1)
            with self.assertRaises(subprocess.CalledProcessError): apply('10.40.135.0/24',run,state)
            self.assertEqual(len(calls),2); self.assertFalse(state.exists())

    def test_schema_one_upgrade_preserves_used_codes_and_extension_events(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'db'; store=Store(path,'pepper'); store.initialize()
            _,codes=store.create_batch(count=1,now=1000)
            store.redeem(codes[0],'10.40.135.11',1000)
            grant=store.grant('10.40.135.11',1000)
            store.extend(grant['session_id'],1,'hours','a'*32,now=1001)
            with store.connect() as db:
                # Recreate the schema-1 shape while retaining the real version-1 data.
                db.execute('DROP TABLE proxy_connections')
                for table in ('domain_rules','policy_state','devices'): db.execute('DROP TABLE '+table)
                db.execute('DROP INDEX grants_device')
                db.execute('ALTER TABLE grants DROP COLUMN device_id')
                db.execute('ALTER TABLE grants DROP COLUMN vpn_binding')
                db.execute('PRAGMA user_version=1')
            store.initialize(); store.initialize()
            self.assertEqual(store.grant('10.40.135.11',1002)['expires'],5500)
            self.assertEqual(len(store.extension_history()),1)
            with self.assertRaises(GateError): store.redeem(codes[0],'10.40.135.12',1002)
            with store.connect() as db: self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(),[])


if __name__=='__main__': unittest.main()
