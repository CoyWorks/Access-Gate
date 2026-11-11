import base64,copy,datetime as dt,hashlib,json,os,secrets,tempfile,time
from pathlib import Path
import unittest
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from access_gate.core import Store
from access_gate.web import create_app
from access_gate.public_security import totp
from access_gate.public_deploy import enrollment,validate_tls
from access_gate.deployment import normalize,render_http
from test_deployment_settings import profile


class PublicPortalTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.c=normalize(dict(profile(),secret='s',pepper='p',acl_token='t',admin_hash='h',database=str(self.root/'db'),public_portal=True))
        self.store=Store(self.c['database'],'p');self.store.initialize();self.store.add_dns_domains('restricted.example')
        self.app=create_app(self.c);self.client=self.app.test_client()
        self.key='a'*64;self.fingerprint='f'*64
        self.gid=self.store.register_gateway('First',self.fingerprint,self.key,time.time()+600)
        self.headers={'X-Gate-Key':'t','X-Gate-Peer-Fingerprint':self.fingerprint,'X-Gateway-Key':self.key,'X-Gate-Origin':'https://restricted.example'}
    def tearDown(self):self.temp.cleanup()
    def rpc(self,path,method='GET',**kwargs):
        return self.client.open('/gateway/v1/'+path,method=method,base_url=self.c['portal_url'],headers=kwargs.pop('headers',self.headers),environ_overrides={'REMOTE_ADDR':'127.0.0.1'},**kwargs)
    def activate(self):self.assertEqual(self.rpc('activate',method='POST').status_code,200)

    def test_enrollment_is_one_use_and_revocation_takes_effect_immediately(self):
        self.assertEqual(self.rpc('health').status_code,403);self.activate()
        self.assertEqual(self.rpc('activate',method='POST').status_code,409)
        self.assertEqual(self.rpc('health').json['gateway'],self.gid)
        self.assertEqual(self.rpc('health',headers=dict(self.headers,**{'X-Gateway-Key':'b'*64})).status_code,403)
        self.store.revoke_gateway(self.gid);self.assertEqual(self.rpc('health').status_code,403)

    def test_browser_handoff_is_bound_to_gateway_origin_challenge_and_deadline(self):
        self.activate();start=self.rpc('start');self.assertEqual(start.status_code,302)
        entry=start.headers['Location'].split('entry=')[1];nonce=self.client.get_cookie('__Host-accessgate-challenge',domain='access.example.net').value
        bid,codes=self.store.create_batch(count=1);self.store.redeem(codes[0],'192.168.10.30',browser_token='c'*64)
        target,ticket=self.store.issue_handoff(entry,'c'*64)
        for values in (dict(gateway_id='other'),dict(nonce='d'*64),dict(target='https://other.example')):
            args=dict(ticket=ticket,nonce=nonce,target=target,gateway_id=self.gid);args.update(values)
            with self.assertRaises(ValueError):self.store.accept_handoff(**args)
        proof=self.store.accept_handoff(ticket,nonce,target,gateway_id=self.gid)
        self.assertIsNone(self.store.gateway_grant(proof['token'],target))
        self.assertIsNotNone(self.store.gateway_grant(proof['token'],target,gateway_id=self.gid))
        with self.assertRaises(ValueError):self.store.accept_handoff(ticket,nonce,target,gateway_id=self.gid)
        self.store.revoke_batch(bid)
        self.assertIsNone(self.store.gateway_grant(proof['token'],target,gateway_id=self.gid))

    def test_public_visitor_is_allowed_but_management_and_feeds_remain_private(self):
        common=dict(base_url=self.c['portal_url'],headers={'X-Real-IP':'8.8.8.8'},environ_overrides={'REMOTE_ADDR':'127.0.0.1'})
        self.assertEqual(self.client.get('/',**common).status_code,200)
        self.assertEqual(self.client.get('/admin/login',**common).status_code,403)
        self.assertEqual(self.client.get('/pihole.conf',**common).status_code,403)
        self.assertEqual(self.client.get('/internal/check',**common).status_code,403)
        self.assertEqual(self.client.get('/gateway/v1/health',**common).status_code,403)

    def test_totp_vectors_replay_and_one_use_recovery(self):
        seed=base64.b32encode(b'12345678901234567890').decode()
        self.assertEqual(totp(seed,1,digits=8),'94287082')
        now=1234567890;counter=now//30
        codes=self.store.set_mfa(seed,totp(seed,counter),now=now)
        self.assertFalse(self.store.verify_mfa(totp(seed,counter),now=now))
        self.assertTrue(self.store.verify_mfa(totp(seed,counter+1),now=now+30))
        self.assertFalse(self.store.verify_mfa(totp(seed,counter+1),now=now+30))
        self.assertTrue(self.store.verify_mfa(codes[0]));self.assertFalse(self.store.verify_mfa(codes[0]))
        with self.store.connect() as db:self.assertNotIn(seed.encode(),db.execute('SELECT seed FROM admin_mfa').fetchone()[0])

    def test_public_admin_password_alone_does_not_sign_in(self):
        from werkzeug.security import generate_password_hash
        c=dict(self.c,public_admin=True,admin_networks=['0.0.0.0/0'],admin_hash=generate_password_hash('password123'))
        app=create_app(c);client=app.test_client();common=dict(base_url=c['portal_url'],headers={'X-Real-IP':'8.8.8.8'},environ_overrides={'REMOTE_ADDR':'127.0.0.1'})
        seed=base64.b32encode(os.urandom(20)).decode();now=time.time();self.store.set_mfa(seed,totp(seed,int(now)//30),now=now)
        client.get('/admin/login',**common)
        with client.session_transaction(base_url=c['portal_url']) as session:csrf=session['csrf']
        r=client.post('/admin/login',data=dict(password='password123',csrf=csrf),**common);self.assertEqual(r.status_code,200)
        recovery=self.store.set_mfa(seed,totp(seed,int(now)//30),now=now)
        r=client.post('/admin/login',data=dict(password='password123',factor=recovery[0],csrf=csrf),**common);self.assertEqual(r.status_code,302)

    def test_limits_bound_source_keys_and_acme_does_not_open_portal(self):
        self.assertTrue(self.store.public_limit('scope',1,now=120));self.assertFalse(self.store.public_limit('scope',1,now=121));self.assertTrue(self.store.public_limit('scope',1,now=180))
        self.assertNotIn('/.well-known/acme-challenge/',render_http(self.c))
        conf=render_http(dict(self.c,acme_http=True));self.assertIn('allow all;',conf);self.assertIn('include /etc/access-gate/client-networks.nginx;',conf)

    def test_enrollment_certificate_is_separate_and_client_auth_only(self):
        (self.root/'etc/access-gate').mkdir(parents=True)
        peer=enrollment(self.store,self.c,'Second',base=self.root/'etc/access-gate',gid=os.getgid())
        cert=x509.load_pem_x509_certificate(peer['cert'].encode())
        from cryptography.x509.oid import ExtendedKeyUsageOID
        self.assertIn(ExtendedKeyUsageOID.CLIENT_AUTH,cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
        self.assertNotIn('inspection',cert.issuer.rfc4514_string().lower())

    def test_private_dns_mirror_uses_local_target_and_rejects_authority_overlap(self):
        c=dict(self.c,public_portal=False,remote_gateway=True,remote_portal_url='https://authority.public.example')
        client=create_app(c).test_client();kwargs=dict(base_url=c['portal_url'],headers={'X-Gate-Key':'t'},environ_overrides={'REMOTE_ADDR':'127.0.0.1'})
        payload=dict(domains=[dict(domain='mirrored.example',include_subdomains=True)])
        self.assertEqual(client.post('/internal/remote-domains',json=payload,**kwargs).status_code,200)
        self.assertIn('address=/mirrored.example/192.168.10.20',self.store.export_dns_domains('dnsmasq',target_ip=c['dns_target_ipv4']))
        payload['domains']=[dict(domain='public.example',include_subdomains=True)]
        self.assertEqual(client.post('/internal/remote-domains',json=payload,**kwargs).status_code,400)
        self.assertEqual(self.store.list_dns_domains()[0]['domain'],'mirrored.example')

    def test_remote_source_header_cannot_claim_a_network_exemption(self):
        self.store.save_admin_security(self.c,exclusions=['192.168.10.0/24'])
        self.activate()
        r=self.rpc('check',headers=dict(self.headers,**{'X-Gate-Client-IP':'192.168.10.30'}))
        self.assertEqual(r.status_code,401)

    def test_tls_sources_follow_renewed_symlinks_and_reject_insecure_keys(self):
        from types import SimpleNamespace
        from access_gate.public_deploy import tls_sources
        cert=self.root/'live-cert';key=self.root/'live-key'
        first=self.root/'first';second=self.root/'second';first.write_bytes(b'certificate 1');second.write_bytes(b'certificate 2')
        key.write_bytes(b'protected key');cert.symlink_to(first)
        with patch.object(Path,'stat',return_value=SimpleNamespace(st_uid=0,st_mode=0o100600)):
            self.assertEqual(tls_sources(cert,key)[0],b'certificate 1')
            cert.unlink();cert.symlink_to(second)
            self.assertEqual(tls_sources(cert,key)[0],b'certificate 2')
        with patch.object(Path,'stat',return_value=SimpleNamespace(st_uid=0,st_mode=0o100644)):
            with self.assertRaises(ValueError):tls_sources(cert,key)
