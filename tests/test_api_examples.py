"""Execute integration clients against a disposable, CA-verified HTTPS API."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from flask import Flask,request
from werkzeug.serving import make_server,WSGIRequestHandler
from access_gate.core import Store
from access_gate.rest_api import RestAPI,APISessionInterface
from gateway_fixtures import ca,write_pair,leaf

ROOT=Path(__file__).resolve().parents[1]


class Quiet(WSGIRequestHandler):
    def log(self,*args,**kwargs):pass


class ExampleTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.store=Store(self.root/'db','example-test-pepper');self.store.initialize()
        self.store.save_api_policy(True,'127.0.0.0/8')
        self.identity,self.token=self.store.create_integration('Example client',['batches:create'])
        cert,key=ca('Example fixture CA')
        write_pair(cert,key,self.root/'ca.crt',self.root/'ca.key')
        leaf(cert,key,'localhost',self.root/'tls.crt',self.root/'tls.key')
        self.app=Flask(__name__);self.app.secret_key='example-test';self.app.session_interface=APISessionInterface()
        self.api=RestAPI(self.store,dict(portal_url='https://localhost',remote_gateway=False))
        self.paths=[];self.redirect=False
        @self.app.before_request
        def trusted_test_edge():
            self.paths.append(request.path)
            if self.redirect:
                from flask import redirect
                return redirect(self.api.config['portal_url']+'/redirected',code=302)
            # Disposable TLS adapter, not a deployment setting or forwarded-header trust rule.
            request.environ['HTTP_X_REAL_IP']=request.remote_addr
            return self.api.handle()
        self.server=make_server('127.0.0.1',0,self.app,threaded=True,request_handler=Quiet,ssl_context=(str(self.root/'tls.crt'),str(self.root/'tls.key')))
        self.api.config['portal_url']='https://localhost:'+str(self.server.server_port)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        token_file=self.root/'credential'
        fd=os.open(token_file,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as stream:stream.write(self.token)
        self.env={**os.environ,'ACCESS_GATE_API_URL':self.api.config['portal_url'],
                  'ACCESS_GATE_API_TOKEN_FILE':str(token_file),'ACCESS_GATE_API_CA':str(self.root/'ca.crt'),
                  'SSL_CERT_FILE':str(self.root/'ca.crt'),'NO_PROXY':'localhost,127.0.0.1'}

    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join(timeout=2);self.temp.cleanup()

    def exercise(self,command,flags):
        operation=self.root/'operation.json';output=self.root/'codes.json'
        def run(path,op=operation):
            args=command+[flags[0],str(op),flags[1],str(path)] if flags else command+[str(op),str(path)]
            return subprocess.run(args,env=self.env,capture_output=True,text=True,timeout=30)
        response=run(output)
        self.assertEqual(response.returncode,0,response.stderr+response.stdout)
        original=json.loads(output.read_text());self.assertEqual(len(original['codes']),10)
        self.assertNotIn(self.token,response.stdout+response.stderr)
        self.assertNotIn(original['codes'][0]['code'],response.stdout+response.stderr)
        self.assertEqual(output.stat().st_mode & 0o077,0)
        replay_file=self.root/'replayed.json';replay=run(replay_file)
        self.assertEqual(replay.returncode,0,replay.stderr)
        self.assertEqual(json.loads(replay_file.read_text())['codes'],original['codes'])
        self.assertEqual(self.store.list_batches()['total'],1)
        self.assertEqual(run(output).returncode,0)
        self.store.revoke_integration(self.identity)
        failure=run(self.root/'unauthorized.json')
        self.assertEqual(failure.returncode,2,failure.stderr)
        self.assertIn('401',failure.stderr)
        self.assertFalse((self.root/'unauthorized.json').exists())
        before=len(self.paths)
        plan=json.loads(operation.read_text());original_plan=dict(plan)
        plan['created_at_epoch']=time.time()-86401;operation.write_text(json.dumps(plan))
        self.assertEqual(run(self.root/'too-late.json').returncode,2)
        self.assertEqual(len(self.paths),before)
        operation.write_text(json.dumps(original_plan))
        _,replacement=self.store.create_integration('Replacement',['batches:create'])
        (self.root/'credential').write_text(replacement)
        self.assertEqual(run(self.root/'wrong-identity.json').returncode,2)
        self.assertEqual(len(self.paths),before)
        self.redirect=True
        redirect_result=run(self.root/'redirect.json',op=self.root/'new-operation.json')
        self.assertIn(redirect_result.returncode,(2,75))
        self.assertNotIn('/redirected',self.paths)
        self.assertFalse((self.root/'redirect.json').exists())

    def test_python_client_success_replay_and_error(self):
        self.exercise([sys.executable,str(ROOT/'examples/api/generate_codes.py')],['--operation','--output'])

    @unittest.skipUnless(shutil.which('curl') and shutil.which('bash'),'Requires curl and Bash.')
    def test_curl_client_success_replay_and_error(self):
        self.exercise(['bash',str(ROOT/'examples/api/generate_codes.sh')],None)

    @unittest.skipUnless(os.environ.get('ACCESS_GATE_TEST_PWSH') or shutil.which('pwsh'),'PowerShell 7.4+ optional; set ACCESS_GATE_TEST_PWSH.')
    def test_powershell_client_success_replay_and_error(self):
        executable=os.environ.get('ACCESS_GATE_TEST_PWSH') or shutil.which('pwsh')
        self.exercise([executable,'-NoLogo','-NoProfile','-File',str(ROOT/'examples/api/Generate-Codes.ps1')],['-Operation','-Output'])
