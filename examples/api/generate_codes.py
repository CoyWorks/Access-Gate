#!/usr/bin/env python3
"""Generate once using a durable retry plan. Secrets never go to stdout."""
import argparse
import json
import os
from pathlib import Path
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


def private_read(path):
    flags=os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)
    with os.fdopen(os.open(path,flags),encoding='utf-8') as handle:
        if os.name=='posix' and os.fstat(handle.fileno()).st_mode & 0o077:
            raise ValueError('Secret and operation files must have owner-only permissions.')
        return handle.read(262145)


def private_write(path,value):
    descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(descriptor,'w',encoding='utf-8') as handle:
        json.dump(value,handle,indent=2,allow_nan=False);handle.write('\n')
        handle.flush();os.fsync(handle.fileno())


def prepare(operation,request_file):
    url=os.environ.get('ACCESS_GATE_API_URL','').rstrip('/')
    parsed=urllib.parse.urlsplit(url)
    if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
        raise ValueError('Set ACCESS_GATE_API_URL to the canonical HTTPS origin, without a path.')
    token=private_read(os.environ['ACCESS_GATE_API_TOKEN_FILE']).strip()
    match=re.fullmatch(r'ag_([a-f0-9]{16})_[A-Za-z0-9_-]{43}',token)
    if not match:raise ValueError('The credential file must contain one integration credential.')
    body=json.loads(Path(request_file).read_text(encoding='utf-8'))
    expected=dict(endpoint=url+'/api/v1/batches',credential_id=match[1],body=body)
    operation=Path(operation)
    if operation.exists():
        plan=json.loads(private_read(operation))
        if any(plan.get(k)!=v for k,v in expected.items()):
            raise ValueError('The operation belongs to another URL, credential or request. Reconcile it before creating a new operation.')
    else:
        plan=dict(**expected,idempotency_key=str(uuid.uuid4()),created_at_epoch=time.time())
        private_write(operation,plan)
    age=time.time()-plan['created_at_epoch']
    if not 0<=age<86400:
        raise ValueError('The local recovery window ended. Reconcile the original batch before replacing it.')
    return token,plan


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--operation',required=True,help='Private persistent plan; keep it for every retry.')
    parser.add_argument('--output',required=True,help='New private response file. Existing files are never overwritten.')
    parser.add_argument('--request',default=str(Path(__file__).with_name('batch.json')))
    parser.add_argument('--prepare-only',action='store_true',help='Prepare a durable plan without sending an HTTP request.')
    args=parser.parse_args(argv)
    try:
        if Path(args.output).exists():
            print('Output already exists; no request sent.');return 0
        token,plan=prepare(args.operation,args.request)
        if args.prepare_only:return 0
        context=ssl.create_default_context(cafile=os.environ.get('ACCESS_GATE_API_CA') or None)
        opener=urllib.request.build_opener(urllib.request.HTTPSHandler(context=context),NoRedirect())
        request=urllib.request.Request(plan['endpoint'],method='POST',data=json.dumps(plan['body']).encode(),
            headers={'Authorization':'Bearer '+token,'Idempotency-Key':plan['idempotency_key'],
                     'Content-Type':'application/json','Accept':'application/json'})
        try:
            with opener.open(request,timeout=30) as response:
                raw=response.read(262145)
                if response.status!=201 or len(raw)>262144:raise ValueError('Unexpected response; reconcile the saved operation before replacing it.')
                result=json.loads(raw)
        except urllib.error.HTTPError as error:
            # Never print response bodies: a proxy can return arbitrary content.
            print('API HTTP '+str(error.code)+'. Keep the operation file for retries; inspect the admin audit for details.',file=sys.stderr)
            return 75 if error.code>=500 or error.code==429 else 2
        private_write(args.output,result)
        print('Batch saved privately. Keep its operation file with the response.')
        return 0
    except (urllib.error.URLError,TimeoutError,OSError):
        print('Result may be uncertain. Keep the same operation file and retry; do not generate a new key.',file=sys.stderr)
        return 75
    except (ValueError,KeyError):
        print('Check the HTTPS origin, private credential/operation files and request. Reconcile an existing operation before changing it.',file=sys.stderr)
        return 2


if __name__=='__main__':raise SystemExit(main())
