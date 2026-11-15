"""Versioned JSON API boundary. Never authenticates a browser session."""
import ipaddress
import json
import math
import re
import secrets
import sqlite3
from urllib.parse import urlsplit
from flask import g,request,jsonify
from flask.sessions import SecureCookieSessionInterface
from werkzeug.exceptions import RequestEntityTooLarge

GENERATION_READY=True


class APISessionInterface(SecureCookieSessionInterface):
    """The integration API neither reads nor refreshes browser cookies."""
    def open_session(self,app,req):
        if req.path=='/api/v1' or req.path.startswith('/api/v1/'):return self.session_class()
        return super().open_session(app,req)

    def save_session(self,app,session,response):
        if request.path=='/api/v1' or request.path.startswith('/api/v1/'):return
        return super().save_session(app,session,response)


def batch_values(payload):
    from .core import GateError,duration_seconds,positive_int
    defaults=dict(name='',count=10,validity_value=7,validity_unit='days',access_value=15,access_unit='minutes')
    if not isinstance(payload,dict) or set(payload)-set(defaults):
        raise APIError(400,'invalid_request','Send an object containing only supported batch fields.')
    values={**defaults,**payload}
    if not isinstance(values['name'],str) or len(values['name'])>80 or any(ord(c)<32 for c in values['name']):
        raise APIError(400,'invalid_request','Batch name must be at most 80 characters without controls.')
    try:values['name'].encode('utf-8')
    except UnicodeError:raise APIError(400,'invalid_request','Batch name must contain valid Unicode characters.')
    for field in ('count','validity_value','access_value'):
        value=values[field]
        if type(value) not in (int,float) or (isinstance(value,float) and (not math.isfinite(value) or int(value)!=value)):
            raise APIError(400,'invalid_request','Use whole-valued JSON numbers for count and durations.')
        values[field]=int(value)
    try:
        return dict(name=values['name'].strip(),count=positive_int(values['count'],'Count',1000),
                    validity_seconds=duration_seconds(values['validity_value'],values['validity_unit'],'validity'),
                    access_seconds=duration_seconds(values['access_value'],values['access_unit'],'access'))
    except (GateError,TypeError):raise APIError(400,'invalid_request','Invalid batch size, duration or unit.')


def json_body():
    if request.mimetype!='application/json' or request.headers.get('Content-Encoding') or any(k!='charset' or v.lower()!='utf-8' for k,v in request.mimetype_params.items()):
        raise APIError(415,'unsupported_media_type','Send uncompressed UTF-8 application/json.')
    if request.content_length is not None and request.content_length>16384:
        raise APIError(413,'request_too_large','The request body is too large.')
    raw=request.stream.read(16385)
    if len(raw)>16384:raise APIError(413,'request_too_large','The request body is too large.')
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:raise ValueError()
            result[key]=value
        return result
    def invalid(value):raise ValueError()
    try:return json.loads(raw.decode('utf-8'),object_pairs_hook=pairs,parse_constant=invalid)
    except (ValueError,UnicodeError,RecursionError):raise APIError(400,'invalid_json','Send a valid UTF-8 JSON object without duplicate keys.')


class APIError(Exception):
    def __init__(self,status,code,message,details=None,batch_id=None):
        self.status,self.code,self.message=status,code,message
        self.details,self.batch_id=details or [],batch_id


class RestAPI:
    def __init__(self,store,config):
        self.store,self.config=store,config

    def response(self,data,status=200,replayed=None):
        data['request_id']=g.api_request_id
        response=jsonify(data);response.status_code=status
        response.headers.update({'X-Request-ID':g.api_request_id,'Cache-Control':'no-store'})
        if replayed is not None:response.headers['Idempotency-Replayed']='true' if replayed else 'false'
        if status==401:response.headers['WWW-Authenticate']='Bearer realm="Access Gate API"'
        if status==405:response.headers['Allow']=getattr(g,'api_allowed_method','POST')
        if status in (429,503):response.headers['Retry-After']='3600' if status==429 else '60'
        if getattr(g,'api_audit_allowed',False):
            try:self.store.api_audit(getattr(g,'api_credential',{}).get('id'),'replay' if replayed else 'request',data.get('batch_id'),g.api_request_id,g.api_address,status)
            except sqlite3.Error:pass
        return response

    def handle(self):
        g.api_request_id=secrets.token_hex(16)
        try:
            return self.dispatch()
        except APIError as exc:
            error=dict(code=exc.code,message=exc.message,details=exc.details)
            if exc.batch_id:error['batch_id']=exc.batch_id
            return self.response(dict(error=error),exc.status)
        except sqlite3.OperationalError:
            return self.response(dict(error=dict(code='service_unavailable',message='The API is temporarily unavailable.',details=[])),503)
        except RequestEntityTooLarge:
            return self.response(dict(error=dict(code='request_too_large',message='The request body is too large.',details=[])),413)
        except Exception:
            # Do not log exception text or the request: either can contain codes.
            return self.response(dict(error=dict(code='internal_error',message='The API could not complete this request.',details=[])),500)

    def authenticate(self):
        if request.remote_addr not in ('127.0.0.1','::1'):
            raise APIError(403,'forbidden','This source is not permitted.')
        if not request.is_secure and request.headers.get('X-Gate-HTTPS')!='1':raise APIError(400,'insecure_transport','Use the configured HTTPS portal origin.')
        try:
            actual=urlsplit('https://'+request.host);expected=urlsplit(self.config['portal_url'])
            same=actual.hostname==expected.hostname and (actual.port or 443)==(expected.port or 443) and not actual.username and not actual.password and not actual.path
        except ValueError:same=False
        if not same:raise APIError(400,'invalid_host','Use the configured canonical portal origin.')
        policy=self.store.api_policy()
        if self.config.get('remote_gateway'):raise APIError(404,'not_found','The requested API resource was not found.')
        if not policy['enabled']:raise APIError(404,'not_found','The requested API resource was not found.')
        try:address=str(ipaddress.ip_address(request.headers.get('X-Real-IP','')))
        except ValueError:raise APIError(403,'forbidden','This source is not permitted.')
        if not policy['networks'] or not any(ipaddress.ip_address(address) in ipaddress.ip_network(n) for n in policy['networks']):
            raise APIError(403,'forbidden','This source is not permitted.')
        g.api_address=address
        if not self.store.api_request_budget(address):raise APIError(429,'rate_limited','The API request budget was reached.')
        g.api_audit_allowed=True
        auth=request.headers.get('Authorization','')
        parts=auth.split(' ')
        credential=self.store.authenticate_integration(parts[1],address) if len(parts)==2 and parts[0].lower()=='bearer' else None
        if not credential:raise APIError(401,'unauthorized','A valid integration credential is required.')
        if not credential['source_allowed']:raise APIError(403,'forbidden','This source is not permitted.')
        g.api_credential=credential;g.api_address=address
        if not self.store.api_request_budget(address,credential['id']):raise APIError(429,'rate_limited','The integration request budget was reached.')
        return credential

    def dispatch(self):
        credential=self.authenticate()
        if not GENERATION_READY:raise APIError(404,'not_found','The requested API resource was not found.')
        if request.path=='/api/v1/batches':g.api_allowed_method='GET, POST'
        if request.path!='/api/v1/batches' or request.method=='GET':
            return self.lifecycle(credential)
        if request.method!='POST':raise APIError(405,'method_not_allowed','This resource accepts GET or POST.')
        if 'batches:create' not in credential['scopes']:raise APIError(403,'forbidden','This operation is not permitted.')
        if request.query_string:raise APIError(400,'invalid_request','This operation accepts no query parameters.')
        if request.headers.get('Accept') and request.accept_mimetypes['application/json']<=0:raise APIError(406,'not_acceptable','This API produces application/json.')
        key=request.headers.get('Idempotency-Key','')
        if not re.fullmatch(r'[A-Za-z0-9._:-]{16,128}',key):raise APIError(400,'invalid_idempotency_key','Supply a valid Idempotency-Key.')
        values=batch_values(json_body())
        result,replayed=self.store.api_create_batch(credential['id'],g.api_address,key,values,g.api_request_id)
        result['portal_url']=self.config['portal_url'].rstrip('/')+'/'
        return self.response(result,201,replayed)

    def lifecycle(self,credential):
        path=request.path
        batch=code=None
        collection=False
        if path=='/api/v1/batches':kind='batches';collection=True;method='GET'
        else:
            match=re.fullmatch(r'/api/v1/batches/([a-f0-9]{16})(?:/(codes|revoke))?',path)
            code_match=re.fullmatch(r'/api/v1/codes/([a-f0-9]{16})/revoke',path)
            if match:
                batch=match[1];kind=match[2] or 'detail';collection=kind=='codes';method='POST' if kind=='revoke' else 'GET'
            elif code_match:code=code_match[1];kind='revoke';method='POST'
            else:raise APIError(404,'not_found','The requested API resource was not found.')
        g.api_allowed_method=method
        if request.method!=method:raise APIError(405,'method_not_allowed','Use the documented method for this resource.')
        scope='batches:revoke' if kind=='revoke' else 'batches:read'
        if scope not in credential['scopes']:raise APIError(403,'forbidden','This operation is not permitted.')
        allowed={'page_size','cursor'} if collection else set()
        if set(request.args)-allowed or any(len(request.args.getlist(k))!=1 for k in request.args):raise APIError(400,'invalid_request','Invalid collection parameters.')
        size=request.args.get('page_size','25')
        if not re.fullmatch(r'[0-9]{1,3}',size) or not 1<=int(size)<=100:raise APIError(400,'invalid_request','Page size must be between 1 and 100.')
        if kind=='revoke' and json_body()!={}:raise APIError(400,'invalid_request','Revocation accepts only an empty JSON object.')
        if request.headers.get('Accept') and request.accept_mimetypes['application/json']<=0:raise APIError(406,'not_acceptable','This API produces application/json.')
        result=self.store.api_lifecycle(credential['id'],g.api_address,kind,batch,code,int(size),request.args.get('cursor'),g.api_request_id)
        return self.response(result)
