"""Versioned JSON API boundary. Never authenticates a browser session."""
import ipaddress
import json
import math
import re
import secrets
import sqlite3
from urllib.parse import urlsplit
from flask import g,request,jsonify
from werkzeug.exceptions import RequestEntityTooLarge

GENERATION_READY=False  # Enabled only once replay and deployment controls ship (#48/#49).


def batch_values(payload):
    from .core import GateError,duration_seconds,positive_int
    defaults=dict(name='',count=10,validity_value=7,validity_unit='days',access_value=15,access_unit='minutes')
    if not isinstance(payload,dict) or set(payload)-set(defaults):
        raise APIError(400,'invalid_request','Send an object containing only supported batch fields.')
    values={**defaults,**payload}
    if not isinstance(values['name'],str) or len(values['name'])>80 or any(ord(c)<32 for c in values['name']):
        raise APIError(400,'invalid_request','Batch name must be at most 80 characters without controls.')
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
        if status==405:response.headers['Allow']='POST'
        if status in (429,503):response.headers['Retry-After']='60'
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
        policy=self.store.api_policy()
        if not policy['enabled']:raise APIError(404,'not_found','The requested API resource was not found.')
        try:address=str(ipaddress.ip_address(request.headers.get('X-Real-IP','')))
        except ValueError:raise APIError(403,'forbidden','This source is not permitted.')
        if not policy['networks'] or not any(ipaddress.ip_address(address) in ipaddress.ip_network(n) for n in policy['networks']):
            raise APIError(403,'forbidden','This source is not permitted.')
        auth=request.headers.get('Authorization','')
        parts=auth.split(' ')
        credential=self.store.authenticate_integration(parts[1],address) if len(parts)==2 and parts[0].lower()=='bearer' else None
        if not credential:raise APIError(401,'unauthorized','A valid integration credential is required.')
        if not credential['source_allowed']:raise APIError(403,'forbidden','This source is not permitted.')
        g.api_credential=credential;g.api_address=address
        return credential

    def dispatch(self):
        credential=self.authenticate()
        if not GENERATION_READY:raise APIError(404,'not_found','The requested API resource was not found.')
        if request.path!='/api/v1/batches':raise APIError(404,'not_found','The requested API resource was not found.')
        if request.method!='POST':raise APIError(405,'method_not_allowed','This resource accepts POST.')
        if 'batches:create' not in credential['scopes']:raise APIError(403,'forbidden','This operation is not permitted.')
        if request.query_string:raise APIError(400,'invalid_request','This operation accepts no query parameters.')
        if request.headers.get('Accept') and not request.accept_mimetypes.accept_json:raise APIError(406,'not_acceptable','This API produces application/json.')
        key=request.headers.get('Idempotency-Key','')
        if not re.fullmatch(r'[A-Za-z0-9._:-]{16,128}',key):raise APIError(400,'invalid_idempotency_key','Supply a valid Idempotency-Key.')
        values=batch_values(json_body())
        result,replayed=self.store.api_create_batch(credential['id'],g.api_address,key,values)
        result['portal_url']=self.config['portal_url'].rstrip('/')+'/'
        return self.response(result,201,replayed)
