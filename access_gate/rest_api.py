"""Versioned JSON API boundary. Never authenticates a browser session."""
import ipaddress
import secrets
import sqlite3
from urllib.parse import urlsplit
from flask import g,request,jsonify


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
        self.authenticate()
        raise APIError(404,'not_found','The requested API resource was not found.')
