import datetime as dt
import functools
import hmac
import ipaddress
import json
import os
import secrets
import time
from pathlib import Path
from urllib.parse import urlencode,urlsplit

from flask import Flask,abort,redirect,render_template,request,session,flash,jsonify,url_for,g
from werkzeug.security import check_password_hash
from .core import Store,GateError,TZ,STATUSES
from .browser import TOKEN

BROWSER_COOKIE='__Host-accessgate-browser'
SITE_COOKIE='__Host-accessgate-site'
CHALLENGE_COOKIE='__Host-accessgate-challenge'


def create_app(config=None):
    if config is None:
        config=json.loads(Path(os.environ.get('ACCESS_GATE_CONFIG','/etc/access-gate/config.json')).read_text())
    app=Flask(__name__,template_folder='../templates',static_folder='../static')
    app.config.update(SECRET_KEY=config['secret'],SESSION_COOKIE_SECURE=True,
                      SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Lax',
                      PERMANENT_SESSION_LIFETIME=dt.timedelta(hours=2),MAX_CONTENT_LENGTH=16384)
    store=Store(config['database'],config['pepper']); app.extensions['store']=store
    networks=[ipaddress.ip_network(n) for n in config.get('client_networks',['10.40.0.0/16','127.0.0.1/32','::1/128'])]
    portal_url=config.get('portal_url','https://10.40.22.5').rstrip('/')

    def client_ip():
        if request.remote_addr not in ('127.0.0.1','::1'): abort(403)
        try: ip=ipaddress.ip_address(request.headers.get('X-Real-IP',''))
        except ValueError: abort(403)
        if not any(ip in net for net in networks): abort(403)
        return str(ip)

    def browser():
        if not hasattr(g,'browser_token'):
            token=request.cookies.get(BROWSER_COOKIE,'')
            g.new_browser=not bool(TOKEN.fullmatch(token))
            g.browser_token=secrets.token_hex(32) if g.new_browser else token
        return g.browser_token

    def current_grant(): return store.browser_grant(browser())

    def csrf(): return session.setdefault('csrf',secrets.token_urlsafe(32))

    @app.before_request
    def guard():
        if request.path.startswith('/internal/'):
            expected=config.get('acl_token','')
            if request.remote_addr not in ('127.0.0.1','::1') or not expected or not hmac.compare_digest(request.headers.get('X-Gate-Key','').encode(),expected.encode()): abort(403)
            return
        client_ip()
        if urlsplit('https://'+request.host).hostname!=urlsplit(portal_url).hostname:
            if request.method in ('GET','HEAD'):
                return redirect(portal_url+request.full_path.rstrip('?'),code=308)
            abort(400,'Open the canonical portal address and reload the form.')
        if request.method=='POST' and (not session.get('csrf') or not hmac.compare_digest(session.get('csrf','').encode(),request.form.get('csrf','').encode())):
            abort(400,'The form has expired. Please reload the page.')

    @app.after_request
    def headers(response):
        response.headers.update({'Cache-Control':'no-store','Referrer-Policy':'no-referrer',
            'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY',
            'Content-Security-Policy':"default-src 'none'; style-src 'self'; script-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"})
        if getattr(g,'new_browser',False):
            response.set_cookie(BROWSER_COOKIE,g.browser_token,max_age=365*86400,secure=True,httponly=True,samesite='Lax',path='/')
        return response

    @app.template_filter('localtime')
    def localtime(stamp): return dt.datetime.fromtimestamp(stamp,TZ).strftime('%d-%m-%Y %H:%M:%S') if stamp else '—'

    def admin_only(fn):
        @functools.wraps(fn)
        def wrapped(*args,**kwargs):
            if not session.get('admin'): return redirect('/admin/login')
            return fn(*args,**kwargs)
        return wrapped

    @app.route('/',methods=['GET','POST'])
    def index():
        ip=client_ip(); token=browser(); entry_id=request.values.get('entry',''); error=None
        entry=store.entry(entry_id) if entry_id else None
        if request.method=='POST':
            if not store.attempt('redeem:'+ip,10): error='Too many attempts. Please wait 15 minutes.'
            else:
                try: store.redeem(request.form.get('code',''),ip,browser_token=token)
                except GateError as exc: error=str(exc)
                else:
                    if entry:
                        target,ticket=store.issue_handoff(entry_id,token)
                        return redirect(target+'/__access_gate/complete?'+urlencode({'ticket':ticket}),code=303)
                    return redirect('/')
        grant=current_grant()
        if entry and grant:
            target,ticket=store.issue_handoff(entry_id,token)
            return redirect(target+'/__access_gate/complete?'+urlencode({'ticket':ticket}),code=303)
        return render_template('index.html',error=error,grant=grant,csrf=csrf(),entry_id=entry_id)

    @app.route('/admin/login', methods=['GET','POST'])
    def login():
        error = None
        if request.method == 'POST':
            ip = client_ip()
            if not store.attempt('login:'+ip, 5):
                error = 'Too many attempts. Please wait 15 minutes.'
            elif check_password_hash(config['admin_hash'], request.form.get('password','')):
                session.clear()
                session['admin'] = True
                session.permanent = True
                return redirect('/admin')
            else:
                error = 'Incorrect password.'
        return render_template('login.html', csrf=csrf(), error=error)

    @app.post('/admin/logout')
    @admin_only
    def logout():
        session.clear()
        return redirect('/admin/login')

    @app.template_filter('duration')
    def duration(value):
        seconds = int(value or 0)
        amount,unit = (seconds//86400,'day') if seconds and seconds % 86400 == 0 else ((seconds//3600,'hour') if seconds and seconds % 3600 == 0 else (seconds//60,'minute'))
        return f'{amount} {unit}' + ('' if amount==1 else 's')

    @app.errorhandler(GateError)
    def gate_error(error):
        return render_template('error.html', error=str(error)), 400

    def page_number():
        return request.args.get('page', '1')

    def list_context(batch_id=None):
        return dict(codes=store.list_codes(batch_id,request.args.get('status',''),page_number()),
                    code_status=request.args.get('status',''),statuses=STATUSES,
                    clear_count=store.revoked_visible(batch_id),batch_id=batch_id,
                    csrf=csrf(),now=time.time())

    def back(batch_id):
        return redirect(url_for('batch_detail',batch_id=batch_id) if batch_id else url_for('admin'))

    @app.get('/status')
    def access_status():
        ip = client_ip()
        grant = current_grant()
        return jsonify(active=bool(grant),expires=grant['expires'] if grant else None,server_time=time.time())

    @app.get('/admin')
    @admin_only
    def admin():
        return render_template('admin.html',**list_context(),grants=[r for r in store.list_grants() if not r['revoked'] and r['expires']>time.time()],
                               extensions=store.extension_history())

    @app.get('/admin/batches')
    @admin_only
    def batches():
        return render_template('batches.html',batches=store.list_batches(page=page_number()),
                               csrf=csrf(),now=time.time())

    @app.get('/admin/batches/new')
    @admin_only
    def new_batch():
        return render_template('new_batch.html',csrf=csrf(),values={},error=None)

    @app.post('/admin/batch')
    @admin_only
    def batch():
        try:
            if 'week' in request.form and 'validity_value' not in request.form:
                raise GateError('This form is from an older version. Reload Create batch before generating codes.')
            batch_id,codes = store.create_batch(name=request.form.get('name',''),
                count=request.form.get('count','10'),validity_value=request.form.get('validity_value','7'),
                validity_unit=request.form.get('validity_unit','days'),access_value=request.form.get('access_value','15'),
                access_unit=request.form.get('access_unit','minutes'))
        except GateError as exc:
            return render_template('new_batch.html',csrf=csrf(),values=request.form,error=str(exc)),400
        return render_template('batch.html',codes=codes,batch=store.batch_detail(batch_id))

    @app.get('/admin/batches/<batch_id>')
    @admin_only
    def batch_detail(batch_id):
        return render_template('batch_detail.html',batch=store.batch_detail(batch_id),
                               extensions=store.extension_history(batch_id),**list_context(batch_id))

    @app.route('/admin/batches/<batch_id>/revoke',methods=['GET','POST'])
    @admin_only
    def revoke_batch(batch_id):
        batch = store.batch_detail(batch_id)
        if request.method=='POST':
            count,active = store.revoke_batch(batch_id)
            flash(f'Batch revoked: {count} codes and {active} active sessions affected.','success')
            return back(batch_id)
        return render_template('confirm_revoke.html',batch=batch,csrf=csrf())

    @app.post('/admin/revoke')
    @admin_only
    def revoke():
        store.revoke(request.form.get('id',''))
        flash('Code revoked. Associated access is no longer authorized.','success')
        return back(request.form.get('batch_id',''))

    @app.post('/admin/codes/clear-revoked')
    @admin_only
    def clear_revoked():
        batch_id = request.form.get('batch_id') or None
        if batch_id: store.batch_detail(batch_id)
        count = store.clear_revoked(batch_id)
        flash(f'Cleared {count} revoked codes from this list. Revocation records remain protected.','success')
        return back(batch_id)

    @app.route('/admin/access/<session_id>/extend',methods=['GET','POST'])
    @admin_only
    def extend_access(session_id):
        grant = next((g for g in store.list_grants() if g['session_id']==session_id),None)
        if not grant or grant['revoked'] or grant['expires']<=time.time():
            raise GateError('Only active browser access can be extended.')
        if request.method=='POST':
            event = store.extend(session_id,request.form.get('value',''),request.form.get('unit',''),
                                 request.form.get('request_id',''),actor=f'Administrator ({client_ip()})')
            flash('Access extended. New end time: '+localtime(event['new_expires'])+'.','success')
            return back(None)
        return render_template('extend.html',grant=grant,request_id=secrets.token_hex(16),csrf=csrf())

    @app.post('/internal/entry')
    def create_entry():
        data=request.get_json()
        if not isinstance(data,dict): abort(400)
        nonce=secrets.token_hex(32)
        entry_id=store.new_entry(data.get('origin'),nonce)
        return jsonify(login_url=portal_url+'/?'+urlencode({'entry':entry_id}),nonce=nonce,expires_in=300)

    @app.post('/internal/handoff')
    def accept_handoff():
        data=request.get_json()
        if not isinstance(data,dict): abort(400)
        result=store.accept_handoff(data.get('ticket'),data.get('nonce'),data.get('origin'))
        return jsonify(result)

    @app.route('/internal/check',methods=['GET','POST'])
    def check():
        # An old ip= parameter can never authorize a browser or a proxied request.
        data=request.get_json(silent=True) if request.method=='POST' else {'token':request.cookies.get(SITE_COOKIE),'origin':request.headers.get('X-Gate-Origin')}
        if not isinstance(data,dict): return jsonify(active=False),401
        try: grant=store.gateway_grant(data.get('token'),data.get('origin'))
        except GateError: grant=None
        if not grant: return jsonify(active=False),401
        response=jsonify(active=True,expires=grant['expires'],session_id=grant['session_id'])
        response.headers['X-Gate-Expires']=str(grant['expires'])
        reserved={BROWSER_COOKIE,SITE_COOKIE,CHALLENGE_COOKIE}
        response.headers['X-Gate-Upstream-Cookie']='; '.join(part.strip() for part in request.headers.get('Cookie','').split(';') if part.strip() and part.strip().split('=',1)[0] not in reserved)
        return response

    @app.get('/internal/start')
    def start_gateway_browser():
        target=request.headers.get('X-Gate-Origin')
        nonce=secrets.token_hex(32); entry_id=store.new_entry(target,nonce)
        response=redirect(portal_url+'/?'+urlencode({'entry':entry_id}),code=302)
        response.set_cookie(CHALLENGE_COOKIE,nonce,max_age=300,secure=True,httponly=True,samesite='Lax',path='/')
        return response

    @app.get('/internal/finish')
    def finish_gateway_browser():
        target=request.headers.get('X-Gate-Origin')
        result=store.accept_handoff(request.args.get('ticket'),request.cookies.get(CHALLENGE_COOKIE),target)
        from .browser import origin
        response=redirect(origin(target)+'/',code=303)
        response.set_cookie(SITE_COOKIE,result['token'],max_age=365*86400,secure=True,httponly=True,samesite='Lax',path='/')
        response.delete_cookie(CHALLENGE_COOKIE,secure=True,httponly=True,samesite='Lax',path='/')
        return response

    return app
