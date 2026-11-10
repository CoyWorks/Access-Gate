import datetime as dt
import functools
import hmac
import ipaddress
import json
import os
import secrets
import time
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from flask import Flask, abort, redirect, render_template, request, session, flash, jsonify, url_for
from werkzeug.security import check_password_hash
from .core import Store, GateError, TZ, STATUSES, domains, matches
from .operations import rule_matches
from .identity import lookup,IdentityUnavailable


def create_app(config=None):
    if config is None:
        config = json.loads(Path(os.environ.get('ACCESS_GATE_CONFIG', '/etc/access-gate/config.json')).read_text())
    app = Flask(__name__, template_folder='../templates', static_folder='../static')
    app.config.update(SECRET_KEY=config['secret'], SESSION_COOKIE_SECURE=True,
                      SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax',
                      PERMANENT_SESSION_LIFETIME=dt.timedelta(hours=2), MAX_CONTENT_LENGTH=16384)
    store = Store(config['database'], config['pepper'])
    app.extensions['store'] = store
    networks = [ipaddress.ip_network(n) for n in config['pilot_clients']]

    def client_ip():
        # Nginx overwrites this header. Gunicorn accepts loopback connections only.
        if request.remote_addr not in ('127.0.0.1', '::1'):
            abort(403)
        try:
            return str(ipaddress.ip_address(request.headers.get('X-Real-IP', '')))
        except ValueError:
            abort(403)

    def eligible(ip):
        return any(ipaddress.ip_address(ip) in net for net in networks)

    def csrf():
        return session.setdefault('csrf', secrets.token_urlsafe(32))

    def safe_target(value):
        try:
            url = urlsplit(value or '')
            host = (url.hostname or '').encode('idna').decode('ascii').lower()
            if url.scheme not in ('http', 'https') or url.username or url.password or url.port not in (None,80,443):
                return None
            rules=store.applied_rules()
            restricted=rule_matches(host,rules) if store.policy_status()['applied']>=0 else matches(host,domains(config['domains']))
            if not restricted:
                return None
            return urlunsplit((url.scheme, url.netloc, '/', '', ''))
        except (ValueError, UnicodeError, OSError):
            return None

    def verified_identity(ip):
        if config.get('require_identity',False) and ipaddress.ip_address(ip) in ipaddress.ip_network('10.40.135.0/24'):
            try: return lookup(ip,config.get('control_socket','/run/access-gate/control.sock'))
            except IdentityUnavailable as exc: raise GateError(str(exc))
        return None

    def current_grant(ip,connection=None):
        if not eligible(ip): return None
        try:
            identity=verified_identity(ip)
            return store.authorize(ip,identity,connection,config.get('enforcement',False))
        except (GateError,OSError,ValueError): return None

    @app.before_request
    def guard():
        if request.path == '/internal/check':
            return
        client_ip()
        if request.method == 'POST':
            if not hmac.compare_digest(session.get('csrf', ''), request.form.get('csrf', '')) or not session.get('csrf'):
                abort(400, 'The form has expired. Please reload the page.')

    @app.after_request
    def headers(response):
        response.headers.update({'Cache-Control':'no-store', 'Referrer-Policy':'no-referrer',
            'X-Content-Type-Options':'nosniff', 'X-Frame-Options':'DENY',
            'Content-Security-Policy':"default-src 'none'; style-src 'self'; script-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"})
        return response

    @app.template_filter('localtime')
    def localtime(stamp):
        return dt.datetime.fromtimestamp(stamp, TZ).strftime('%d-%m-%Y %H:%M:%S') if stamp else '—'

    def admin_only(fn):
        @functools.wraps(fn)
        def wrapped(*args, **kwargs):
            if not session.get('admin'):
                return redirect('/admin/login')
            return fn(*args, **kwargs)
        return wrapped

    @app.route('/', methods=['GET','POST'])
    def index():
        ip = client_ip()
        target = safe_target(request.values.get('return'))
        error = None
        if request.method == 'POST':
            if not eligible(ip):
                error = 'This IP address has not been registered for the pilot.'
            elif not store.attempt('redeem:'+ip, 10):
                error = 'Too many attempts. Please wait 15 minutes.'
            else:
                try:
                    identity=verified_identity(ip)
                    store.redeem(request.form.get('code',''), ip,identity=identity,enforce=config.get('enforcement',False))
                except GateError as exc:
                    error = str(exc)
                else:
                    if target:
                        return redirect(target, code=303)
                    return redirect('/')
        return render_template('index.html', ip=ip, target=target, error=error,
                               grant=current_grant(ip), csrf=csrf(), eligible=eligible(ip))

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
        grant = current_grant(ip)
        return jsonify(active=bool(grant),expires=grant['expires'] if grant else None,server_time=time.time())

    @app.get('/admin')
    @admin_only
    def admin():
        return render_template('admin.html',**list_context(),grants=store.list_grants(),
                               extensions=store.extension_history(),
                               domains=([r['domain'] for r in store.applied_rules() if r['enabled']] if store.policy_status()['applied']>=0 else domains(config['domains'])),pilot=config['pilot_clients'])

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
        flash('Code revoked. Any associated access will be closed.','success')
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
        if not grant or not eligible(grant['ip']) or not current_grant(grant['ip']):
            raise GateError('Only active access for a registered pilot address can be extended.')
        if request.method=='POST':
            event = store.extend(session_id,request.form.get('value',''),request.form.get('unit',''),
                                 request.form.get('request_id',''),actor=f'Administrator ({client_ip()})')
            flash('Access extended. New end time: '+localtime(event['new_expires'])+'.','success')
            return back(None)
        return render_template('extend.html',grant=grant,request_id=secrets.token_hex(16),csrf=csrf())

    @app.get('/admin/domains')
    @admin_only
    def restricted_domains():
        rule_id=request.args.get('edit')
        rules=store.domain_rules(request.args.get('q',''))
        editing=next((r for r in store.domain_rules() if r['id']==rule_id),None)
        state=store.policy_status()
        return render_template('domains.html',rules=rules,editing=editing,state=state,
                               healthy=state['healthy'] and 0<=time.monotonic()-state['heartbeat']<=3,
                               search=request.args.get('q',''),applied_rules=store.applied_rules(),csrf=csrf())

    @app.post('/admin/domains/save')
    @admin_only
    def save_domain():
        store.save_domain(request.form.get('domain',''),request.form.get('subdomains')=='on',
                          request.form.get('description',''),request.form.get('enabled')=='on',request.form.get('id') or None)
        flash('Rule saved. Waiting for proxy validation and apply.','success')
        return redirect(url_for('restricted_domains'))

    @app.post('/admin/domains/delete')
    @admin_only
    def delete_domain():
        store.delete_domain(request.form.get('id',''))
        flash('Rule deleted. Waiting for proxy validation and apply.','success')
        return redirect(url_for('restricted_domains'))

    @app.post('/admin/domains/apply')
    @admin_only
    def retry_policy():
        with store.connect() as db: db.execute("UPDATE policy_state SET desired=desired+1,error='' WHERE id=1")
        flash('Policy apply requested. Refresh to see the result.','success')
        return redirect(url_for('restricted_domains'))

    @app.get('/admin/devices')
    @admin_only
    def devices():
        return render_template('devices.html',devices=store.devices(),csrf=csrf(),now=time.time(),
                               require_identity=config.get('require_identity',False))

    @app.post('/admin/devices/save')
    @admin_only
    def save_device():
        store.save_device(request.form.get('username',''),request.form.get('label',''),
                          request.form.get('enabled')=='on',request.form.get('id') or None)
        flash('VPN user registration saved. Disabled users lose restricted access.','success')
        return redirect(url_for('devices'))

    @app.get('/internal/check')
    def check():
        if request.remote_addr not in ('127.0.0.1','::1') or not hmac.compare_digest(request.headers.get('X-Gate-Key',''), config['acl_token']):
            abort(403)
        try:
            ip = str(ipaddress.ip_address(request.args.get('ip','')))
        except ValueError:
            return 'ERR\n'
        connection=None
        if config.get('enforcement',False):
            connection={name:request.args.get(name,'') for name in ('client_port','local_ip','local_port')}
        return 'OK\n' if current_grant(ip,connection) else 'ERR\n'

    return app
