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

from flask import Flask, abort, redirect, render_template, request, session
from werkzeug.security import check_password_hash
from .core import Store, GateError, TZ, domains, matches


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
            if not matches(host, domains(config['domains'])):
                return None
            return urlunsplit((url.scheme, url.netloc, '/', '', ''))
        except (ValueError, UnicodeError, OSError):
            return None

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
                    store.redeem(request.form.get('code',''), ip)
                except GateError as exc:
                    error = str(exc)
                else:
                    if target:
                        return redirect(target, code=303)
                    return redirect('/')
        return render_template('index.html', ip=ip, target=target, error=error,
                               grant=store.grant(ip), csrf=csrf(), eligible=eligible(ip))

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

    @app.get('/admin')
    @admin_only
    def admin():
        codes, grants = store.dashboard()
        today = dt.datetime.now(TZ).date()
        monday = today - dt.timedelta(days=today.weekday())
        return render_template('admin.html', csrf=csrf(), codes=codes, grants=grants,
                               monday=monday.isoformat(), now=time.time(),
                               domains=domains(config['domains']), pilot=config['pilot_clients'])

    @app.post('/admin/batch')
    @admin_only
    def batch():
        try:
            count = int(request.form.get('count','10'))
            _, codes = store.new_batch(request.form.get('week',''), count, 15)
        except (ValueError, GateError):
            abort(400, 'Choose a valid Monday and 1–100 codes.')
        return render_template('batch.html', codes=codes, week=request.form['week'])

    @app.post('/admin/revoke')
    @admin_only
    def revoke():
        store.revoke(request.form.get('id',''))
        return redirect('/admin')

    @app.get('/internal/check')
    def check():
        if request.remote_addr not in ('127.0.0.1','::1') or not hmac.compare_digest(request.headers.get('X-Gate-Key',''), config['acl_token']):
            abort(403)
        try:
            ip = str(ipaddress.ip_address(request.args.get('ip','')))
        except ValueError:
            return 'ERR\n'
        return 'OK\n' if eligible(ip) and store.grant(ip) else 'ERR\n'

    return app
