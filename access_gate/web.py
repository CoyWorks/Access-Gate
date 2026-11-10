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

from flask import Flask,abort,redirect,render_template,request,session,flash,jsonify,url_for,g,send_file
from werkzeug.security import check_password_hash,generate_password_hash
from .core import Store,GateError,TZ,STATUSES
from .browser import TOKEN
from .dns_export import TARGET_IP
from .blocklist import download_blocklist
from .administration import management_networks
from .health import Health
from .exclusions import exclusion_networks,ADMIN_IDLE_SECONDS
from .operations import EVENTS

BROWSER_COOKIE='__Host-accessgate-browser'
SITE_COOKIE='__Host-accessgate-site'
CHALLENGE_COOKIE='__Host-accessgate-challenge'
ADMIN_COOKIE='__Host-accessgate-admin'
PUBLIC_CA=Path('/var/lib/access-gate/public/ca.crt')
DNS_FEED_PATHS = frozenset(('/domains.txt', '/pihole.conf'))


def create_app(config=None):
    if config is None:
        config=json.loads(Path(os.environ.get('ACCESS_GATE_CONFIG','/etc/access-gate/config.json')).read_text())
    app=Flask(__name__,template_folder='../templates',static_folder='../static')
    app.config.update(SECRET_KEY=config['secret'],SESSION_COOKIE_SECURE=True,
                      SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Lax',
                      PERMANENT_SESSION_LIFETIME=dt.timedelta(days=7),MAX_CONTENT_LENGTH=16384)
    store=Store(config['database'],config['pepper']); app.extensions['store']=store
    health=Health(config,store); app.extensions['health']=health
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

    def current_exclusion():
        if store.ip_excluded(client_ip(),config):return dict(kind='ip',expires=None)
        if getattr(g,'admin_login',None):return dict(kind='admin',expires=g.admin_login['expires'])
        return None

    def website_handoff(entry_id,token,entry):
        if store.ip_excluded(client_ip(),config):return redirect(entry['origin']+'/',code=303)
        if getattr(g,'admin_login',None):target,ticket=store.issue_admin_handoff(entry_id,g.admin_login['id'],config)
        else:target,ticket=store.issue_handoff(entry_id,token)
        return redirect(target+'/__access_gate/complete?'+urlencode({'ticket':ticket}),code=303)

    def end_login():
        store.end_admin_login(request.cookies.get(ADMIN_COOKIE,''),browser())
        if getattr(g,'admin_login',None):store.audit('admin.logout')
        session.clear();g.admin_login=None;g.new_admin_cookie=None;g.clear_admin_cookie=True


    @app.before_request
    def guard():
        if request.path.startswith('/internal/'):
            expected=config.get('acl_token','')
            if request.remote_addr not in ('127.0.0.1','::1') or not expected or not hmac.compare_digest(request.headers.get('X-Gate-Key','').encode(),expected.encode()): abort(403)
            return
        address=client_ip()
        g.admin_security=store.admin_security(config)
        # Polling/static/feed requests validate but never renew an idle login.
        activity=request.path not in DNS_FEED_PATHS and request.path not in ('/status','/request-access/status') and not request.path.startswith(('/static/','/admin/api/'))
        g.admin_login=None
        admin_cookie=request.cookies.get(ADMIN_COOKIE,'')
        if admin_cookie:
            g.admin_login=store.admin_login(admin_cookie,browser(),config,touch=activity)
            if not g.admin_login:g.clear_admin_cookie=True
        if g.admin_login:
            if activity:g.new_admin_cookie=admin_cookie
            session['admin']=True; session['auth_version']=g.admin_security['version']; session.permanent=True
        else:
            for key in ('admin','auth_version'):session.pop(key,None)
        if request.path=='/admin' or request.path.startswith('/admin/'):
            if not any(ipaddress.ip_address(address) in ipaddress.ip_network(n) for n in g.admin_security['networks']):
                abort(403,'Administration is not available from this network. The code portal is still available.')
        if request.path not in DNS_FEED_PATHS and urlsplit('https://'+request.host).hostname!=urlsplit(portal_url).hostname:
            if request.method in ('GET','HEAD'):
                return redirect(portal_url+request.full_path.rstrip('?'),code=308)
            abort(400,'Open the canonical portal address and reload the form.')
        if request.method=='POST' and (not session.get('csrf') or not hmac.compare_digest(session.get('csrf','').encode(),request.form.get('csrf','').encode())):
            abort(400,'The form has expired. Please reload the page.')

    @app.after_request
    def headers(response):
        response.headers.update({'Cache-Control':'no-store','Referrer-Policy':'no-referrer',
            'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY',
            'Content-Security-Policy':"default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"})
        if getattr(g,'new_browser',False):
            response.set_cookie(BROWSER_COOKIE,g.browser_token,max_age=365*86400,secure=True,httponly=True,samesite='Lax',path='/')
        if getattr(g,'new_admin_cookie',None):
            # The opaque cookie is only a lookup handle; the DB enforces seven idle days.
            response.set_cookie(ADMIN_COOKIE,g.new_admin_cookie,max_age=365*86400,secure=True,httponly=True,samesite='Lax',path='/')
        elif getattr(g,'clear_admin_cookie',False):
            response.delete_cookie(ADMIN_COOKIE,secure=True,httponly=True,samesite='Lax',path='/')
        return response

    @app.template_filter('localtime')
    def localtime(stamp): return dt.datetime.fromtimestamp(stamp,TZ).strftime('%d-%m-%Y %H:%M:%S') if stamp else '—'

    def admin_only(fn):
        @functools.wraps(fn)
        def wrapped(*args,**kwargs):
            if not session.get('admin'): return redirect('/admin/login')
            return fn(*args,**kwargs)
        return wrapped

    @app.get('/ca.crt')
    def ca_certificate():
        return send_file(PUBLIC_CA,mimetype='application/x-x509-ca-cert',as_attachment=True,download_name='ca.crt',max_age=0)

    @app.get('/domains.txt')
    def hosts_feed():
        return app.response_class(store.dns_hosts_feed(), mimetype='text/plain')

    @app.get('/pihole.conf')
    def dnsmasq_feed():
        return app.response_class(store.export_dns_domains('dnsmasq'), mimetype='text/plain')

    @app.route('/',methods=['GET','POST'])
    def index():
        ip=client_ip(); token=browser(); entry_id=request.values.get('entry',''); error=None
        entry=store.entry(entry_id) if entry_id else None
        if request.method=='POST' and current_exclusion():
            return redirect(url_for('continue_access',entry=entry_id) if entry_id else '/',code=303)
        if request.method=='POST':
            if not store.attempt('redeem:'+ip,10): error='Too many attempts. Please wait 15 minutes.'
            else:
                try: store.redeem(request.form.get('code',''),ip,browser_token=token)
                except GateError as exc:
                    store.audit('code.failed',actor='Visitor',details=dict(reason='invalid_or_unavailable'))
                    error=str(exc)
                else:
                    if entry:
                        # End the form navigation on a portal document before leaving
                        # the origin: Chrome applies form-action to redirect chains.
                        return redirect(url_for('continue_access',entry=entry_id),code=303)
                    return redirect('/')
        grant=current_grant();exclusion=current_exclusion()
        if entry and (grant or exclusion):return website_handoff(entry_id,token,entry)
        return render_template('index.html',error=error,grant=grant,exclusion=exclusion,csrf=csrf(),entry_id=entry_id,history_policy=store.activity_settings())

    @app.get('/continue')
    def continue_access():
        entry_id=request.args.get('entry','')
        if not entry_id: abort(400,'A website entry is required.')
        store.entry(entry_id)
        resume_url=url_for('index',entry=entry_id)
        if not (current_grant() or current_exclusion()): return redirect(resume_url,code=303)
        return render_template('continue.html',resume_url=resume_url)

    @app.route('/admin/login', methods=['GET','POST'])
    def login():
        error = None
        portal=request.values.get('portal','')=='1'
        entry_id=request.values.get('entry','')
        if entry_id:store.entry(entry_id)
        if request.method == 'POST':
            ip = client_ip()
            if not store.attempt('login:'+ip, 5):
                error = 'Too many attempts. Please wait 15 minutes.'
            elif check_password_hash(g.admin_security['password_hash'], request.form.get('password','')):
                token,login_state=store.new_admin_login(browser(),config,expected_version=g.admin_security['version'])
                g.new_admin_cookie=token;g.clear_admin_cookie=False;g.admin_login=login_state
                session.clear()
                session['admin'] = True
                session['auth_version'] = g.admin_security['version']
                session.permanent = True
                store.audit('admin.login')
                if portal:return redirect(url_for('continue_access',entry=entry_id) if entry_id else '/',code=303)
                return redirect('/admin')
            else:
                store.audit('admin.login_failed',actor='Visitor',details=dict(reason='incorrect_password'))
                error = 'Incorrect password.'
        return render_template('login.html', csrf=csrf(), error=error,portal=portal,entry_id=entry_id)

    @app.post('/admin/logout')
    @admin_only
    def logout():
        end_login()
        return redirect('/admin/login')

    @app.post('/logout')
    def portal_logout():
        end_login()
        return redirect('/')

    @app.context_processor
    def notifications_context():
        def page_link(page):
            params=request.args.to_dict();params['page']=page
            return request.path+'?'+urlencode(params)
        return dict(page_link=page_link,request_notifications=store.notifications()['unread'] if getattr(g,'admin_login',None) else 0)

    @app.route('/request-access',methods=['GET','POST'])
    def request_access():
        entry_id=request.values.get('entry','')
        entry=store.entry(entry_id) if entry_id else None
        requested_domain=entry['origin'][8:] if entry else ''
        if request.method=='POST' and not entry and request.form.get('previous_request'):
            requested_domain=store.own_request_status(request.form['previous_request'],browser())['domain']
        if request.method=='POST':
            rid,created=store.submit_request(browser(),client_ip(),requested_domain,request.form.get('label',''),request.form.get('reason',''))
            flash('Request sent. An administrator has been notified in the portal.' if created else 'You already have a pending request for this website.','success')
            return redirect(url_for('request_access',request=rid),code=303)
        selected=store.own_request_status(request.args['request'],browser()) if request.args.get('request') else None
        return render_template('requests.html',result=store.requests_page(browser(),page=request.args.get('page','1')),visitor=True,requested_domain=requested_domain,entry_id=entry_id,csrf=csrf(),state='all',selected=selected)

    @app.get('/request-access/status')
    def request_status():
        item=store.own_request_status(request.args.get('request',''),browser())
        item['continue_url']=url_for('continue_request',request_id=item['id']) if item['active'] else None
        return jsonify(item)

    @app.get('/request-access/<request_id>/continue')
    def continue_request(request_id):
        item=store.own_request_status(request_id,browser())
        if not item['active']:return redirect(url_for('request_access',request=request_id))
        return redirect('https://'+item['domain']+'/' if item['domain'] else '/',code=303)

    @app.get('/admin/requests')
    @admin_only
    def access_requests():
        state=request.args.get('state','pending')
        return render_template('requests.html',result=store.requests_page(state=state,page=page_number()),visitor=False,state=state)

    @app.route('/admin/requests/<request_id>',methods=['GET','POST'])
    @admin_only
    def access_request_detail(request_id):
        if request.method=='POST':
            action=request.form.get('action','')
            if action in ('approve','deny'):
                result=store.decide_request(request_id,action,request.form.get('value','15'),request.form.get('unit','minutes'))
                flash(('Access approved until '+localtime(result['expires'])+'.' if result['changed'] else 'This request was already approved; no additional time was added.') if result['state']=='approved' else 'Request denied.','success')
            elif action=='read':
                store.change_request(request_id,action)
                flash('Request marked read.','success')
            else:raise GateError('Reload this request to choose Approve or Deny; the old Resolve/Dismiss form is no longer supported.')
            return redirect(url_for('access_request_detail',request_id=request_id))
        return render_template('request_detail.html',item=store.request_detail(request_id),csrf=csrf())

    @app.get('/admin/api/notifications')
    @admin_only
    def notifications_data():
        return jsonify(store.notifications())

    def history_options():
        values={}
        for field in ('since','until'):
            text=request.args.get(field,'')
            if text:
                try:
                    date=dt.date.fromisoformat(text)
                    if field=='until':date+=dt.timedelta(days=1)
                except (ValueError,OverflowError):raise GateError('Use valid dates for the activity range.')
                values[field]=dt.datetime.combine(date,dt.time(),TZ).timestamp()
        if values.get('since',0)>=values.get('until',float('inf')):raise GateError('The activity end date must not be before the start date.')
        values.update(event=request.args.get('event',''),actor=request.args.get('actor',''),domain=request.args.get('domain',''),page=page_number())
        return values

    @app.get('/admin/activity')
    @admin_only
    def activity():
        return render_template('activity.html',history=store.history(**history_options(),batch_id=request.args.get('batch') or None),events=sorted(EVENTS),csrf=csrf(),policy=store.activity_settings(),batches=store.list_batches(per_page=100,view='all')['items'],now=time.time())

    @app.post('/admin/activity/settings')
    @admin_only
    def activity_settings():
        if not store.attempt('admin-settings:'+client_ip(),5):raise GateError('Too many attempts. Please wait 15 minutes.')
        if not check_password_hash(g.admin_security['password_hash'],request.form.get('current_password','')):raise GateError('Current password is incorrect.')
        store.save_activity_settings(request.form.get('mode',''),request.form.get('retention_days',''),request.form.get('version',''))
        flash('Activity settings saved. Code consumption and revocation records are preserved.','success')
        return redirect(url_for('activity'))

    @app.get('/admin/codes/<code_id>')
    @admin_only
    def code_detail(code_id):
        kind=request.args.get('view','domains')
        return render_template('code_detail.html',code=store.code_detail(code_id),history=store.history(kind=kind,code_id=code_id,**history_options()),events=sorted(EVENTS),policy=store.activity_settings())

    @app.route('/admin/batches/<batch_id>/remove',methods=['GET','POST'])
    @admin_only
    def remove_batch(batch_id):
        batch=store.batch_detail(batch_id)
        if request.method=='POST':
            store.remove_batches([batch_id])
            flash('Batch removed from the normal list. Its codes and grants remain revoked.','success')
            return redirect(url_for('batches'))
        return render_template('remove_batches.html',items=[batch],bulk=False,csrf=csrf())

    @app.route('/admin/batches/clear-revoked',methods=['GET','POST'])
    @admin_only
    def clear_revoked_batches():
        if request.method=='POST':
            ids=request.form.get('ids','').split(',')
            count=store.remove_batches(ids,revoked_only=True)
            flash(f'Removed {count} reviewed revoked batches.','success')
            return redirect(url_for('batches'))
        return render_template('remove_batches.html',items=store.removable_batches(),bulk=True,csrf=csrf())

    @app.route('/admin/settings',methods=['GET','POST'])
    @admin_only
    def admin_settings():
        security=g.admin_security
        if request.method=='POST':
            if not store.attempt('admin-settings:'+client_ip(),5): raise GateError('Too many attempts. Please wait 15 minutes.')
            if not check_password_hash(security['password_hash'],request.form.get('current_password','')):
                raise GateError('Current password is incorrect.')
            action=request.form.get('action','')
            changes={}
            if action=='password':
                password=request.form.get('new_password','')
                if len(password)<8 or len(password)>256: raise GateError('Use a password between 8 and 256 characters.')
                if password!=request.form.get('confirm_password',''): raise GateError('Passwords do not match.')
                changes['password_hash']=generate_password_hash(password)
            elif action=='networks':
                changes['networks']=management_networks(request.form.get('networks',''))
                if not any(ipaddress.ip_address(client_ip()) in ipaddress.ip_network(n) for n in changes['networks']):
                    raise GateError('Keep your current management address in an allowed network to prevent lockout.')
            elif action=='exclusions':
                changes['exclusions']=exclusion_networks(request.form.get('exclusions',''))
            else: raise GateError('Invalid settings action.')
            store.save_admin_security(config,expected_version=request.form.get('version',''),**changes)
            end_login()
            flash('Administrator settings saved. Sign in again. Other administrator sessions have been signed out.','success')
            return redirect(url_for('login'))
        return render_template('settings.html',security=security,csrf=csrf(),address=client_ip())

    @app.get('/admin/sessions')
    @admin_only
    def active_sessions():
        state=request.args.get('state','active')
        result=store.session_overview(state,request.args.get('page','1'))
        return render_template('sessions.html',result=result,state=state,csrf=csrf())

    @app.get('/admin/api/sessions')
    @admin_only
    def sessions_data():
        return jsonify(store.session_overview(request.args.get('state','active'),request.args.get('page','1')))

    @app.route('/admin/access/<session_id>/terminate',methods=['GET','POST'])
    @admin_only
    def terminate_access(session_id):
        grant=next((r for r in store.list_grants() if r['session_id']==session_id),None)
        if not grant: raise GateError('Browser session not found.')
        if request.method=='POST':
            changed=store.terminate_session(session_id)
            flash('Session terminated. The gateway will close its restricted connections on its next live check.' if changed else 'Session already ended.','success')
            return redirect(url_for('active_sessions'))
        return render_template('terminate.html',grant=grant,csrf=csrf())

    @app.get('/admin/system')
    @admin_only
    def system_status():
        return render_template('system.html',health=health.snapshot())

    @app.get('/admin/api/health')
    @admin_only
    def health_data():
        return jsonify(health.snapshot())

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
        return dict(codes=store.list_codes(batch_id,request.args.get('status',''),page_number(),include_cleared=bool(batch_id and (store.batch_detail(batch_id)['removed_at'] or request.args.get('cleared')=='1'))),
                    code_status=request.args.get('status',''),statuses=STATUSES,
                    clear_count=store.revoked_visible(batch_id),batch_id=batch_id,
                    csrf=csrf(),now=time.time())

    def back(batch_id):
        return redirect(url_for('batch_detail',batch_id=batch_id) if batch_id else url_for('admin'))

    @app.get('/status')
    def access_status():
        ip = client_ip()
        grant = current_grant()
        exclusion=current_exclusion()
        return jsonify(active=bool(grant or exclusion),expires=exclusion['expires'] if exclusion else (grant['expires'] if grant else None),kind=exclusion['kind'] if exclusion else ('code' if grant else None),server_time=time.time())

    @app.get('/admin')
    @admin_only
    def admin():
        return render_template('admin.html',**list_context(),grants=[r for r in store.list_grants() if not r['revoked'] and r['expires']>time.time()],
                               extensions=store.extension_history())

    @app.get('/admin/batches')
    @admin_only
    def batches():
        return render_template('batches.html',batches=store.list_batches(page=page_number(),view=request.args.get('view','active')),view=request.args.get('view','active'),
                               csrf=csrf(),now=time.time())

    @app.route('/admin/dns-domains', methods=['GET', 'POST'])
    @admin_only
    def dns_domains():
        error = None
        value = ''
        scope = request.form.get('scope', 'subdomains')
        if request.method == 'POST':
            value = request.form.get('domains', '')
            try:
                added, existing = store.add_dns_domains(value, scope)
            except GateError as exc:
                error = str(exc)
            else:
                flash(f'Added {added} hostnames; {existing} already listed. Pi-hole must fetch and apply the updated feed to use these changes.', 'success')
                return redirect(url_for('dns_domains'))
        return dns_page(error=error, value=value, scope=scope)

    def dns_page(error=None, value='', scope='subdomains', import_error=None, import_url='', import_scope='subdomains'):
        page = store.dns_domain_page(request.args.get('q', ''), request.args.get('page', '1'))
        summary = store.dns_summary()
        return render_template('dns_domains.html', domains=page['items'], domain_page=page, summary=summary,
                               target_ip=TARGET_IP, enabled_count=summary['enabled'], wildcard_count=summary['wildcard'],
                               preview=store.export_dns_domains('dnsmasq', limit=50), value=value, scope=scope,
                               error=error, csrf=csrf(), import_error=import_error,
                               import_url=import_url, import_scope=import_scope), 400 if error or import_error else 200

    @app.post('/admin/dns-domains/import')
    @admin_only
    def import_dns_domains():
        source = request.form.get('url', '').strip()
        scope = request.form.get('scope', 'subdomains')
        try:
            if scope not in ('subdomains', 'exact'): raise GateError('Choose a valid domain match scope.')
            result = store.import_dns_blocklist(download_blocklist(source), scope)
        except GateError as exc:
            return dns_page(import_error=str(exc), import_url=source, import_scope=scope)
        flash(f"Imported {result['added']:,} new domains; {result['existing']:,} already listed, "
              f"{result['duplicates']:,} source duplicates and {result['skipped']:,} unsupported/local entries skipped. "
              'Existing rules kept their state and scope. The live feeds are updated; Pi-hole must fetch and apply them.', 'success')
        return redirect(url_for('dns_domains'))

    @app.post('/admin/dns-domains/change')
    @admin_only
    def change_dns_domain():
        store.change_dns_domain(request.form.get('domain', ''), request.form.get('action', ''))
        flash('Domain list updated. Pi-hole must fetch and apply the updated feed to use this change.', 'success')
        return redirect(url_for('dns_domains'))

    @app.get('/admin/dns-domains/export/<kind>')
    @admin_only
    def export_dns_domains(kind):
        if kind not in ('hosts', 'dnsmasq'): abort(404)
        filename = 'access-gate.hosts' if kind == 'hosts' else '99-access-gate.conf'
        response = app.response_class(store.export_dns_domains(kind), mimetype='text/plain')
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response

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
        result=store.accept_admin_handoff(data.get('ticket'),data.get('nonce'),data.get('origin'),config) or store.accept_handoff(data.get('ticket'),data.get('nonce'),data.get('origin'))
        return jsonify(result)

    @app.route('/internal/check',methods=['GET','POST'])
    def check(require_domain=False):
        # An old ip= parameter can never authorize a browser or a proxied request.
        data=request.get_json(silent=True) if request.method=='POST' else {'token':request.cookies.get(SITE_COOKIE),'origin':request.headers.get('X-Gate-Origin')}
        if not isinstance(data,dict): return jsonify(active=False),401
        if require_domain:
            from .browser import origin
            try:
                target = origin(data.get('origin'))
                if not store.restricted_host(target[8:]): return jsonify(active=False),403
            except GateError: return jsonify(active=False),403
        grant=None
        if require_domain and request.method=='GET' and store.ip_excluded(request.headers.get('X-Gate-Client-IP'),config):
            grant=dict(expires=time.time()+60,session_id='ip-exclusion',kind='ip')
        if not grant:
            try:
                grant=store.admin_site_grant(data.get('token'),data.get('origin'),config,
                    activity=request.method=='GET' and request.headers.get('X-Gate-Activity')=='1') or store.gateway_grant(data.get('token'),data.get('origin'))
            except GateError:grant=None
        if not grant: return jsonify(active=False),401
        response=jsonify(active=True,expires=grant['expires'],session_id=grant['session_id'])
        response.headers['X-Gate-Expires']=str(grant['expires'])
        if grant.get('kind','code')=='code':
            response.headers['X-Gate-Code-Session']=grant['session_id']
            response.headers['X-Gate-Visit-Mode']=store.activity_settings()['mode']
        reserved={BROWSER_COOKIE,SITE_COOKIE,CHALLENGE_COOKIE,ADMIN_COOKIE}
        response.headers['X-Gate-Upstream-Cookie']='; '.join(part.strip() for part in request.headers.get('Cookie','').split(';') if part.strip() and part.strip().split('=',1)[0] not in reserved)
        return response

    @app.post('/internal/activity/visit')
    def record_visit():
        store.record_visit(request.get_json(silent=True))
        return jsonify(ok=True)

    @app.post('/internal/activity/cleanup')
    def cleanup_activity():
        store.cleanup_activity()
        return jsonify(ok=True)

    @app.get('/internal/gateway/domain')
    def gateway_domain():
        try: allowed = store.restricted_host(request.args.get('host', ''))
        except GateError: allowed = False
        return jsonify(restricted=allowed)

    @app.get('/internal/gateway/check')
    def gateway_check():
        return check(require_domain=True)

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
        result=store.accept_admin_handoff(request.args.get('ticket'),request.cookies.get(CHALLENGE_COOKIE),target,config) or store.accept_handoff(request.args.get('ticket'),request.cookies.get(CHALLENGE_COOKIE),target)
        from .browser import origin
        response=redirect(origin(target)+'/',code=303)
        response.set_cookie(SITE_COOKIE,result['token'],max_age=365*86400,secure=True,httponly=True,samesite='Lax',path='/')
        response.delete_cookie(CHALLENGE_COOKIE,secure=True,httponly=True,samesite='Lax',path='/')
        return response

    return app
