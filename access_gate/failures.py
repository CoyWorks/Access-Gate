"""Fixed visitor messages; never interpolate upstream errors or requested URLs."""
from html import escape
from urllib.parse import urlsplit
from .deployment import host

MESSAGES={
 'busy':('Please try again shortly','Access Gate is handling many connections. Wait a moment and retry.'),
 'policy':('Website policy unavailable','Website access cannot be checked right now. Try again shortly or contact the administrator.'),
 'authorization':('Access check unavailable','Your access could not be checked. No additional access has been granted. Try again shortly.'),
 'origin':('Website unavailable','The website could not be reached securely. Try again later or contact the administrator.'),
 'portal':('Access portal unavailable','The access portal is temporarily unavailable. Try again shortly or contact the administrator.'),
 'request':('Website request expired','Open the original website again to start a new request. Your code is not activated by this error page.'),
 'ended':('Access has ended','Your access expired or was revoked. Enter a new unused code or request access again.'),
 'setup':('Connection needs attention','This connection is not available for the current device or website. Check device setup or contact the administrator.'),
 'invalid':('Request could not be completed','Reload the page and try again. If this continues, contact the administrator.'),
 'missing':('Page not found','Open the access portal or return to the original website.'),
}

def portal_origin(value):
    """Only a configured HTTPS origin, including a local IPv4, can become a link."""
    try:
        u=urlsplit(value)
        if u.scheme!='https' or u.username or u.password or u.port not in (None,443) or u.path not in ('','/') or u.query or u.fragment:raise ValueError()
        return 'https://'+host(u.hostname)
    except (ValueError,TypeError,AttributeError):return None

def page(kind,portal_url):
    title,message=MESSAGES.get(kind,MESSAGES['invalid'])
    portal=portal_origin(portal_url)
    links='<a href="/">Retry website</a>'
    if portal:
        base=escape(portal,quote=True)
        links+=f'<a href="{base}/">Open access portal</a><a href="{base}/request-access">Request access</a><a href="{base}/setup">Device setup</a>'
    return f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{title} · Access Gate</title>
<style>body{{font:1rem/1.6 system-ui,sans-serif;background:#101624;color:#edf2fa;margin:0;padding:24px}}main{{max-width:640px;margin:8vh auto}}h1{{font-size:1.8rem}}nav{{display:flex;flex-wrap:wrap;gap:16px}}a{{color:#a8d7ff;padding:10px 0}}a:focus-visible{{outline:3px solid #a8d7ff;outline-offset:4px}}</style>
<main><p>ACCESS GATE</p><h1>{title}</h1><p role="alert">{message}</p><nav aria-label="Recovery options">{links}</nav></main></html>'''

HEADERS={'Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff',
         'Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"}
