"""Allowlisted server settings review, consumed by the serialized root worker."""
import hashlib
import ipaddress
import json
from pathlib import Path
import subprocess
import time
from urllib.parse import urlsplit
from .core import Store,GateError
from .deployment import FIELDS,normalize
from .maintenance import JOB_ID,read_regular,write_private
from .recovery import DATABASE,database_account
from .reconfigure import updated,apply as apply_reconfiguration,command
from .installer import local_addresses,preflight
from .updates import installed

EDITABLE=FIELDS+('dns_upstreams',)


def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def public_settings(config,networks=None):
    result={key:config[key] for key in FIELDS}
    result['admin_networks']=networks if networks is not None else result['admin_networks']
    result.update(dns_mode=config['dns_mode'],web_mode=config['web_mode'],public_portal=config['public_portal'],remote_gateway=config['remote_gateway'])
    if config['dns_mode']=='builtin':result['dns_upstreams']=config['dns_upstreams']
    return result


def parse_form(form,config):
    if set(form)-{'csrf','action','current_password','server_ipv4','portal_url','portal_aliases','client_networks','admin_networks','dns_upstreams'}:raise GateError('Unsupported server setting.')
    def words(key):return form.get(key,'').replace(',',' ').split()
    result=dict(server_ipv4=form.get('server_ipv4',''),listen_ipv4=form.get('server_ipv4',''),dns_target_ipv4=form.get('server_ipv4',''),portal_url=form.get('portal_url',''),portal_aliases=words('portal_aliases'))
    from .administration import management_networks
    for key in ('client_networks','admin_networks'):result[key]=management_networks(form.get(key,''))
    if config['dns_mode']=='builtin':result['dns_upstreams']=words('dns_upstreams')
    elif 'dns_upstreams' in form:raise GateError('DNS upstream editing requires the installed built-in resolver.')
    try:updated(config,result)
    except (ValueError,TypeError):raise GateError('Check the IPv4 address, HTTPS origin, aliases and networks. Unsupported settings were not queued.') from None
    return result


class ServerSettings:
    def __init__(self,root='/',runner=None,gid=None):
        self.root=Path(root);self.private=self.root/'var/lib/access-gate/maintenance';self.runner=runner or command;self.gid=gid

    def current(self):
        c=normalize(json.loads(read_regular(self.root/'etc/access-gate/config.json',65536)))
        if c['database']!=DATABASE:raise GateError('Server settings require the standard installed database path. Use the documented root deployment workflow.')
        with database_account(self.root):policy=Store(self.root/DATABASE.lstrip('/'),c['pepper']).admin_security(c)
        return c,policy

    def candidate(self,current,requested,address):
        if not isinstance(requested,dict) or set(requested)-set(EDITABLE):raise GateError('Only supported server deployment fields may be changed.')
        try:c=updated(current,requested);actor=ipaddress.ip_address(address)
        except (ValueError,TypeError):raise GateError('Invalid or unsupported server settings.') from None
        try:portal_ip=ipaddress.ip_address(urlsplit(c['portal_url']).hostname)
        except ValueError:portal_ip=None
        if portal_ip is not None and str(portal_ip)!=c['listen_ipv4']:raise GateError('For an IPv4 portal origin, use the selected listener IPv4 in the portal URL as well.')
        if current['public_portal'] and (c['portal_url']!=current['portal_url'] or c['portal_aliases']!=current['portal_aliases']):raise GateError('Public portal identity changes require the supported root TLS workflow; network settings can be reviewed here.')
        if not any(actor in ipaddress.ip_network(n) for n in c['admin_networks']):raise GateError('Keep this administrator address in the proposed management networks.')
        if not c['public_portal'] and not any(actor in ipaddress.ip_network(n) for n in c['client_networks']):raise GateError('Keep this administrator address in the proposed client networks.')
        return c

    def check_host(self,current,c):
        addresses=local_addresses();listeners=[]
        if current['listen_ipv4']!=c['listen_ipv4']:
            result=subprocess.run(['/usr/bin/ss','-H','-lntu'],check=True,capture_output=True,text=True,timeout=5)
            from .services import endpoint
            for line in result.stdout.splitlines():
                fields=line.split()
                if len(fields)<5:raise GateError('Listener discovery returned an invalid result.')
                value=fields[4];bound,port=endpoint(value)
                if port in (80,443,53) and bound in (c['listen_ipv4'],'*','0.0.0.0','::',''):listeners.append(value)
        try:preflight(c,addresses=addresses,listeners=listeners)
        except (ValueError,OSError):raise GateError('Assign the selected IPv4 first, include it in client networks, and resolve listener or DNS upstream conflicts before applying.') from None

    def review(self,job_id,requested,address,policy_version):
        if not JOB_ID.fullmatch(job_id):raise GateError('Invalid review identity.')
        current,policy=self.current()
        if policy['version']!=policy_version:raise GateError('Administrator settings changed. Reload and review again.')
        c=self.candidate(dict(current,admin_networks=policy['networks']),requested,address);self.check_host(current,c)
        before=public_settings(current,policy['networks']);after=public_settings(c)
        changes=[dict(field=key,before=before.get(key),after=after.get(key)) for key in EDITABLE if before.get(key)!=after.get(key)]
        now=time.time();identity=installed(self.root)
        if identity['version']=='Unknown':raise GateError('Installed version is unavailable. Run the normal updater before reviewing server settings.')
        summary=dict(current=before,proposed=after,changes=changes,checked_at=now,expires=now+900,installed=identity,reconnect_url=c['portal_url'],origin_changed=current['portal_url']!=c['portal_url'])
        if changes:
            record=dict(configuration=digest(current),policy_version=policy['version'],requested=requested,address=address,summary=summary)
            write_private(self.private/(job_id+'.server-preview'),json.dumps(record).encode())
        return dict(message='Server settings reviewed. Confirm within 15 minutes; nothing has been changed.' if changes else 'No settings changed. No services were touched.',server_settings={k:v for k,v in summary.items() if k not in ('current','proposed')},server_confirm=bool(changes))

    def apply(self,preview_id,progress):
        if not JOB_ID.fullmatch(preview_id or ''):raise GateError('Invalid server-settings preview.')
        path=self.private/(preview_id+'.server-preview')
        try:review=json.loads(read_regular(path,131072))
        except (OSError,ValueError):raise GateError('Preview was already used or expired. Review server settings again.') from None
        current,policy=self.current();summary=review['summary']
        if not 0<=time.time()-summary['checked_at']<=900 or summary['expires']<time.time() or review['configuration']!=digest(current) or review['policy_version']!=policy['version'] or summary['installed']!=installed(self.root):
            raise GateError('Configuration, administrator policy or installed version changed, or the review expired. Review again.')
        c=self.candidate(dict(current,admin_networks=policy['networks']),review['requested'],review['address']);self.check_host(current,c)
        if public_settings(c)!=summary['proposed']:raise GateError('Reviewed proposal is inconsistent. Review again.')
        path.unlink() # Single use, including readiness failure or an interrupted root worker.
        progress('Applying reviewed server settings. Services will briefly disconnect; use the reviewed portal address afterward.')
        try:apply_reconfiguration(self.root,c,runner=self.runner,gid=self.gid,expected_policy_version=policy['version'],expected_configuration=review['configuration'])
        except RuntimeError as exc:
            if str(exc).startswith('Reconfiguration failed; previous configuration restored.'):
                raise GateError('Application failed; previous configuration was restored and local readiness passed. Reconnect at '+current['portal_url']+' and review before retrying.') from None
            if str(exc).startswith('Reconfiguration and rollback readiness failed.'):
                raise GateError('Application and rollback readiness failed. Root recovery is required; inspect services and /var/lib/access-gate/reconfigure rollback snapshots.') from None
            raise GateError('Server settings could not pass validation/application. Check services and root reconfigure snapshots; do not assume the new address is active.') from None
        except Exception:raise GateError('Server settings could not pass validation/application. Check services and root reconfigure snapshots before retrying.') from None
        return dict(message='Server settings applied and local readiness passed. Check external DNS/client routing and sign in again if required.',reconnect_url=c['portal_url'])
