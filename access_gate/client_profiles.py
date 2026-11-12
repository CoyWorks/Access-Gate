"""Public, deployment-specific client artifacts. Never read a signing/private key."""
import base64
import hashlib
import json
from pathlib import Path
import plistlib
import uuid
from .onboarding import public_root


def identity(config):return hashlib.sha256(config['portal_url'].encode()).hexdigest()[:24]


def apple_profile(config,ca_path):
    if config['public_portal']:raise ValueError('Use the private gateway for device profiles.')
    root=public_root(ca_path);origin=config['portal_url'];base='org.accessgate.client.'+identity(config)
    def payload(kind,suffix,label,**values):
        return dict(PayloadType=kind,PayloadVersion=1,PayloadIdentifier=base+'.'+suffix,PayloadUUID=str(uuid.uuid5(uuid.NAMESPACE_URL,origin+'/access-gate/'+suffix)).upper(),PayloadDisplayName=label,**values)
    certificate=payload('com.apple.security.root','root','Access Gate device CA',PayloadCertificateFileName='access-gate-root.cer',PayloadContent=root['der'])
    shortcut=payload('com.apple.webClip.managed','portal','Access Gate portal',Label='Access Gate',URL=origin+'/',IsRemovable=True,FullScreen=False)
    profile=payload('Configuration','profile','Access Gate — '+origin,PayloadRemovalDisallowed=False,PayloadDescription='Installs the verified device CA and a portal shortcut only. Manually enable full SSL/TLS trust after installation. No VPN, DNS, MDM enrollment or credentials are included.',PayloadContent=[certificate,shortcut])
    return plistlib.dumps(profile,fmt=plistlib.FMT_XML,sort_keys=True)


def windows_script(config,ca_path):
    if config['public_portal']:raise ValueError('Use the private gateway for device setup.')
    root=public_root(ca_path)
    data=dict(Deployment=identity(config),Portal=config['portal_url']+'/',RootSha256=root['sha256'],Certificate=base64.b64encode(root['der']).decode())
    encoded=base64.b64encode(json.dumps(data,separators=(',',':')).encode()).decode()
    return Path(__file__).with_name('windows_client.ps1.in').read_text().replace('@@PUBLIC_DATA@@',encoded).encode('utf-8')
