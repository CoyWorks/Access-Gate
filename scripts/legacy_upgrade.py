"""Retire only Access Gate's known legacy local proxy integration."""
import argparse
from pathlib import Path
import shutil
import subprocess
from reset_install import APPARMOR_BLOCK,LEGACY_APPARMOR_BLOCK,mapped


def check(root,run=subprocess.run):
    root=Path(root).resolve()
    if mapped(root,'etc/access-gate/network.json').exists():
        raise ValueError('Legacy transparent interception is enabled. Apply its matching FortiGate rollback and run the old /opt/access-gate network disable command before updating to the standalone portal. Existing state has not been changed.')
    config=mapped(root,'etc/squid/squid.conf'); backup=mapped(root,'etc/squid/squid.conf.before-access-gate')
    profile=mapped(root,'etc/apparmor.d/local/usr.sbin.squid')
    if any(p.is_symlink() for p in (config,backup,profile)): raise ValueError('Inspect symlinked legacy proxy configuration before migration.')
    managed=config.exists() and '/opt/access-gate/access_gate/acl_helper.py' in config.read_text()
    if managed and not backup.is_file(): raise ValueError('Original Squid configuration backup is missing. Restore the legacy proxy configuration before migrating.')
    if profile.exists():
        text=profile.read_text()
        if '# Access Gate local pilot' in text and not any(block in text for block in (APPARMOR_BLOCK,LEGACY_APPARMOR_BLOCK)):
            raise ValueError('The legacy Access Gate AppArmor block was customized. Remove that block before migrating.')
    if root==Path('/') and Path('/usr/sbin/nft').exists() and (managed or (root/'etc/systemd/system/access-gate-network.service').exists()):
        result=run(['/usr/sbin/nft','list','table','inet','access_gate'],capture_output=True,text=True,timeout=5)
        if result.returncode==0:
            raise ValueError('A legacy Access Gate interception table is still active. Restore the matching FortiGate routing and remove that owned table before migrating.')
        if result.stderr and 'No such file or directory' not in result.stderr:
            raise ValueError('The legacy interception table could not be inspected. Check nftables permissions before migrating.')
    return managed


def retire(root,run=subprocess.run):
    root=Path(root).resolve(); managed=check(root,run=run)
    if managed:
        run(['systemctl','disable','--now','squid.service'],check=True)
        shutil.copy2(root/'etc/squid/squid.conf.before-access-gate',root/'etc/squid/squid.conf')
    profile=root/'etc/apparmor.d/local/usr.sbin.squid'
    if profile.exists():
        text=profile.read_text(); cleaned=text.replace(APPARMOR_BLOCK,'').replace(LEGACY_APPARMOR_BLOCK,'')
        if cleaned!=text:
            profile.write_text(cleaned)
            if root==Path('/') and Path('/usr/sbin/apparmor_parser').exists() and Path('/etc/apparmor.d/usr.sbin.squid').exists():
                run(['/usr/sbin/apparmor_parser','-r','/etc/apparmor.d/usr.sbin.squid'],check=True)
    for name in ('access-gate-keeper.service','access-gate-network.service'):
        path=mapped(root,'etc/systemd/system/'+name)
        if path.exists():
            run(['systemctl','disable','--now',name],check=True)
            path.unlink()


if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('mode',choices=('check','retire')); args=parser.parse_args()
    try: check('/') if args.mode=='check' else retire('/')
    except ValueError as exc: raise SystemExit(str(exc))
