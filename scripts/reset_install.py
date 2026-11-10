#!/usr/bin/env python3
"""Remove Access Gate state only; service shutdown is handled by reset.sh."""
import argparse
from pathlib import Path
import shutil

APPARMOR_BLOCK = '''# Access Gate local pilot
/etc/access-gate/ r,
/etc/access-gate/** r,
/opt/access-gate/access_gate/acl_helper.py r,
/usr/bin/python3* ix,
/usr/lib/python3*/** mr,
/etc/python3*/** r,
/var/lib/squid/ssl_db/ rw,
/var/lib/squid/ssl_db/** rwk,
'''
REMOVE = (
    'etc/systemd/system/access-gate.service',
    'etc/systemd/system/access-gate-keeper.service',
    'etc/nginx/sites-enabled/access-gate',
    'etc/nginx/sites-available/access-gate',
    'opt/access-gate', 'etc/access-gate', 'var/lib/access-gate',
    'var/lib/squid/ssl_db', 'root/access-gate-initial-login.txt',
)


def mapped(root, relative):
    path = root/relative
    for parent in path.parents:
        if parent == root: break
        if parent.is_symlink():
            raise ValueError(f'Refusing a path with a symlinked parent: {path}')
    return path


def plan(root):
    root = Path(root).resolve()
    config = mapped(root,'etc/squid/squid.conf')
    backup = mapped(root,'etc/squid/squid.conf.before-access-gate')
    profile = mapped(root,'etc/apparmor.d/local/usr.sbin.squid')
    if config.is_symlink() or backup.is_symlink() or profile.is_symlink():
        raise ValueError('Refusing to rewrite a symlinked service configuration.')
    managed = config.exists() and '/etc/access-gate/' in config.read_text()
    if managed and not backup.is_file():
        raise ValueError('Original Squid backup is missing. Restore it before purging Access Gate.')
    if profile.exists():
        text = profile.read_text()
        if '# Access Gate local pilot' in text and APPARMOR_BLOCK not in text:
            raise ValueError('The Access Gate AppArmor block was customized. Remove that block manually first.')
    paths = [mapped(root,p) for p in REMOVE]
    for pattern in ('root/access-gate-resume.*','opt/.access-gate-previous-*','opt/.access-gate-stage-*'):
        paths.extend(root.glob(pattern))
    if backup.exists(): paths.append(backup)
    for p in paths: mapped(root,str(p.relative_to(root)))
    return paths, managed, profile


def purge(root):
    root = Path(root).resolve()
    paths, managed, profile = plan(root)
    if managed:
        shutil.copy2(root/'etc/squid/squid.conf.before-access-gate',root/'etc/squid/squid.conf')
    if profile.exists():
        text = profile.read_text()
        cleaned = text.replace(APPARMOR_BLOCK,'')
        if cleaned != text: profile.write_text(cleaned)
    for p in paths:
        if p.is_symlink() or p.is_file(): p.unlink()
        elif p.is_dir(): shutil.rmtree(p)


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('mode',choices=('check','dry-run','purge'))
    args=parser.parse_args()
    paths,restore,_=plan(Path('/'))
    if args.mode=='dry-run':
        print('Restore the original Squid configuration.' if restore else 'Preserve the current Squid configuration.')
        for p in paths: print('Remove:',p)
        print('Remove only the Access Gate AppArmor block, if present.')
    elif args.mode=='purge':
        purge(Path('/'))
        print('Access Gate application, data, keys and saved installation backups removed.')
