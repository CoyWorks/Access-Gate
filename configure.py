#!/usr/bin/python3
"""Validate the standalone code portal; does not change DNS or firewall settings."""
import argparse
import getpass
import secrets
import warnings
from werkzeug.security import generate_password_hash
import json
import os
from pathlib import Path
from access_gate.core import Store
from access_gate.settings import validate,atomic_write


def change_admin_password(path,initial_login_path):
    path=Path(path)
    config=validate(json.loads(path.read_text()))
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error',getpass.GetPassWarning)
            password=getpass.getpass('New admin password (at least 8 characters): ')
            confirmation=getpass.getpass('Confirm new admin password: ')
    except (EOFError,KeyboardInterrupt,getpass.GetPassWarning):
        raise SystemExit('Password change cancelled. Use an interactive terminal; nothing was changed.')
    if len(password)<8: raise SystemExit('Use at least 8 characters. Nothing was changed.')
    if password!=confirmation: raise SystemExit('Passwords do not match. Nothing was changed.')
    config['admin_hash']=generate_password_hash(password)
    # Flask sessions contain admin login/CSRF state. Browser grants use a separate pepper.
    config['secret']=secrets.token_hex(32)
    atomic_write(path,json.dumps(config,indent=2)+'\n')
    initial=Path(initial_login_path)
    if initial.exists():
        atomic_write(initial,config['portal_url']+'/admin\nAdmin password changed locally; the initial password is no longer valid.\n',0o600)
    print('Admin password changed. Restart access-gate.service to apply and sign out existing admin sessions.')


def main(argv=None,config_path='/etc/access-gate/config.json',initial_login_path='/root/access-gate-initial-login.txt'):
    if os.geteuid()!=0: raise SystemExit('Run this command as root.')
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true',help='Validate configuration and the database')
    parser.add_argument('--set-admin-password',action='store_true',help='Prompt for a new admin password and sign out existing admin sessions after restart')
    args=parser.parse_args(argv)
    if args.set_admin_password:
        change_admin_password(config_path,initial_login_path)
        return
    path=Path(config_path)
    config=validate(json.loads(path.read_text()))
    Store(config['database'],config['pepper']).initialize()
    atomic_write(path,json.dumps(config,indent=2)+'\n')
    atomic_write('/etc/access-gate/client-networks.nginx',''.join('allow '+n+';\n' for n in config['client_networks'])+'deny all;\n',0o644)
    print('Portal configuration and database are ready.')
    print('Client networks: '+', '.join(config['client_networks']))
    print('Select restricted domains and configure redirects in your external DNS/firewall/proxy solution.')


if __name__=='__main__': main()
