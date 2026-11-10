#!/usr/bin/env bash
set -euo pipefail
umask 027
if [[ $EUID -ne 0 ]]; then echo 'Run this installer as root.' >&2; exit 1; fi
resume_install=0
if [[ $# -gt 1 ]]; then echo 'Usage: bash install.sh [install|resume|update]' >&2; exit 1; fi
case ${1:-install} in
    install) install_mode=install ;;
    resume|--resume) install_mode=resume; resume_install=1 ;;
    update|--update) install_mode=update; resume_install=1 ;;
    -h|--help) echo 'Usage: bash install.sh [install|resume|update]'; exit 0 ;;
    *) echo 'Usage: bash install.sh [install|resume|update]' >&2; exit 1 ;;
esac
source /etc/os-release
if [[ "$ID" != ubuntu || "$VERSION_ID" != 24.04 ]]; then echo 'This installer requires Ubuntu 24.04.' >&2; exit 1; fi
bundle_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ $(readlink -f "$bundle_dir") == /opt/access-gate ]]; then
    echo 'Keep source files outside /opt/access-gate. Use /opt/access-gate-src for the Git checkout.' >&2; exit 1
fi
for required_item in access_gate access_gate/gateway.py access_gate/gateway_tls.py access_gate/gateway_setup.py templates static wsgi.py configure.py VERSION scripts/deploy_portal.py scripts/legacy_upgrade.py scripts/reset_install.py; do
    if [[ ! -e "$bundle_dir/$required_item" ]]; then
        echo "Missing source item: $required_item. Extract the complete repository archive first." >&2; exit 1
    fi
done
if ! ip -4 addr show | grep -q 'inet 10.40.22.5/24'; then echo 'Expected server address: 10.40.22.5/24.' >&2; exit 1; fi
if [[ $resume_install -eq 1 ]]; then
    for state_file in config.json acl-token ca/root.key ca/root.crt portal.key portal.crt; do
        if [[ ! -s /etc/access-gate/$state_file ]]; then
            echo "Cannot resume: missing /etc/access-gate/$state_file. Existing state has not been replaced." >&2; exit 1
        fi
    done
    if [[ ! -s /var/lib/access-gate/data/gate.sqlite3 ]]; then
        echo 'Cannot resume: the existing database is missing. No credentials or certificates were regenerated.' >&2; exit 1
    fi
    /usr/bin/python3 - <<'PY'
import json
from pathlib import Path
c = json.loads(Path('/etc/access-gate/config.json').read_text())
for key in ('secret','pepper','acl_token','admin_hash','database'):
    if not c.get(key):
        raise SystemExit('Cannot resume: incomplete configuration.')
if c['database'] != '/var/lib/access-gate/data/gate.sqlite3':
    raise SystemExit('Cannot resume: unexpected database path.')
if Path('/etc/access-gate/acl-token').read_text().strip() != c['acl_token']:
    raise SystemExit('Cannot resume: ACL token mismatch.')
PY
else
    if [[ -e /etc/access-gate/config.json ]]; then
        echo 'Access Gate already exists. To preserve its state, use the updated installer with --resume.' >&2; exit 1
    fi
    if ss -H -lnt | awk '{print $4}' | grep -Eq ':(80|443|8088)$'; then
        echo 'A required port is in use. Use a dedicated VM.' >&2; exit 1
    fi
fi
/usr/bin/python3 "$bundle_dir/scripts/legacy_upgrade.py" check
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y nginx python3-flask python3-aiohttp python3-cryptography gunicorn openssl ca-certificates curl iproute2 util-linux
if [[ $resume_install -eq 1 ]]; then
    for unit in access-gate-gateway.service access-gate.service access-gate-keeper.service; do
        if systemctl cat "$unit" >/dev/null 2>&1; then systemctl stop "$unit"; fi
    done
    backup_dir=$(mktemp -d /root/access-gate-resume.XXXXXX)
    cp -a /etc/access-gate "$backup_dir/config"
    cp -a /var/lib/access-gate/data "$backup_dir/data"
    if [[ -f /etc/squid/squid.conf ]]; then cp -a /etc/squid/squid.conf "$backup_dir/squid.conf"; fi
    if [[ -f /etc/nginx/sites-available/access-gate ]]; then
        cp -a /etc/nginx/sites-available/access-gate "$backup_dir/nginx.conf"
    fi
    echo "Existing server state backed up to $backup_dir"
fi
/usr/bin/python3 "$bundle_dir/scripts/legacy_upgrade.py" retire
id accessgate >/dev/null 2>&1 || useradd --system --home /var/lib/access-gate --shell /usr/sbin/nologin accessgate
id accessgate-gateway >/dev/null 2>&1 || useradd --system --home /nonexistent --shell /usr/sbin/nologin accessgate-gateway
install -d -m 0755 /etc/access-gate /var/lib/access-gate/public
install -d -o accessgate -g accessgate -m 0700 /var/lib/access-gate/data
install -d -o root -g root -m 0700 /etc/access-gate/ca
/usr/bin/python3 "$bundle_dir/scripts/deploy_portal.py" "$bundle_dir" /opt/access-gate
chown -R root:root /opt/access-gate
chmod -R go-w /opt/access-gate

if [[ $resume_install -eq 0 ]]; then
openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 3650 \
    -keyout /etc/access-gate/ca/root.key -out /etc/access-gate/ca/root.crt \
    -subj '/CN=Home Access Gate Root CA' \
    -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign'
chown root:root /etc/access-gate/ca/root.key /etc/access-gate/ca/root.crt
chmod 0640 /etc/access-gate/ca/root.key
chmod 0644 /etc/access-gate/ca/root.crt
openssl req -new -newkey rsa:2048 -nodes -keyout /etc/access-gate/portal.key \
    -out /etc/access-gate/portal.csr -subj '/CN=toegang.coyseinri.nl'
cat > /etc/access-gate/portal.ext <<'EXT'
subjectAltName=DNS:toegang.coyseinri.nl,IP:10.40.22.5
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EXT
openssl x509 -req -in /etc/access-gate/portal.csr -CA /etc/access-gate/ca/root.crt \
    -CAkey /etc/access-gate/ca/root.key -CAcreateserial -days 365 -sha256 \
    -extfile /etc/access-gate/portal.ext -out /etc/access-gate/portal.crt
chmod 0600 /etc/access-gate/portal.key
install -m 0644 /etc/access-gate/ca/root.crt /var/lib/access-gate/public/ca.crt

cd /opt/access-gate
/usr/bin/python3 - <<'PY'
import json, secrets, os
from pathlib import Path
from werkzeug.security import generate_password_hash
from access_gate.core import Store
password = secrets.token_urlsafe(20)
config = dict(secret=secrets.token_hex(32), pepper=secrets.token_hex(32),
              acl_token=secrets.token_hex(32), admin_hash=generate_password_hash(password),
              database='/var/lib/access-gate/data/gate.sqlite3',
              portal_url='https://10.40.22.5',client_networks=['10.40.0.0/16','127.0.0.1/32','::1/128'])
Path('/etc/access-gate/config.json').write_text(json.dumps(config,indent=2)+'\n')
Path('/etc/access-gate/acl-token').write_text(config['acl_token']+'\n')
Path('/root/access-gate-initial-login.txt').write_text('https://10.40.22.5/admin\nAdmin password: '+password+'\n')
os.chmod('/root/access-gate-initial-login.txt',0o600)
Store(config['database'],config['pepper']).initialize()
PY
else
    echo 'Reusing the existing configuration, database, admin password and certificates.'
    install -m 0644 /etc/access-gate/ca/root.crt /var/lib/access-gate/public/ca.crt
fi
cd /opt/access-gate
/usr/bin/python3 /opt/access-gate/configure.py --check
chown root:accessgate /etc/access-gate/config.json
chmod 0640 /etc/access-gate/config.json
chown root:root /etc/access-gate/acl-token
chmod 0600 /etc/access-gate/acl-token
chown -R accessgate:accessgate /var/lib/access-gate/data
/usr/bin/python3 -m access_gate.gateway_setup
runuser -u accessgate-gateway -- /usr/bin/python3 -m access_gate.gateway --check

cat > /etc/nginx/sites-available/access-gate <<'NGINX'
server {
    listen 10.40.22.5:80;
    server_name 10.40.22.5 toegang.coyseinri.nl;
    include /etc/access-gate/client-networks.nginx;
    location = /ca.crt {
        root /var/lib/access-gate/public;
        default_type application/x-x509-ca-cert;
        add_header Cache-Control no-store;
    }
    location ~ ^/(domains\.txt|pihole\.conf)$ {
        proxy_pass http://127.0.0.1:8088;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For "";
        proxy_set_header X-Gate-Key "";
        access_log off;
    }
    location / {
        proxy_pass http://127.0.0.1:8089;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For "";
        proxy_set_header X-Gate-Key "";
    }
}
NGINX
ln -sfn /etc/nginx/sites-available/access-gate /etc/nginx/sites-enabled/access-gate
if [[ -L /etc/nginx/sites-enabled/default ]]; then rm /etc/nginx/sites-enabled/default; fi
cat > /etc/systemd/system/access-gate.service <<'UNIT'
[Unit]
Description=Access Gate portal
After=network.target
[Service]
User=accessgate
Group=accessgate
WorkingDirectory=/opt/access-gate
ExecStart=/usr/bin/gunicorn --bind 127.0.0.1:8088 --workers 2 --threads 2 --timeout 15 wsgi:app
Restart=on-failure
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/access-gate/data
PrivateTmp=true
[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/access-gate-gateway.service <<'UNIT'
[Unit]
Description=Access Gate restricted-domain HTTPS gateway
Requires=access-gate.service
After=network.target access-gate.service
PartOf=access-gate.service
[Service]
User=accessgate-gateway
Group=accessgate-gateway
WorkingDirectory=/opt/access-gate
ExecStart=/usr/bin/python3 -m access_gate.gateway
Restart=on-failure
UMask=0077
RuntimeDirectory=access-gate-gateway
RuntimeDirectoryMode=0700
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/run/access-gate-gateway
PrivateTmp=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
[Install]
WantedBy=multi-user.target
UNIT
nginx -t
systemctl daemon-reload
systemctl enable nginx access-gate.service access-gate-gateway.service
systemctl reset-failed access-gate-gateway.service
# Nginx releases its former HTTPS listener before the new gateway binds port 443.
systemctl restart nginx
systemctl restart access-gate.service
if ! systemctl restart access-gate-gateway.service; then
    journalctl -u access-gate-gateway.service -n 60 --no-pager >&2 || true
    echo 'HTTPS gateway startup failed. Existing data and the pre-update backup are retained; correct the reported error and rerun update.sh.' >&2
    exit 1
fi
systemctl is-active access-gate.service nginx.service access-gate-gateway.service
if ! /usr/bin/python3 -m access_gate.readiness; then
    echo 'Portal startup failed. Existing data and the pre-update backup remain available.' >&2
    echo 'Recent portal service logs:' >&2
    journalctl -u access-gate.service -n 40 --no-pager >&2 || true
    journalctl -u access-gate-gateway.service -n 40 --no-pager >&2 || true
    echo 'Recent Nginx upstream errors:' >&2
    tail -n 20 /var/log/nginx/error.log >&2 || true
    echo 'Correct the reported backend/proxy error, then rerun update.sh. Do not reset the installation.' >&2
    exit 1
fi
printf '\nInstallation complete. CA certificate: http://10.40.22.5/ca.crt\n'
printf 'Completed mode: %s; version: %s\n' "$install_mode" "$(cat /opt/access-gate/VERSION)"
if [[ $resume_install -eq 1 ]]; then
    echo 'Admin portal: https://10.40.22.5/admin'
    echo 'Your existing admin password is unchanged. Initial login details, if still valid: /root/access-gate-initial-login.txt.'
elif [[ -f /root/access-gate-initial-login.txt ]]; then
    cat /root/access-gate-initial-login.txt
else
    echo 'Admin portal: https://10.40.22.5/admin (existing password unchanged).'
fi
printf '\nHTTPS gateway ready. Keep restricted DNS names pointing to 10.40.22.5 and trust the retained root CA on your browser devices. See docs/GATEWAY.md for verification and supported transports.\n'
