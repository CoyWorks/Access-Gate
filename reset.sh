#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 1 || ( $1 != --purge && $1 != --dry-run ) ]]; then
    echo 'Usage: bash reset.sh --purge | --dry-run' >&2
    echo '--purge permanently removes codes, credentials, certificates and Access Gate backups.' >&2
    exit 1
fi
if [[ $EUID -ne 0 ]]; then echo 'Run this command as root.' >&2; exit 1; fi
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ $1 == --dry-run ]]; then
    exec /usr/bin/python3 "$source_dir/scripts/reset_install.py" dry-run
fi
# Validate restoration and file scope before stopping any service.
/usr/bin/python3 "$source_dir/scripts/reset_install.py" check
if [[ -f /etc/access-gate/network.json ]]; then
    cd /opt/access-gate
    /usr/bin/python3 -m access_gate.network disable
fi
echo 'Resetting Access Gate on this dedicated VM. Installed dependency packages will remain.'
for unit in access-gate.service access-gate-keeper.service access-gate-network.service squid.service nginx.service; do
    if systemctl cat "$unit" >/dev/null 2>&1; then systemctl disable --now "$unit"; fi
done
/usr/bin/python3 "$source_dir/scripts/reset_install.py" purge
if [[ -f /etc/apparmor.d/usr.sbin.squid ]] && command -v apparmor_parser >/dev/null; then
    apparmor_parser -r /etc/apparmor.d/usr.sbin.squid
fi
systemctl daemon-reload
echo 'Reset complete. The source checkout, system account and installed packages remain.'
echo 'To start fresh, run: bash install.sh'
