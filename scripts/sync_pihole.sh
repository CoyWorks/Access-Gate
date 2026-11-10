#!/usr/bin/env bash
# Run on a native Linux Pi-hole host; /etc/dnsmasq.d must already be enabled.
set -euo pipefail
if [[ $EUID -ne 0 ]]; then echo 'Run this command as root.' >&2; exit 1; fi
exec 9>/run/lock/access-gate-pihole-sync.lock
flock -n 9 || exit 0
work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT
config_file=/etc/dnsmasq.d/99-access-gate.conf
curl --noproxy '*' --fail --silent --show-error --connect-timeout 5 --max-time 60 \
    http://10.40.22.5/pihole.conf --output "$work_dir/new.conf"
# Refuse empty/error-page responses before touching the active configuration.
if ! head -n 1 "$work_dir/new.conf" | grep -Fxq '# Access Gate DNS mappings: 10.40.22.5'; then
    echo 'Downloaded content is not an Access Gate DNS configuration; nothing changed.' >&2
    exit 1
fi
if [[ -f $config_file ]] && cmp -s "$work_dir/new.conf" "$config_file"; then exit 0; fi
had_config=false
if [[ -e $config_file ]]; then cp -a -- "$config_file" "$work_dir/previous.conf"; had_config=true; fi
rollback() {
    if $had_config; then cp -a -- "$work_dir/previous.conf" "$config_file"; else rm -f -- "$config_file"; fi
}
install -d -m 0755 /etc/dnsmasq.d
install -m 0644 "$work_dir/new.conf" "$config_file"
if ! pihole-FTL dnsmasq-test; then
    rollback
    echo 'DNS configuration test failed; previous configuration restored.' >&2
    exit 1
fi
if ! systemctl restart pihole-FTL; then
    rollback
    systemctl restart pihole-FTL || true
    echo 'Pi-hole restart failed; previous configuration restored.' >&2
    exit 1
fi
echo 'Access Gate DNS configuration updated.'
