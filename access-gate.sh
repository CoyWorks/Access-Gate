#!/usr/bin/env bash
# Download a clean snapshot before every install, resume or update.
set -euo pipefail
if [[ $# -gt 1 ]]; then echo 'Usage: bash access-gate.sh [install|resume|update]' >&2; exit 1; fi
mode=${1:-install}
case "$mode" in
    install|resume|update) ;;
    -h|--help) echo 'Usage: bash access-gate.sh [install|resume|update]'; exit 0 ;;
    *) echo 'Usage: bash access-gate.sh [install|resume|update]' >&2; exit 1 ;;
esac
if [[ $EUID -ne 0 ]]; then echo 'Run this command as root.' >&2; exit 1; fi
for tool in curl tar mktemp; do
    if ! command -v "$tool" >/dev/null; then echo "Required command not found: $tool" >&2; exit 1; fi
done
download_dir=$(mktemp -d /root/access-gate-download.XXXXXX)
mkdir "$download_dir/source"
echo "Downloading CoyWorks/Access-Gate main into $download_dir"
curl --fail --location --show-error --retry 2 --connect-timeout 15 --max-time 180 \
    https://github.com/CoyWorks/Access-Gate/archive/refs/heads/main.tar.gz \
    --output "$download_dir/source.tar.gz"
tar -xzf "$download_dir/source.tar.gz" --no-same-owner --strip-components=1 -C "$download_dir/source"
if [[ ! -s "$download_dir/source/install.sh" || ! -s "$download_dir/source/VERSION" ]]; then
    echo 'The downloaded archive is incomplete. No installer was started.' >&2; exit 1
fi
bash -n "$download_dir/source/install.sh"
echo "Running $mode for Access Gate $(cat "$download_dir/source/VERSION")"
exec bash "$download_dir/source/install.sh" "$mode"
