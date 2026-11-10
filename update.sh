#!/usr/bin/env bash
set -euo pipefail
if [[ $EUID -ne 0 ]]; then
    echo 'Run this updater as root.' >&2
    exit 1
fi
if [[ $# -ne 0 ]]; then
    echo 'Usage: bash update.sh' >&2
    exit 1
fi
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
bash -n "$source_dir/install.sh"
if [[ -e /etc/access-gate/config.json ]]; then
    echo 'Updating or resuming Access Gate using the existing server state.'
    exec bash "$source_dir/install.sh" update
else
    echo 'No existing Access Gate configuration found. Starting a fresh installation.'
    exec bash "$source_dir/install.sh"
fi
