#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 0 ]]; then echo 'Usage: bash resume.sh' >&2; exit 1; fi
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec bash "$source_dir/install.sh" resume
