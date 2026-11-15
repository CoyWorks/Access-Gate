#!/usr/bin/env bash
# Bash + curl + Python 3. Durable preparation is shared with the Python example.
set -euo pipefail
umask 077
if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "Usage: bash generate_codes.sh OPERATION.json OUTPUT.json [REQUEST.json]" >&2
  exit 2
fi
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
operation=$1
output=$2
request_file=${3:-$script_dir/batch.json}
if [[ -e "$output" ]]; then echo 'Output already exists; no request sent.'; exit 0; fi
python3 "$script_dir/generate_codes.py" --operation "$operation" --output "$output" --request "$request_file" --prepare-only
header_file=$(mktemp)
body_file=$(mktemp)
response_file=$(mktemp)
trap 'rm -f -- "$header_file" "$body_file" "$response_file"' EXIT
# The bearer credential is in a private file, never a curl command argument.
IFS= read -r token < "$ACCESS_GATE_API_TOKEN_FILE" || [[ -n "$token" ]]
printf 'Authorization: Bearer %s\n' "$token" > "$header_file"
unset token
endpoint=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["endpoint"])' "$operation")
key=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["idempotency_key"])' "$operation")
python3 -c 'import json,sys; json.dump(json.load(open(sys.argv[1]))["body"],open(sys.argv[2],"w"))' "$operation" "$body_file"
tls_options=()
if [[ -n ${ACCESS_GATE_API_CA:-} ]]; then tls_options=(--cacert "$ACCESS_GATE_API_CA"); fi
if ! status=$(curl --silent --show-error --proto '=https' --max-time 30 --max-filesize 262144 --max-redirs 0 \
  "${tls_options[@]}" --request POST --header "@$header_file" \
  --header 'Content-Type: application/json' --header 'Accept: application/json' \
  --header "Idempotency-Key: $key" --data-binary "@$body_file" \
  --output "$response_file" --write-out '%{http_code}' --url "$endpoint"); then
  echo 'Result may be uncertain. Retry with the same operation file.' >&2; exit 75
fi
if [[ "$status" != 201 ]]; then
  echo "API HTTP $status. Keep the operation file; inspect the admin audit." >&2
  if [[ "$status" == 429 || "$status" == 5?? ]]; then exit 75; else exit 2; fi
fi
python3 - "$script_dir" "$response_file" "$output" <<'PY'
import json,sys
sys.path.insert(0,sys.argv[1])
from generate_codes import private_write
with open(sys.argv[2]) as response: result=json.load(response)
private_write(sys.argv[3],result)
PY
echo 'Batch saved privately. Keep its operation file with the response.'
