# Generate codes from another program

Choose one client: [Python 3](generate_codes.py), [Bash + curl + Python 3](generate_codes.sh), or [PowerShell 7.4+](Generate-Codes.ps1). They use the same [batch request](batch.json) and durable operation-file format. None prints visitor codes or the bearer credential.

## Prepare Access Gate

1. Update the server using the normal `update.sh` workflow. No reset or new CA is required. API access stays disabled until you enable it.
2. Open **More → API integrations**. Enable the API and enter the source CIDR your server will actually see for the external program. An extra reverse proxy may appear as the source; forwarded headers from arbitrary clients are ignored. Do not open the loopback backend ports.
3. Create a named credential with an appropriate expiry. Start with `batches:create`. Add `batches:read` or `batches:revoke` only if the integration needs those operations. Optional credential CIDRs further restrict the global API policy.
4. Copy the secret once into a private credential file or your program's secret store. Keep administrator passwords and internal/gateway keys separate.
5. Use the configured canonical HTTPS portal origin. Portal aliases and remote gateway URLs do not accept this API. Verify and trust the portal's CA using the normal client-onboarding process; public trusted certificates need no extra CA file.

## Linux: save the credential privately

Run from a private user account. Keep the credential, operation plan and code output outside the repository and shared/synchronized folders.

```bash
umask 077
api_dir="$HOME/.config/access-gate-api"
mkdir -p -m 700 "$api_dir"
chmod 700 "$api_dir"
export ACCESS_GATE_API_URL='https://access.example.org'
export ACCESS_GATE_API_TOKEN_FILE="$api_dir/credential"
IFS= read -r -s -p 'Integration credential: ' api_token
printf '\n'
printf '%s' "$api_token" > "$ACCESS_GATE_API_TOKEN_FILE"
chmod 600 "$ACCESS_GATE_API_TOKEN_FILE"
unset api_token
```

The URL is an example. For a private CA, set `ACCESS_GATE_API_CA` to the independently verified CA file. Python and curl use that file without disabling certificate or hostname checks:

```bash
export ACCESS_GATE_API_CA='/path/to/verified-ca.crt'
```

For a publicly trusted portal certificate, leave that variable unset. Do not enable shell tracing (`set -x`) around secret preparation. The credential is never placed in the example clients' command arguments; the curl client uses a temporary private header file.

## Python

From the repository root:

```bash
python3 examples/api/generate_codes.py \
  --operation "$api_dir/weekly.plan.json" \
  --output "$api_dir/weekly.codes.json"
```

Python uses its standard library. To change the requested number of codes or durations, copy `batch.json`, edit the six documented fields, then pass `--request /path/to/request.json`. A new intended batch needs a new operation/output filename. Changing the request for an existing operation is rejected.

## curl

The Bash client uses curl for HTTPS and the Python client helper to prepare/check its durable retry plan:

```bash
bash examples/api/generate_codes.sh \
  "$api_dir/weekly.plan.json" \
  "$api_dir/weekly.codes.json"
```

An optional third argument supplies a custom request JSON file. This example deliberately uses the same plan/output filenames as the Python command; running both commands will not create a second batch. Curl does not follow redirects and uses a private header file, verified HTTPS, bounded response size and a 30-second timeout.

## PowerShell

Use PowerShell **7.4 or newer**, with the portal's CA trusted by the operating system. The Linux Python/curl CA variable does not configure PowerShell trust. Keep the following folder private to the client account; on Windows, use a user-profile folder with appropriate user ACLs.

```powershell
$apiDir = Join-Path $env:LOCALAPPDATA 'AccessGateApi'
New-Item -ItemType Directory -Force -Path $apiDir | Out-Null
$env:ACCESS_GATE_API_URL = 'https://access.example.org'
$env:ACCESS_GATE_API_TOKEN_FILE = Join-Path $apiDir 'credential'
$secureToken = Read-Host 'Integration credential' -AsSecureString
$apiToken = [System.Net.NetworkCredential]::new('', $secureToken).Password
[System.IO.File]::WriteAllText($env:ACCESS_GATE_API_TOKEN_FILE, $apiToken, [System.Text.UTF8Encoding]::new($false))
Remove-Variable apiToken, secureToken

pwsh -NoProfile -File examples/api/Generate-Codes.ps1 `
  -Operation (Join-Path $apiDir 'weekly.plan.json') `
  -Output (Join-Path $apiDir 'weekly.codes.json')
```

Use `-RequestFile /path/to/request.json` for a custom request. On Linux/macOS choose a private user directory instead of `LOCALAPPDATA` and make the credential file owner-readable only. The script creates operation/output files with owner-only Unix permissions; on Windows they inherit the private directory's ACLs. It uses normal OS certificate validation and refuses automatic redirects.

## Retry and recover

- The plan is created **before** the HTTP request and binds the key to its HTTPS endpoint, credential identity and body. Keep it after success or failure.
- Rerun the same command after a timeout or temporary failure. The server returns the same codes for 24 hours. Existing output files are never overwritten; if output exists, no request is sent.
- If a response file was only partially written after a disk/process failure, keep it for investigation and choose a new output filename with the **same operation file**. Do not delete the plan or generate a replacement key merely because transport failed.
- The examples stop sending an unresolved operation 24 hours after its local creation, conservatively within the server's retry-key retention. After that, inspect/revoke the original batch in administration before intentionally replacing it with a new operation.
- A credential rotation is a new API identity. Old operation files reject the replacement credential instead of accidentally generating another batch. Reconcile old operations first.
- Exit `0` means a private response already exists or was saved. Exit `2` means configuration or a non-retryable HTTP error needs attention. Exit `75` means a temporary/uncertain outcome; schedule a bounded retry of the same operation. Observe API `Retry-After` and use backoff/jitter in a production scheduler rather than a tight loop.

The sample clients perform one HTTP attempt per invocation and do not sleep or retry indefinitely. They log only safe status information. Store/distribute the output according to your own integration's needs; never commit it or put codes in URLs/logs. Do not enable HTTP debug/transcript logging that captures authorization headers or response bodies.

## Status and revocation

With `batches:read`, use `GET /api/v1/batches`, `GET /api/v1/batches/{batch_id}` and `GET /api/v1/batches/{batch_id}/codes`. Preserve `page_size` when following `next_cursor`. Ordinary reads contain only status metadata and hints, never the raw codes.

With `batches:revoke`, send an explicit `{}` JSON body to `POST /api/v1/batches/{batch_id}/revoke` or `POST /api/v1/codes/{code_id}/revoke`. Repeating revocation is safe. Every operation is restricted to objects created by that same credential; manual batches and other credentials' batches remain private.

See the [API contract](../../docs/REST_API.md) for exact payloads, error codes, budgets and compatibility rules, and [API testing](../../docs/API_TESTING.md) for a disposable-server acceptance procedure.
