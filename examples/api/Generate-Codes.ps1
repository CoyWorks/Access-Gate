#requires -Version 7.4
<# Uses operating-system CA trust. Never disables certificate verification. #>
param(
    [Parameter(Mandatory)][string]$Operation,
    [Parameter(Mandatory)][string]$Output,
    [string]$RequestFile = (Join-Path $PSScriptRoot 'batch.json')
)
$ErrorActionPreference = 'Stop'

function Read-Private([string]$Path) {
    if (-not $IsWindows) {
        $mode = [System.IO.File]::GetUnixFileMode($Path)
        if (([int]$mode -band 63) -ne 0) { throw 'Private file permissions required.' }
    }
    return [System.IO.File]::ReadAllText($Path)
}

function Write-Private([string]$Path, $Value) {
    $options = [System.IO.FileStreamOptions]::new()
    $options.Mode = [System.IO.FileMode]::CreateNew
    $options.Access = [System.IO.FileAccess]::Write
    $options.Share = [System.IO.FileShare]::None
    if (-not $IsWindows) { $options.UnixCreateMode = [System.IO.UnixFileMode]::UserRead -bor [System.IO.UnixFileMode]::UserWrite }
    $stream = [System.IO.FileStream]::new($Path, $options)
    try {
        $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 20))
        $stream.Write($bytes); $stream.Flush($true)
    } finally { $stream.Dispose() }
}

try {
    if (Test-Path -LiteralPath $Output) { Write-Output 'Output already exists; no request sent.'; exit 0 }
    $origin = $env:ACCESS_GATE_API_URL.TrimEnd('/')
    $uri = [uri]$origin
    if ($uri.Scheme -ne 'https' -or -not $uri.Host -or $uri.UserInfo -or $uri.AbsolutePath -ne '/' -or $uri.Query -or $uri.Fragment) { throw 'Use the canonical HTTPS origin.' }
    $token = (Read-Private $env:ACCESS_GATE_API_TOKEN_FILE).Trim()
    $match = [regex]::Match($token, '^ag_([a-f0-9]{16})_[A-Za-z0-9_-]{43}$')
    if (-not $match.Success) { throw 'Invalid integration credential file.' }
    $body = Get-Content -Raw -LiteralPath $RequestFile | ConvertFrom-Json
    $endpoint = $origin + '/api/v1/batches'
    if (Test-Path -LiteralPath $Operation) {
        $plan = Read-Private $Operation | ConvertFrom-Json
        if ($plan.endpoint -ne $endpoint -or $plan.credential_id -ne $match.Groups[1].Value -or
            ($plan.body | ConvertTo-Json -Depth 20 -Compress) -ne ($body | ConvertTo-Json -Depth 20 -Compress)) { throw 'Operation mismatch; reconcile before replacing.' }
    } else {
        $plan = [ordered]@{ endpoint=$endpoint; credential_id=$match.Groups[1].Value; idempotency_key=[guid]::NewGuid().ToString(); body=$body; created_at_epoch=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }
        Write-Private $Operation $plan
    }
    $age = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - [double]$plan.created_at_epoch
    if ($age -lt 0 -or $age -ge 86400) { throw 'Recovery window ended; reconcile the original batch.' }
    try {
        $response = Invoke-WebRequest -Uri $endpoint -Method Post -Headers @{
            Authorization=('Bearer ' + $token); 'Idempotency-Key'=$plan.idempotency_key; Accept='application/json'
        } -ContentType 'application/json' -Body ([System.Text.Encoding]::UTF8.GetBytes(($plan.body | ConvertTo-Json -Depth 20))) -MaximumRedirection 0 -SkipHttpErrorCheck -TimeoutSec 30
    } catch {
        [Console]::Error.WriteLine('Result may be uncertain. Retry with the same operation file.'); exit 75
    }
    if ($response.StatusCode -ne 201) {
        [Console]::Error.WriteLine('API HTTP ' + $response.StatusCode + '. Keep the operation file; inspect the admin audit.')
        if ($response.StatusCode -ge 500 -or $response.StatusCode -eq 429) { exit 75 }; exit 2
    }
    $result = $response.Content | ConvertFrom-Json
    Write-Private $Output $result
    Write-Output 'Batch saved privately. Keep its operation file with the response.'
} catch {
    [Console]::Error.WriteLine('Check the HTTPS origin, private files and request. Reconcile an existing operation before changing it.'); exit 2
} finally { $token = $null }
