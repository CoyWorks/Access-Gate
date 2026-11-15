# Validate the integration API

Run automated tests in a development environment with the normal Access Gate Python dependencies and the developer-only packages in `tests/requirements-contract.txt`.

```bash
python3 -m pip install -r tests/requirements-contract.txt
python3 scripts/check_api.py
python3 -m unittest discover -s tests -v
```

Use a virtual environment or a disposable development system for package installation. Validation extras are not installed on production servers. `check_api.py` fails if validators are missing or any selected checks are skipped; the normal discovery command can skip optional schema checks when those extras are absent.

Full discovery needs the optional built-in DNS dependency `dnspython` in the development environment, even when the tested server profile uses external DNS. The example-client tests additionally use curl/Bash and optionally PowerShell 7.4+; set `ACCESS_GATE_TEST_PWSH` to its executable when it is not on PATH. No certificate-verification bypass is used.

The API checks cover actual JSON responses against OpenAPI, independent credential authentication, scopes, trusted sources, body/type validation, retry concurrency and encryption, bounded request/code budgets, ownership, pagination, revocation and migration. Full discovery also checks the verified-TLS gateway flow and existing browser, notification, certificate, deployment and recovery behavior. It does not contact or change a live installation.

## Opt-in HTTPS acceptance test

Use a **disposable installation** with a test browser and a test restricted domain. These steps create usable codes and change access state; they are not a read-only health probe.

1. Install/update normally and verify the gateway/portal certificate. Use the canonical portal URL. For a private CA, supply the independently verified CA to your client; keep hostname verification enabled.
2. Open **More → API integrations**. Enable the API for only the test program's source CIDR. Create a short-lived credential with `batches:create`, `batches:read` and `batches:revoke`; store its secret privately.
3. Follow the [API examples](REST_API.md). Request ten codes with seven-day validity and fifteen-minute access. Save the key and response privately. Confirm `201`, `Idempotency-Replayed: false`, ten distinct codes and the integration identifier on the admin batch page.
4. Repeat with the same key/body. Confirm `201`, `Idempotency-Replayed: true` and the same batch/codes/deadlines. The administrator list must show one batch. Repeat concurrently if validating a multi-worker deployment.
5. Redeem one code in the test browser. Confirm its active access ends fifteen minutes after redemption. Try that code in a separate non-excluded browser: a second redemption must fail.
6. Read the batch/code status with the same credential. Verify the redeemed state and counts. Confirm ordinary reads contain no raw codes, visitor IPs or browser tokens.
7. Revoke the active code or batch through the API, then repeat the request. Both return `200`. Refresh the restricted website and verify the existing session loses access. Do not use a signed-in administrator browser or an excluded address for this enforcement check.
8. Create a second credential. It must receive the same `404` for the first credential's batch as for a nonexistent identifier, and its list must omit that batch. A creation-only credential must receive `403` on reads/revocation.
9. Revoke the test credential in administration and repeat generation: expect JSON `401` and no new batch. Disable the API: expect JSON `404`.
10. Confirm the integrations audit shows safe source/credential/request/batch attribution and excludes the credential and raw codes. Remove the disposable system or revoke all remaining test codes/credentials.

Never paste credentials, full code responses or request headers into test reports. A successful server test does not prove DNS/VPN/certificate enforcement on every real client; repeat the affected client path separately.

[API reference](REST_API.md) · [Documentation overview](README.md)
