# REST API v1 contract

**Status: contract only.** Issue [#45](https://github.com/CoyWorks/Access-Gate/issues/45) defines the interface; it does not add HTTP routes, integration credentials or server settings. Existing installations cannot use the examples yet. Runtime delivery is tracked in [#44](https://github.com/CoyWorks/Access-Gate/issues/44), with credentials in #46, generation in #47, retry handling in #48 and deployment controls in #49.

Use the checked-in [OpenAPI 3.1 specification](openapi/access-gate-v1.json) as the machine-readable reference. Its `info.version` describes the contract, independently of the Access Gate application version. The JSON file can be imported into OpenAPI tooling without a running server. The format follows the [OpenAPI 3.1 specification](https://spec.openapis.org/oas/v3.1.0).

## Manage integration credentials

Open **More → API integrations** to create a named credential. Choose scopes, a 1–365 day lifetime and optional extra source CIDRs, then confirm with your current administrator password. Copy the secret once; only its digest is stored. Rotate by creating a replacement before revoking the old identity. Revocation applies on the next request. Credentials are preserved by normal updates; a backup restore disables API access and revokes restored credentials. Until generation and deployment controls are delivered, the API remains disabled.

For emergency local recovery, run as the server administrator:

```bash
python3 /root/Access-Gate/scripts/revoke_api.py --all
```

This disables API access and revokes every integration credential without changing browser access, administrator passwords or the CA.

## Create a batch

The first operation is `POST /api/v1/batches` on the configured canonical HTTPS portal origin. `https://access.example.org` is an example, not a default or a hosted service. No port or backend service needs to be opened for this contract.

Required headers:

| Header | Value |
| --- | --- |
| `Authorization` | `Bearer <integration credential>` |
| `Content-Type` | `application/json` (optional `charset=utf-8`) |
| `Idempotency-Key` | A unique 16–128 character key using letters, digits, `.`, `_`, `:` or `-` |
| `Accept` | `application/json`, or omitted/compatible wildcard |

The credential needs **`batches:create`**. It is separate from visitor codes, the admin password, browser cookies, the internal ACL key and gateway credentials. It grants no browser access or admin login. Cookie authentication is not accepted, and API responses must not create or renew browser/admin sessions. API credentials are managed by an administrator in #46, not through a public credential-creation endpoint.

Example request body for ten codes, available for seven days, with fifteen minutes of access per redemption:

```json
{
  "name": "Weekly allowance",
  "count": 10,
  "validity_value": 7,
  "validity_unit": "days",
  "access_value": 15,
  "access_unit": "minutes"
}
```

Every field is optional, but the body must be an explicit JSON object: `{}` uses all defaults. Do not send a missing body, `null`, an array, duplicate object keys, non-finite numbers or unknown fields. `profile_id`, schedules, start dates, caller references and automatic activation are not part of v1 creation.

| Field | Default | Accepted values |
| --- | --- | --- |
| `name` | Empty; server generates a name | String, at most 80 characters before trimming, no U+0000–U+001F controls. Trim leading/trailing whitespace; an empty result uses the existing generated name. |
| `count` | `10` | Whole-valued JSON number, 1–1000 |
| `validity_value` | `7` | Whole-valued JSON number: 1–365 for days, 1–8760 for hours |
| `validity_unit` | `days` | `hours` or `days`, case-sensitive |
| `access_value` | `15` | Whole-valued JSON number: 1–10080 for minutes, 1–168 for hours |
| `access_unit` | `minutes` | `minutes` or `hours`, case-sensitive |

Strings such as `"10"`, booleans, fractions and `null` are rejected for numeric fields. Whole-valued JSON numbers such as `10.0` are equivalent to `10`; normalize them to integers before calling the existing shared validator. Defaults do not bypass unit-specific limits. Unknown properties report `body` / `unknown_field`, without echoing arbitrary submitted property names or values.

The uncompressed UTF-8 body is limited to **16384 bytes**, including whitespace. Content encodings are unsupported; reject a `Content-Encoding` header. Reject query parameters on this operation. Creation is atomic: validation or transaction failure cannot leave part of a batch behind.

## Time and access rules

- Code validity starts when the batch is created. `valid_from` equals `created_at`; `valid_until` is exclusive.
- One day is exactly 86400 seconds, including across daylight-saving changes. Maximum validity is 365 days; maximum activated access is seven days.
- Redeeming a code just before `valid_until` still grants the full `access_seconds`. Validity limits redemption, not the end of an already active session.
- Codes are single-use. Access starts on redemption through the normal portal; generating or replaying a batch activates nothing.
- Access covers **all currently restricted domains in that browser session**. Per-domain profiles remain separate planned work in #11. Different browsers have different sessions; the timer continues when the browser closes.
- Timestamps use RFC 3339 UTC with `Z`, including any fractional seconds. Never infer deadlines from the client's local timezone.

## Success response

An initial creation returns `201 Created`. A successful retry returns the same status. Both use `Content-Type: application/json`, `Cache-Control: no-store`, `X-Request-ID` and `Idempotency-Replayed` (`false` for creation, `true` for a replay).

The full ten-code example is embedded in the OpenAPI response. The response object contains:

| Property | Meaning |
| --- | --- |
| `request_id` | Server-generated 32-character lowercase hexadecimal ID matching `X-Request-ID`; new for every HTTP attempt |
| `batch_id` | Stable batch identifier, 16 lowercase hexadecimal characters |
| `name`, `count` | Effective name and generated code count |
| `created_at`, `valid_from`, `valid_until` | Original creation and validity timestamps |
| `validity_seconds`, `access_seconds` | Normalized durations |
| `portal_url` | Canonical HTTPS portal root with trailing `/`; never contains a code |
| `replay_until` | Exclusive end of the 24-hour secret-response replay window |
| `key_retained_until` | End of the guaranteed 30-day retry-key retention window |
| `codes` | Exactly `count` objects, each containing stable `id` and secret `code` |

Identifiers and codes must be unique within the response. Newly generated codes use the existing `ABCD-EFGH` format and alphabet excluding ambiguous characters. Examples in the specification are synthetic, not usable codes.

Save codes securely when received. Ordinary batch/code reads, admin detail pages and logs cannot recover raw codes. The authenticated, short-lived replay below is the only exception. Do not cache responses, put codes in URLs, or include responses in support reports. No `Location` header is promised: batch-detail reads belong to the follow-up scope.

## Retry without generating extra codes

Create a fresh `Idempotency-Key` for each intended batch. Preserve that key and the request body before sending it. Reuse them only when retrying the same intended operation; do not use a credential or visitor code as a retry key.

The key is scoped to the integration credential ID and `createBatch`. The server applies defaults, converts whole numbers to integers, trims the name and normalizes duration units to seconds before fingerprinting. Object-property order and equivalent inputs such as 24 hours versus 1 day must not change the fingerprint. An omitted/empty name fingerprints as the empty value, before generating a display name. Unknown fields are rejected rather than ignored.

| Situation | Result |
| --- | --- |
| New valid key and request | Create one batch and return `201`, `Idempotency-Replayed: false` |
| Same key and normalized request before `replay_until` | Return original batch/codes with `201`, `Idempotency-Replayed: true` |
| Same key, different normalized request during retention | `409`, `idempotency_conflict`; no creation |
| Same key/request at or after `replay_until`, before `key_retained_until` | `409`, `replay_expired`, with original `batch_id`; no raw codes or creation |
| Invalid/expired/revoked credential or forbidden source/scope | Reject before disclosing any stored batch or replay result |
| Temporary storage/decryption problem or lock contention | `503` with `Retry-After`; no replacement batch |

Replay encryption uses a purpose-separated key derived from the existing application pepper. Back up configuration and database together using the normal encrypted backup workflow; copying only the database is insufficient to recover replay responses. Restore deliberately revokes integration credentials, disables API access and deletes replay records. Reconcile outstanding batches manually before issuing replacement credentials or operations. A normal update/restart preserves identity and replay state.

At most 50000 retry records are retained; capacity exhaustion fails with retryable `503`. Periodic activity maintenance and creation requests clear expired encrypted payloads and prune expired tombstones in bounded chunks. Cleanup lag cannot authorize a replay after its deadline.

The response payload is encrypted at rest and removed after 24 hours; a minimal key/fingerprint/batch tombstone remains for at least 30 days from creation. Replay checks the clock, so delayed cleanup cannot extend the replay window. A replay retains the original timestamps, code IDs, codes and deadlines; only `request_id` changes. It does not extend validity, undo revocation or reset redemption state. The payload is an issuance snapshot, not a live status response; already used/revoked codes may appear and remain unusable.

Concurrent identical requests must commit exactly one batch plus one replay record. A concurrent retry may wait briefly or return retryable `503`; it must never create a second batch. Rejected requests before a successful transaction do not consume the key. A failure after commit is recovered using the same key.

Always authenticate, check network policy and scope, and enforce request budgets on every retry. Replays count against request budgets but must not consume the new-code generation budget again. Lost-response retries after a credential rotation must not use the replacement credential as if it were the same identity.

After 30 days the server may prune the tombstone, and reusing that key might create a new batch. **Clients must never reuse old keys for a new operation or retry beyond `key_retained_until`.** Beyond the replay window, inspect/revoke the original batch through the administrator portal before intentionally replacing it with a new key. A restore can roll back batches and retry records together; reconcile outstanding operations after a restore before retrying. The runtime recovery guide must document replay-key backup and invalidation behavior in #48/#52.

## Errors and transport

All HTTP responses generated inside the configured API edge use JSON and `Cache-Control: no-store`. The application generates a fresh request ID rather than trusting a caller-supplied value. Body `request_id` and `X-Request-ID` match, including nginx-generated HTTP errors. Network failures, TLS handshake failures or an unrelated upstream proxy can have no API envelope; clients must treat an uncertain creation outcome as a retry of the same operation.

Example field error:

```json
{
  "request_id": "1234567890abcdef1234567890abcdef",
  "error": {
    "code": "invalid_request",
    "message": "The request is invalid.",
    "details": [
      {
        "field": "count",
        "code": "out_of_range",
        "message": "Count must be between 1 and 1000."
      }
    ]
  }
}
```

`details` is always present, is empty when no field detail is needed, and contains at most 16 safe entries. Error `batch_id` is present only for an authenticated `replay_expired` result. Never include request values, Authorization headers, SQL, stack traces, credentials or raw codes. Clients branch on status and `error.code`, not the human-readable message.

| HTTP | Machine codes | Client action |
| --- | --- | --- |
| `400` | `invalid_json`, `invalid_request`, `invalid_idempotency_key`, `invalid_host`, `insecure_transport` | Correct the request or canonical HTTPS address. Do not follow a redirect with the credential. |
| `401` | `unauthorized` | Correct/replace the credential. Includes `WWW-Authenticate: Bearer realm="Access Gate API"`. |
| `403` | `forbidden` | Check credential scope and effective-source network policy. |
| `404` | `api_disabled`, `not_found` | Check feature availability and path. A disabled API may return generic `not_found` rather than disclose configuration. |
| `405` | `method_not_allowed` | Use POST; includes `Allow: POST` on `/batches`. |
| `406` | `not_acceptable` | Permit `application/json` in Accept. |
| `409` | `idempotency_conflict`, `replay_expired` | Stop automatic retries; reconcile the original operation. |
| `413` | `request_too_large` | Reduce the body below 16385 bytes. |
| `415` | `unsupported_media_type` | Send uncompressed UTF-8 `application/json`. |
| `429` | `rate_limited` | Wait at least `Retry-After` seconds, then retry with the same key/body. |
| `500` | `internal_error` | Outcome may be uncertain; retry with the same key/body and bounded backoff. |
| `503` | `service_unavailable` | Wait at least `Retry-After` seconds; retain the same key/body. |

`Retry-After` is a positive integer number of seconds, at most 86400. Client retries need bounded exponential backoff and jitter; never substitute a new key merely because an HTTP request failed.

Validation order: enforce edge transport/host, feature/network and raw body/request budgets first; authenticate and authorize before decoding fields or looking up replay data; validate JSON/media type, schema and retry key before attempting creation. If several failures apply, an earlier protective check can win. A source/global rate limit can return `429` before credential verification. Requests exceeding edge limits may return `413` before authentication. Disabled/unknown routes return `404`; an existing route with an unsupported method returns `405`. No check may disclose another credential's replay record.

The API is opt-in. Public visitor-portal access must not automatically enable API access or expose administration. API routes use bearer authentication and independent network policy; they do not change `/admin/api/*`, `/internal/*` or `/gateway/v1/*`. Use the configured HTTPS origin, reject wrong host/scheme rather than redirecting secrets, and provide no permissive cross-origin browser access. Edge HTTP requests may be rejected before reaching the app; never send a bearer credential over HTTP to discover a redirect.

## Reserved follow-up operations

These are **reserved designs for #50**, not implemented operations. They are listed under `x-reserved-operations` rather than published as executable OpenAPI paths:

| Method and path below `/api/v1` | Scope |
| --- | --- |
| `GET /batches` | `batches:read` |
| `GET /batches/{batch_id}` | `batches:read` |
| `GET /batches/{batch_id}/codes` | `batches:read` |
| `POST /batches/{batch_id}/revoke` | `batches:revoke` |
| `POST /codes/{code_id}/revoke` | `batches:revoke` |

Reads and mutations are restricted to objects created by the same credential. A rotation creates a new identity; managing older batches remains possible through the admin UI. Ordinary reads must never return raw codes, browser cookies, visitor IPs or browsing history. Unknown and non-owned objects use the same `404` response. Revocation is safe to repeat.

For future collection reads, reserve `page_size` (integer 1–100, default 25) and `cursor` (opaque, 1–256 characters when supplied). Responses use `items` and `next_cursor` (opaque string or `null`), with deterministic descending creation-time/identifier order. Reject invalid/foreign cursor contexts; never encode secrets in cursors. Concurrent changes need not provide a snapshot, so clients deduplicate identifiers. #50 must define item/filter/cursor schemas in OpenAPI before exposing those routes. No pagination parameters are accepted by batch creation.

## Compatibility and validation

Breaking changes require `/api/v2` or a pre-release contract revision explicitly noted before the first API release. Additive v1 operations and optional response fields are allowed; clients must ignore unrecognized response properties. Servers reject unknown request properties to prevent typo-driven defaults. The current specification closes response objects to catch accidental data leakage during validation; update the schemas and tests when deliberately adding response fields. Machine error codes and existing meanings remain stable; clients must still handle unfamiliar codes as failures.

Validate the contract without starting Access Gate:

```bash
python3 -m venv /tmp/access-gate-contract-venv
/tmp/access-gate-contract-venv/bin/pip install -r tests/requirements-contract.txt
/tmp/access-gate-contract-venv/bin/python -m unittest discover -s tests -p 'test_api_contract.py' -v
```

The checks validate OpenAPI structure, local references, examples, unit-dependent boundaries and error contracts. They do not claim a working HTTP API. Runtime authentication, concurrency, deployment and end-to-end tests belong to #46–#51. Full operator setup and executable integration examples belong to #52.

[Documentation overview](README.md) · [Project README](../README.md)
