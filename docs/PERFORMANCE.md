# Gateway performance

Open **System status → Gateway performance** as an administrator. `/admin/api/performance` returns the same authenticated snapshot. Counters, fixed histograms and process identity reset on restart/update. Measurements contain no hostname, client address, URL, code, cookie or key. There is no persistent performance history.

Stages separate policy lookup, certificate hit/miss lookup, signing/context generation, renewal, live authorization, origin DNS, origin connection/TLS, origin response headers and portal response headers. Connect/TLS includes nested DNS time; do not add those two figures. Header timings measure waiting for upstream headers, not a complete page download or the client's handshake. P50/P95 are fixed histogram upper bounds, not exact percentiles. Null means no samples or an overflow above 30 seconds. Collection never waits on a contended metrics lock; dropped samples are counted.

## Repeatable baseline

On the gateway, with permissions to read its existing configuration and issuer key:

```sh
cd /opt/access-gate
python3 -m access_gate.benchmark_tls --hostname restricted.example --iterations 20
```

Replace the example with an enabled restricted hostname. This builds an isolated in-memory cache, measures one cold and repeated warm SNI callbacks, and leaves the running cache and access grants alone. It uses the actual configured local/remote policy authority. Record version, machine, local/remote mode and repetitions. It excludes client network TLS, page assets and origin forwarding.

For real-client measurements, use a test client that trusts the gateway CA:

```sh
curl --noproxy '*' --cacert root.crt --resolve restricted.example:443:GATEWAY_IP -o /dev/null -sS -w 'connect=%{time_connect} tls=%{time_appconnect} headers=%{time_starttransfer} total=%{time_total}\n' https://restricted.example/
```

Replace hostname/IP, repeat immediately for a warm result, then run a small controlled batch (for example 10 parallel curl processes). Record redirect status: a restricted visitor measures the portal handoff, not an authorized origin fetch. For the latter use an isolated test browser session and the browser network panel; do not publish its cookies. Never clear a production cache just to benchmark it. A controlled test-process restart gives the cold baseline.

For background renewal compare the renewal count/duration and concurrent warm requests before/after the fixed cache age. Automated fake-clock tests exercise that boundary without waiting a day. Target-server measurements and phone/browser validation must be collected on that installation; local fixture timings are not production promises.

## Development baseline (#31)

Measured in the development container with Python 3.12, aiohttp 3.9.1 and cryptography 41.0.7, a real loopback Flask policy server, generated test CA and one enabled synthetic hostname: cold callback 4.70 ms; 10 warm callbacks mean 2.86 ms, maximum 4.96 ms. Each warm callback still creates a policy HTTP connection in this baseline. These numbers are fixture results, not measurements of a deployed server or remote WAN authority.

## Policy snapshots (0.23)

The gateway loads an authenticated complete rule snapshot before opening listeners. Local mode uses the loopback API key; remote mode uses verified HTTPS and gateway mTLS credentials. Network reads are asynchronous, capped at 64 MiB/500,000 rules; parsing runs off the event loop. Exact and suffix sets are immutable and swapped atomically. The TLS callback and HTTP handler only read memory.

Edits are normally visible at the next two-second refresh (plus request/parse time). Maximum snapshot age is ten seconds. A malformed response or outage retains the last good snapshot only within that age; stale SNI is rejected, including previously cached certificates. Authentication rejection invalidates immediately when observed. Startup fails without a valid snapshot; an authenticated empty rule set is valid and rejects all intercepted hosts. Freshness and refresh errors appear in administrator performance diagnostics. No snapshot is persisted.

Policy freshness never grants access. Code/admin state, domain removal, peer revocation and streaming deadlines still use the live authority checks. Existing streams are stopped by their normal live checks during an outage.

With the same local fixture after #32, cold callback was 1.36 ms and 10 warm callbacks averaged 0.053 ms (maximum 0.199 ms). Initial authenticated snapshot loading occurs outside the callback timing. The earlier #31 warm mean was 2.86 ms. This shows removal of the loopback API roundtrip; it does not predict WAN/page-load performance. Concurrent refresh and slow-parser tests also verify that immutable warm lookups remain available while background work awaits network/worker execution.

## Certificate lifecycle (0.24)

Intercepted website leaves expire 48 hours after generation (with five minutes of not-before clock-skew allowance). Their TLS contexts live in a process-local LRU of at most 256 entries. Age is measured from creation; hits do not extend it. Eviction can shorten residency. Restart/update intentionally empties the cache; no leaf database or persistent private-key cache is created. The short-lived PEM used to load OpenSSL is removed immediately.

One background worker checks cached entries every minute and starts renewal five minutes before their fixed 24-hour age. It signs/loads outside the event loop, deduplicates by cache key and swaps a completed context atomically. During a slow/failed replacement, a still-valid old context may be used for at most five minutes beyond the 24-hour age. It is never reused beyond its cryptographic expiry. An evicted entry is not resurrected by a late worker. Shutdown cancels the loop, waits for the bounded worker off the event loop and clears RAM state.

Cold misses still sign synchronously in Python's SNI callback; background renewal removes ordinary warm-cache expiry stalls, not first-ever signing cost. Only visited entries are created; imported lists are not pre-generated. Renewal has its own aggregate timer/failure count. All visitors share the same cached context; that context never caches or extends a visitor's live authorization.

Signing requires at least 48 hours plus five minutes of issuer lifetime. Otherwise it fails explicitly; use the normal installer/updater issuer provisioning path. The retained device root CA, public-portal TLS and gateway enrollment certificates have their own lifecycles and are unchanged by this setting.

## Wildcard groups (0.25)

Each intercepted certificate contains a base DNS SAN and one wildcard SAN. Under a suffix rule for `example.com`, the apex and direct children such as `www.example.com`/`api.example.com` share the `example.com` + `*.example.com` context. `images.api.example.com` and `other.api.example.com` share the separate `api.example.com` + `*.api.example.com` context. A wildcard matches exactly one label; see [RFC 9525 §6.3](https://www.rfc-editor.org/rfc/rfc9525.html#section-6.3).

The most-specific configured matching rule defines the boundary. An exact-only rule uses its own hostname as base; its wildcard SAN does not permit child names. Every SNI and every HTTP request still checks the actual requested hostname and every authorized request uses live access checks. Adding more-specific scopes may split groups, without broadening policy. Unicode rule names use the shared IDNA normalization.

The installer explicitly installs `libpsl5`. The gateway uses its offline built-in Public Suffix List (ICANN and private suffixes), maintained through Ubuntu package updates; there is no suffix download in a handshake. `co.uk`, `github.io` and other suffix bases are rejected, including a rule that tries to use such a suffix as its boundary. Add actual tenant/domain roots instead, such as `example.co.uk` or `alice.github.io`. Missing suffix data/library fails startup rather than falling back to a last-two-labels guess. See [libpsl](https://github.com/rockdaboot/libpsl).

Real TLS fixture validation in the development container: ten concurrent sibling connections completed in about 91 ms and all received the same certificate, with one signing operation total. This includes local client/server TLS scheduling and is not a server/network performance guarantee. Automated tests verify deeper wildcard mismatch rejection by the TLS verifier itself, safe separate deep groups and exact/unmanaged-domain rejection with an already warm cache. The 48-hour validity / 24-hour RAM lifecycle and live grant deadlines remain unchanged.

A second isolated fixture compared ten sibling callbacks using a per-hostname cache against grouping: ten signing operations versus one; about 13.9 ms total versus 1.9 ms in that run. The comparison uses the same certificate generator and CA on the same local machine, and measures callback/context work rather than browser page loads.
