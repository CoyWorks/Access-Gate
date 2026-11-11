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
