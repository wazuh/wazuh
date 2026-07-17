# SPIKE #37738 — agent HTTPS client PoC

A self-contained proof of concept for the agent-side HTTPS transport. It is
**not** wired into any daemon and is **not** part of the agent build — it is a
spike artifact (deliverable D10/T12) that exercises the proposed contract end to
end against a mock manager, and de-risks the ADR-1 library choice empirically.

Built after the team proposals landed (2026-07-17), so it targets the *proposed*
contract, not the earlier assumption register:

* **Auth** — AES-CMAC request signing (#37732): `Authorization: Wazuh <id>:<ts>:<mac>`
  over the canonical request `WAZUH-REQUEST\n1\nMETHOD\ntarget\nid\nts\nbody`.
* **/stateless** — H/E batch wire format.
* **/stateful** — one `FullSession` POST, streamed from a spooled file; retries
  reuse the same session id and get the manager's cached result (#37733 §2.8).
* **/control** — Startup (handshake JSON) / Notify (pull tasks + config) / Response.
* Synchronous everywhere; retry with re-sign + full-jitter back-off; honor
  `503 + Retry-After`; TLS verification per DEC-6 (CA file + hostname).

## What it demonstrates (why it matters for the spike)

| Claim from the design | Proven by |
|---|---|
| libcurl is sufficient as the engine, no Boost (ADR-1) | the whole client is C over libcurl + libcrypto |
| AES-CMAC signing interoperates | client signs with OpenSSL `EVP_MAC`; the mock verifies with the **openssl CLI** — two independent implementations agree |
| A tampered request is refused | `tamper` scenario → `401` |
| Large `/stateful` needs no big buffer (#37738 §6) | 3 MB session streamed from a temp file via `CURLOPT_READFUNCTION` |
| Whole-session retry + dedup (no ReqRet) | same `X-Session-Id` → cached result |
| Back-pressure is honored | `503 + Retry-After` → client backs off and retries → `200` |
| TLS validation modes (DEC-6) | `HC_VERIFY_FULL` against the generated CA |
| One thread per endpoint doesn't block (D5) | `hc_poc_mt`: 3 endpoint threads + dispatcher; a 4 s `/stateful` runs while `/stateless` + `/control` keep completing; ThreadSanitizer-clean |

## Layout

```
include/hc_client.h     the D3 hc_* interface (opaque handle + injected callbacks)
src/hc_cmac.c/.h        canonical request + AES-CMAC (OpenSSL EVP_MAC)
src/hc_client.c         libcurl transport: stateless/stateful/control, retry, streaming
src/main.c              driver: scripted scenario standing in for the agentd seams
src/main_mt.c           multi-threaded driver: 3 endpoint threads + dispatcher (D5)
mock_manager/           python3 TLS server (CMAC middleware + 3 endpoints)
mock_manager/mocks/     D10 canonical request/response examples per endpoint
Makefile  run.sh
```

## Run it

```sh
./run.sh          # generates certs + key, starts the mock, builds, runs 5 scenarios
```

Scenario 5 is the concurrency demo: the mock runs with `--slow-stateful 4` and
`hc_poc_mt`'s timestamped output shows `/stateless` and `/control` completing
while one `/stateful` request is held open for 4 s. Run just that binary with:
`./hc_poc_mt <base_url> 001 <key_hex> <ca> <seconds>`.

Requirements: a C compiler, libcurl + OpenSSL 3.x dev libs, python3, the
`openssl` CLI. On macOS the Makefile finds Homebrew `openssl@3`/`curl`
automatically. Nothing is installed system-wide; all run artifacts land in
`.poc_run/` (gitignored).

## Relationship to production

The client is written in **C** to match the parallel #37738 proposal (Nicogp);
whether the production agent client is C or C++ is an open team decision (tension
T1). Either way, the shape here maps onto the D2/D3 design: `hc_submit_event` is
the `EventForward` seam, `hc_submit_sync_session` is fed by the STREAM-socket +
spool path, and the callback table is how received tasks reach the existing C
dispatch handlers. Production would link the vendored `external/curl` +
`external/openssl` through `libwazuhext` (as the C `wurl` client does today)
rather than the system libraries this PoC uses for portability.
