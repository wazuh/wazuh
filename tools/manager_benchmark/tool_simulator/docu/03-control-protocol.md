# 03 — The control protocol (`POST /control`)

In 5.x an agent's control traffic — "I started", "I am alive", "I am stopping" — is HTTP: a single
authenticated route on remoted, `POST /control`, whose body is JSON discriminated by a `"type"`
field. This is the manager's real hot path (one `notify` per agent per interval, forever), so the
`agent` mode sends it for real; it is also the endpoint whose behavior at fleet scale F9c-4 must
report on.

Source of truth: `src/remoted/remoted_module/src/endpoints/controlEndpoint.cpp` and
`src/remoted/remoted_module/src/control/controlHandler.cpp`.

## Authentication — no exception for this route

`/control` goes through the SAME authenticated gateway as `/stateful` and `/stateless`. The sender
therefore **MUST**, for every control request:

- send `protocol-version: 1`;
- send `Authorization: Bearer <wazuh-agent+jwt token>`, a fresh token per request minted with the
  agent's key as described in [04-wire-protocol.md](04-wire-protocol.md).

The **agent id the manager uses is the token's verified `sub`**, not anything in the JSON body. The
body carries no identity field at all, so a sender that signs with agent A's key while describing
agent B in the payload is simply agent A as far as the manager is concerned.

Failure modes are the gateway's, not the endpoint's: every credential problem (missing/malformed
`Authorization`, unknown agent, expired or future timestamp, bad MAC) collapses to `401` with one
opaque message. A `401` during a benchmark run **MUST** be treated as a sender bug and fail the run,
not counted as load.

## The three message types

### `startup`

Sent once, when the simulated agent comes up.

```json
{"type": "startup", "version": "5.0.0"}
```

`version` is the only field. The manager validates it (a version regex, then a numeric comparison
against its own version unless `allow_higher_versions` is set) and answers:

```json
{
  "limits": { "...": "manager-side limits" },
  "cluster": { "name": "cluster01" },
  "agent": { "groups": ["default"] }
}
```

Errors: `400 {"error":"invalid_version"}` when the version is malformed,
`409 {"error":"invalid_version"}` when it is well-formed but too new for the manager's
`allow_higher_versions` policy, and `503 {"error":"dependency_unavailable","dependency":"wazuh-db"}`
when wazuh-db does not answer (`controlHandler.cpp`).

`cluster.name` is where a REAL agent learns the value it later echoes in `Start.cluster_name` (it
stores it as `agent_metadata_t.cluster_name`, "received during handshake"). The sender discards it,
like every other field of this reply: `cluster_name` comes from the run configuration, because a
mismatch is answered `403` and the value belongs to the environment. There is no cluster node in
the reply or in `Start` — see [05-flatbuffers-messages.md](05-flatbuffers-messages.md).

The sender **MUST** send a version the manager accepts so that `startup` failures are never mistaken
for load effects. It is `defaults.control.startup_version` in the scenario, `5.0.0` when absent (the
manager's own version on this branch, `VERSION.json`).

### `notify` — the keepalive

Sent periodically for the lifetime of the agent. Every field below is optional; the sender
**SHOULD** send the full shape, because a `notify` carrying `host` is the more expensive one on the
manager side (it triggers the full agent-data write rather than a bare keepalive) and is what a real
agent sends:

```json
{
  "type": "notify",
  "agent": { "version": "5.0.0" },
  "host": {
    "hostname": "bench-0001",
    "ip": "127.0.0.1",
    "architecture": "x86_64",
    "os": { "name": "Ubuntu", "version": "24.04", "platform": "ubuntu", "type": "Linux" }
  }
}
```

Response:

```json
{
  "agent": {
    "groups": ["default"],
    "config_token": "<opaque /download resource_id>",
    "config_hash": "<sha or \"0\">"
  },
  "settings_hash": "<sha256 hex>",
  "ca_generation": 0,
  "tasks": [ { "task_id": 1, "task_type": "...", "payload": {} } ],
  "vd_feed_offset": 849527
}
```

`ca_generation` is present only on a manager whose HTTPS listener provides it (`null` when there is
no servable CA bundle). `vd_feed_offset` is the node's current VD feed offset, the one field the
sender reads (see [below](#what-the-sender-does-with-the-response)).

Errors: `400 {"error":"invalid_host_info"}` when a field exceeds its bound — hostname ≤ 255, ip
≤ 45, and the architecture/os fields ≤ 128 bytes (`controlTypes.hpp`). The sender's generated
hostnames and metadata **MUST** stay inside those bounds. `503
{"error":"dependency_unavailable","dependency":"wazuh-db"}` when the agent's groups must be
refreshed, wazuh-db does not answer, and remoted has no cached membership for that agent.

Two behaviors worth exploiting in scenarios:

- **`notify` does NOT validate the agent version** (only `startup` does), so version-mismatch
  scenarios must go through `startup`.
- **`notify` does NOT require a previous `startup`**: the manager creates its in-memory registry
  entry on the fly. A scenario **MAY** therefore model a fleet that only keepalives, to isolate the
  cost of the notify path from enrollment and startup.

### `shutdown`

Sent during drain, once per agent.

```json
{"type": "shutdown"}
```

The response is the literal `{}`. The manager answers **before** marking the agent disconnected in
wazuh-db (fire-and-forget), so a `200` here says "accepted", not "state updated" — the sender
**MUST NOT** poll for the disconnected state as if it were synchronous.

### Endpoint-level rejections

Independent of type: `400 invalid_body` (empty body, or larger than 64 KiB),
`400 invalid_json` (not parseable, or not a JSON object), `400 invalid_agent_id` (the id in
`Authorization` is not a plain integer), `400 unknown_message_type` (a `type` other than the three
above). All four are sender bugs and **MUST** fail the run.

As implemented, the sender is stricter than that for `startup` and `notify`: **any** status other
than `200` (a `503` from wazuh-db too) invalidates the run (exit `1`). A `shutdown` answer is only
counted (`control_shutdown_ok`/`_err`). A transport error on a `notify` is counted as
`control_notify_err` and the loop continues.

## Cadence

| Knob | Value | Where |
|---|---|---|
| Real agent keepalive interval | **10 s** by default | `NOTIFY_TIME` in `src/shared/include/defs.h`, overridable with `<client><notify_time>` in the agent's `ossec.conf` |
| Sender default | **10 s**, `defaults.control.keepalive_interval` in the scenario JSON | Matches the agent so a fleet of N produces the real N/10 requests per second. The first notify of each agent is sent immediately, then one per interval |
| Manager write throttle | **60 s** | `kKeepaliveThrottleSec` (`src/remoted/remoted_module/src/control/controlConfig.hpp`): how often a `notify` actually writes to wazuh-db |
| Manager groups refresh | **60 s** | `kGroupsRefreshIntervalSec`, same file |

The throttle matters for interpreting results, not for behavior: it does not slow the response, but
it means a keepalive interval below 60 s produces cheap notifies most of the time and an expensive
one periodically. A run whose interval is much shorter than 60 s therefore measures mostly the cheap
path — the notify-storm scenario **SHOULD** report both, and F9c-4 **MUST** state the interval used.

## What the sender does with the response

**Validate and mostly discard.** For each control request the sender **MUST**:

1. record the status code (and fail the run on `401` or any `400`; as implemented, on any
   non-`200` answer to `startup` or `notify`);
2. assert the body parses as JSON — a malformed body is a server regression and **MUST** be
   reported;
3. record the response latency and byte size into the metrics for this request type.

And it **MUST NOT** use any field of the body to change what it does next, with exactly ONE
exception: `limits` does not become a rate limit, `agent.groups` does not reach the sessions'
`Start.groups`, `config_hash`, `config_token` and `settings_hash` are not compared across requests
or turned into a `/download` call, and `tasks` are never executed or acknowledged. The reasons are
two: a load generator whose shape depends on the system under test produces incomparable numbers
between runs, and consuming that payload would make the tool a conformance checker for a contract
that is not what this benchmark measures.

The exception is `notify`'s `vd_feed_offset`: it is the one piece of server state a real agent
DOES act on (deciding when to request a VD re-scan through `POST /scan/vd` — see
[14-scan-vd.md](14-scan-vd.md) and
[remoted's https-events-api.md](../../../../docs/ref/modules/remoted/https-events-api.md#scan-endpoint-post-scanvd)),
and VD sessions' `Start.feed_offset` must match the server's current offset or they are rejected
with `409 version_mismatch` before ever reaching the scanner (see
[05-flatbuffers-messages.md](05-flatbuffers-messages.md)). Not tracking it would not make the
sender's shape independent of the system under test — it would make every `agent`-mode VD scenario
send sessions the server is guaranteed to reject once its feed has moved past offset 0, which
measures the version_mismatch fast-path instead of the scan lane. The sender therefore stores the
latest `vd_feed_offset` per agent (updated on every successful notify) and uses ONLY that one value
when building a VD session's `Start.feed_offset` — nothing else about session content, pacing or
routing depends on any control response.

A scenario **MAY** ask for a sample of control responses to be written to an artifact for manual
inspection; that is evidence in the report, still not behavior. **Not implemented:** the scenario
schema has no such field, and the sender writes no control response anywhere.
