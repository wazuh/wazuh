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
generic message (the classes are in
[remoted's https-events-api.md](../../../../docs/ref/modules/remoted/https-events-api.md#error-responses)).
A `401` during a benchmark run is treated as a sender bug or an unloaded key and fails the run, not
counted as load — except while the fleet waits for remoted to load its keys
([06](06-agent-state-machine.md)), when `startup` retries it.

## The three message types

### `startup`

Sent once per agent before its lanes start (only when `defaults.control.enabled`), retried every
2 s while it is answered `401` within the readiness budget ([06](06-agent-state-machine.md)). The
fleet-wide readiness probe also sends one `startup`, for the fleet's first agent, whether or not
control is enabled.

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

Sent periodically for the lifetime of the agent's lanes. Every field below is optional on the
manager side. The sender always sends `agent.version` (the same `startup_version`) and adds the
`host` block only when the scenario sets `defaults.control.send_host_info: true` (default `false`).
A `notify` carrying `host` is the more expensive one on the manager side (it triggers the full
agent-data write rather than a bare keepalive) and is what a real agent sends, so a scenario
modelling a real fleet sets it. The block is filled from the fleet's `start` metadata with the same
built-in fallbacks as `Start` ([05](05-flatbuffers-messages.md#start)), the agent's name as
`hostname` and a fixed `ip` of `127.0.0.1`:

```json
{
  "type": "notify",
  "agent": { "version": "5.0.0" },
  "host": {
    "hostname": "bench-linux-2000",
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
    "config_token": "<group selector; 5.x agents ignore it>",
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

Two manager behaviors worth knowing when reading results:

- **`notify` does NOT validate the agent version** (only `startup` does), so version-mismatch
  scenarios must go through `startup`.
- **`notify` does NOT require a previous `startup`**: the manager creates its in-memory registry
  entry on the fly. The sender cannot model such a fleet, though: with control enabled every agent
  sends its `startup` before its first `notify`.

### `shutdown`

Sent once per agent, after all of its lanes have returned (they finished, or the run is draining).

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
above). All four are sender bugs.

The sender does not tell these apart from the per-type errors above
(`internal/control/control.go`): for `startup` and `notify`, **any** status other than `200` — a
wazuh-db `503` too — and any `200` whose body is not JSON invalidates the run (exit `1`); so does a
transport error on `startup`. A transport error on a `notify` is counted in `control_notify_err`
and the loop continues. A `shutdown` answer is only counted (`control_shutdown_ok`/`_err`).

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

**Validate and mostly discard.** For each control request the sender:

1. records the outcome in `control_<type>_ok`/`_err` (and fails the run on any non-`200` answer to
   `startup` or `notify`);
2. requires a `200` body to parse as JSON — a malformed body is a server regression, and for
   `startup`/`notify` it fails the run;
3. records the response latency in the `startup`, `notify` or `shutdown` histogram (no response
   size is recorded).

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
