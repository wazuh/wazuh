# Wazuh DB API Reference

All routes are served over a Unix domain socket at `queue/sockets/wdb-http.sock`, relative to the
installation directory. There is no TCP listener, and the socket is manager-internal: its callers
are `clusterd` and the framework (`wazuh.core.wdb_http` for the data routes, `WazuhDBStatusHTTPClient`
in `wazuh.core.engine_http` for `/v1/status`), never an agent. Socket permissions are the whole access
control; there is no authentication.

This is the REST interface. The daemon also serves the older framed protocol on
`queue/sockets/wdb.sock`, documented in [the module README](README.md#socket-protocol); the two are
independent and neither is a wrapper of the other.

Requests are HTTP/1.1 over the socket. The router is **exact-match**: there are no path parameters,
so an agent id travels in a header (`X-Wazuh-Agent-Id`) rather than in the path.

## Routes

| Method | Path | Success | Notes |
|---|---|---|---|
| `GET` | `/v1/status` | `200` | Readiness: can this daemon serve? See [`GET /v1/status`](#get-v1status). `503` when it is running but the global database cannot answer. |
| `GET` | `/v1/agents/groups` | `200` | The groups one agent belongs to, in priority order. Requires the `X-Wazuh-Agent-Id` header; `400` without it or when it is not a numeric agent id. |
| `GET` | `/v1/agents/all` | `200` | Every agent with every field, `id` ascending. |
| `POST` | `/v1/agents/summary` | `200` | Counts of agents by status, by group and by OS, for all agents or for the ids in the body. |
| `GET` | `/v1/agents/sync` | `200` | The agents whose `sync_status` marks them as pending, and **marks them synced** as a side effect. |
| `POST` | `/v1/agents/sync` | `200` | Applies an agent state update sent by another node. Empty body on success; `400` on a malformed body. |

Every route answers `500` when the database connection cannot be obtained, and `500` when the
handler throws — except `/v1/status`, which answers `503` in both cases, because for that route
being unable to serve is the answer rather than a fault.

The transport answers before any handler runs for a request no route serves: a path none of the
rows above lists is `404 Unknown endpoint`; a listed path with another method is `405 Method not
allowed for this endpoint`, with an `Allow` header naming the methods it does serve. Both are logged
as one `WARNING` per 90 s window under the `wazuh-manager-db` tag (`Answered N request(s) … with
404: no route for …`). A declared `Content-Length` larger than the server could ever admit is refused
with `413` at the headers, before any body byte is read; `GET /v1/agents/groups` additionally caps a
body at 64 KiB and `GET /v1/status` at 4 KiB, though neither takes one.

---

## `GET /v1/status`

Reports whether the global database can serve the queries this daemon exists to serve, so a caller
can know it **before** issuing one.

```console
$ curl -s --unix-socket /var/wazuh-manager/queue/sockets/wdb-http.sock http://localhost/v1/status
{"status":"ok","module":"wazuh-db","global":{"available":true}}
```

| Answer | Meaning |
|---|---|
| `200` | The global database answers and carries the schema an agent-groups lookup needs |
| `503` | The daemon is running but cannot serve: the database is unreachable, or that schema is absent |
| connection refused | The daemon is not running at all |

Those three are distinguishable on purpose: a readiness aggregator has to tell "not running" from
"running but unable", and they call for different operator action.

On `503` the body names what is missing:

```json
{"status":"unavailable","module":"wazuh-db","global":{"available":false,"missing_tables":["belongs","group"]}}
```

When the database could not be opened or queried at all, `missing_tables` is the empty list `[]`, and
the daemon logs `Status endpoint could not query the database: <reason>` when the query itself failed.

It checks that the `agent`, `belongs` and `group` tables exist — the tables agent-group lookups
read. `remoted` reads an agent's groups from the `agent` table with `global select-agent-group` on
`wdb.sock`, and a failure there makes it answer `503 dependency_unavailable` on `POST /control`;
[`GET /v1/agents/groups`](#get-v1agentsgroups) joins `belongs` and `group`. A `503` for missing
tables also logs a `WARNING` under the `wazuh-manager-db` tag (`Status answered unavailable N
time(s) in the last <s> s: the global database is missing expected tables.`, or `… so far: …` on
the first one), at most once per 90 seconds so a polling load balancer does not flood the log;
`<s>` is the real time since the previous such line.

**This is a readiness answer, not a liveness one.** A process that is up is not necessarily a
process that can work: `wazuh-manager-db` can be running and accepting connections on this socket
while being unable to query `global.db`. Before this route existed, that state was only observable
one request at a time, after an agent had already been served badly — a node in it kept answering
`remoted`'s liveness probe with `200` and stayed in a load balancer's rotation indefinitely
(issue #39429).

The check is deliberately cheap and read-only: it reads `sqlite_master`, not agent rows, and runs no
integrity check. A status route that is expensive stops being safe to poll, and whoever consumes
this will poll it.

---

## `GET /v1/agents/groups`

The groups one agent belongs to, ordered by group priority.

```console
$ curl -s -H 'X-Wazuh-Agent-Id: 7' --unix-socket /var/wazuh-manager/queue/sockets/wdb-http.sock http://localhost/v1/agents/groups
["default","linux"]
```

The body is a bare JSON array of group names, not an object.

The agent id travels in the `X-Wazuh-Agent-Id` header because the router is exact-match and cannot
carry it as a path segment. Without the header the route answers `400 Missing header:
X-Wazuh-Agent-Id` without touching the database. The value must be decimal digits only (leading
zeros allowed, as in `001`) within the signed 32-bit range; anything else — `abc`, `1abc`, `-1`, a
space, an overflow — answers `400 Invalid header: X-Wazuh-Agent-Id must be a numeric agent id`,
also without touching the database. Both rejections are logged as a `WARNING` under the
`wazuh-manager-db` tag at most once per 90 seconds, with the count of requests the line stands for.

An agent that exists but belongs to no group answers `[]`; the route does not distinguish that from an
id that does not exist.

---

## `GET /v1/agents/all`

Every agent in `global.db`, ordered by `id` ascending, with a fixed set of 18 fields (credentials such
as `internal_key` and `reenroll_secret` are never included). Agent `0` (the manager itself) is excluded.

Field names are flattened with dots where the source is an OS attribute:

```json
[{"id":1,"name":"agent-a","ip":"10.0.0.7","status":"active",
  "os.name":"Ubuntu","os.version":"24.04","os.type":"linux","os.platform":"ubuntu",
  "version":"v5.0.0","dateAdd":"1789600454","os.major":"24","os.minor":"04","os.arch":"x86_64",
  "lastKeepAlive":"1789686854","registerIP":"10.0.0.7","disconnection_time":"0",
  "status_code":0,"group":"default,linux"}]
```

Two fields are aliases rather than columns: `ip` is `coalesce(ip, register_ip)`, so an agent that
never reported an address still answers the one it enrolled from, and `status` is
`connection_status`. Only `id` and `status_code` are numbers; everything else is a string, including
the three timestamps (`dateAdd`, `lastKeepAlive`, `disconnection_time`), which are Unix epoch seconds
written as text.

`group` is the agent's groups as one comma-separated string, not an array.

Empty fields are omitted rather than serialized as `""` or `null`, so two agents can answer with
different key sets. The response is unbounded — it is one row per agent, with no paging — which is
why it is classified as a data-plane route and can be shed under back-pressure.

---

## `POST /v1/agents/summary`

Counts for the server API's agent overview. The body is optional: empty, it counts every agent; a JSON
array of agent ids (for example `[1,2,7]`), it counts only those, so `[]` counts nothing and answers
`{}`. The id list is not parsed as JSON: the body is split into maximal runs of digits and `-`, and
each run's leading integer is taken as an id when it fits a 32-bit `int` (a run that does not is
dropped). A leading `-` is part of the number, so `[-1]` names no agent rather than agent 1, and
`1-2` names agent 1 only. Answers three maps:

```json
{"agents_by_status":{"active":42,"disconnected":3},
 "agents_by_groups":{"default":40,"linux":12},
 "agents_by_os":{"ubuntu":38,"windows":7}}
```

`agents_by_os` is keyed by `os_platform`, and agents without one are not counted there. Empty maps
are omitted entirely — an installation with no agents answers `{}`.

With an id list every entry is returned. With an empty body each map is capped at five entries, and
the orderings differ, which matters when there are more than five:
`agents_by_groups` and `agents_by_os` keep the five **largest** (`ORDER BY quantity DESC`), while
`agents_by_status` keeps the five **first alphabetically** (`ORDER BY status ASC`). There are
fewer than five connection statuses in practice, so that cap does not bite today, but the ordering
is not the one the other two use.

---

## `GET /v1/agents/sync`

Returns the agents the cluster still has to replicate, grouped by what changed, and **marks every
agent synced as a side effect of answering**.

```json
{"syncreq":[{"id":7,"name":"agent-a","ip":"10.0.0.7","os_name":"Ubuntu","os_version":"24.04",
             "os_major":"24","os_minor":"04","os_type":"linux","os_platform":"ubuntu",
             "os_arch":"x86_64","version":"v5.0.0","last_keepalive":1789686854,
             "connection_status":"active","disconnection_time":0,"status_code":0}],
 "syncreq_keepalive":[{"id":9,"version":"v5.0.0"}],
 "syncreq_status":[{"id":11,"version":"v5.0.0","connection_status":"disconnected",
                    "disconnection_time":1789686854,"status_code":0}]}
```

The three keys are the three **pending** `sync_status` values (`syncreq`, `syncreq_keepalive`,
`syncreq_status`); the fourth the column holds, `synced`, is what this route writes. Empty groups
are omitted.

**The side effect matters.** Answering this route runs `UPDATE agent SET sync_status = 'synced'`
over every agent, so a caller that reads the response and then fails to act on it loses the work:
those agents will not be offered again. It is a destructive read, not a query, and the only caller is
`clusterd` on a worker node, which sends the result to the master (where it lands on
[`POST /v1/agents/sync`](#post-v1agentssync)).

---

## `POST /v1/agents/sync`

Applies an agent state update produced by another cluster node. The body is the shape
`GET /v1/agents/sync` returns, and each of its three groups is applied with its own statement, keyed
by `id`:

| Group | Writes |
|---|---|
| `syncreq` | `ip`, `name`, the OS fields, `version`, `last_keepalive`, `connection_status`, `disconnection_time`, `status_code` |
| `syncreq_keepalive` | `last_keepalive` = now, `connection_status` = `active`, `disconnection_time` = 0, `status_code` = 0, `version` |
| `syncreq_status` | `connection_status`, `disconnection_time`, `status_code`, `version` |

A field absent from an entry is written as an empty string or `0`. Every applied row is left
`sync_status = 'synced'`. The caller is `clusterd` on the master.

Success answers an **empty body** with `200`, not a JSON document.

A body that is not valid JSON, an entry without `id`, or a field of the wrong type is answered
`400 Malformed request body` (`text/plain`). Numbers are converted rather than checked: in a numeric field
(`id` included) a fraction is truncated (`99999.5` reads as `99999`) and a boolean reads as `1` or `0`
(`"id": true` addresses agent 1), so only a string, an array, an object or `null` there is the wrong type.
A text field takes only a string. Every 400 is logged as one WARNING under the `wazuh-manager-db`
tag, throttled to one line per 90 s window that carries the count and the route, never the body:
`Rejected <n> request(s) to /v1/agents/sync with 400 so far|in the last <s> s: malformed request body.`
Nothing is written for a body that does not parse; for an entry that fails later, the entries
applied before it stay applied (the groups are not one transaction).
