# Authd Architecture

## Overview

`wazuh-manager-authd` owns the agent keystore. It hands out agent ids and keys, persists them to
`client.keys`, mirrors every registration into Wazuh DB, and makes sure a removed agent's documents
leave the indexer too. Enrollment arrives through three doors — the TLS port on 1515, remoted's
authenticated `/enroll` route and the server API — and all of them converge on the same in-memory
keystore behind one mutex: the last two both arrive over the local Unix socket.

```mermaid
flowchart TB
    AG[Agent] -->|"enrollment (TLS 1.3, port 1515)"| REMS
    REM2[wazuh-manager-remoted\nPOST /enroll] -->|"add (UDS)"| LOCS
    API[wazuh-manager-apid\nserver API] -->|"add / remove / get (UDS)"| LOCS

    subgraph AUTHD["wazuh-manager-authd"]
        REMS[Remote server thread]
        LOCS[Local server thread]
        KS[(in-memory keystore\nkeys + id counter)]
        QR[queue_remove\nqueue_insert]
        WR[Writer thread]
        PJ[(deletion journal\nin memory)]

        REMS -->|"under mutex_keys"| KS
        LOCS -->|"under mutex_keys"| KS
        KS --> QR
        QR --> WR
        WR -->|"1. journal the intent"| PJ
    end

    PJ <-->|"every change, atomically"| PF[(queue/authd/pending-purges\nwhat a crash is reconciled against)]

    WR ==>|"2. rewritten whole, atomically"| CK[(client.keys)]
    WR -->|"delete-agent"| WDB[(wazuh-db)]
    WR -->|"3. create the deletion task\n4. drop the journal line"| MT[(tasks.db\nMANAGER_TASKS)]
    MT --> DISP[Task Manager dispatcher\nmodulesd]
    DISP -->|"POST /_internal/agents/delete (UDS)"| ISS[inventory_sync_server\nmodulesd]
    ISS -->|"deleteByQuery + flush"| IDX[(wazuh-indexer)]
    CK --> REMOTED[wazuh-manager-remoted\nauthenticates agents]
```

The load-bearing property of this layout is that **the writer thread never waits on anything it does
not own**. It is the only thread that persists `client.keys`, and remoted authenticates agents by
reading that file, so anything slow in the writer's pass delays every enrollment — including agents
unrelated to the work in progress. That is why the indexer purge sits behind a queue and a second
thread instead of being called inline.

## Threads

| Thread | Runs on | Role |
|---|---|---|
| Remote server | any node with `remote_enrollment` | TLS enrollment on port 1515 |
| Local server | every node | `queue/sockets/auth.sock`: `add`, `remove`, `get` — for the server API and for remoted's `/enroll` |
| Writer | master only | persists `client.keys`, removes Wazuh DB rows, records each deletion as a Task Manager task |
| authpass watcher | workers with `use_password` | re-reads `etc/authd.pass` as the cluster syncs it down from the master |

## The two stores

authd keeps every key in **two** places, and the difference between them explains most of the
module's behaviour — and most of its surprises.

```mermaid
flowchart TB
    G["authd generates a key"] --> MEM
    MEM[("in-memory keystore\ncurrent from the instant the key exists")]
    MEM -->|"answers the enrolling agent"| AG[Agent]
    MEM -.->|"the writer copies it\nCAN LAG"| CK[("etc/client.keys")]
    CK --> REM["remoted\nauthenticates every agent request"]
    MEM --> AUT["authd itself\nduplicates, agent limit, force rules"]
```

- **The in-memory keystore** (`keys`, guarded by `mutex_keys`) is authoritative *inside* authd. It is
  where `OS_AddNewAgent()` assigns the id, where duplicate checks look, and where the key the agent
  receives comes from. It is current the moment a key exists.
- **`etc/client.keys`** is how the rest of the manager finds out. Only the writer thread rewrites it,
  and **remoted authenticates agents by reading it** — so an agent whose key has not reached the file
  yet is rejected as unknown (`401`), even though the key it holds is perfectly valid.

**Enrollment latency is the writer's pass time plus remoted's reload.** That is the reason nothing
slow may live in the writer's pass, and the reason the indexer purge sits behind a queue and a second
thread instead of being called inline.

On a **worker node** the gap is structural rather than incidental — see [Cluster](#cluster).

## Enrollment

Three doors converge on the same code. The TLS port on 1515 is served by the remote server thread;
remoted's authenticated `POST /enroll` and the server API both arrive over the local Unix socket.

```mermaid
sequenceDiagram
    participant C as Caller<br/>(agent · remoted /enroll · server API)
    participant T as Serving thread
    participant KS as In-memory keystore
    participant W as Writer thread
    participant CK as client.keys
    participant R as remoted

    C->>T: enroll (name, version, ip?, groups?, key_hash?)
    Note over T: parse + credential<br/>(password and/or TLS client cert)
    T->>T: validate name, ip, groups, agent version
    rect rgb(240, 240, 235)
        Note over T,KS: under mutex_keys
        T->>KS: duplicate id / ip / name?
        alt duplicate found
            KS-->>T: force rules decide (see below)
        end
        T->>KS: OS_AddNewAgent() — assigns the id, generates the key
        T->>W: queue_insert += entry; write_pending = 1; signal
    end
    T-->>C: id + name + ip + key
    Note over C: the agent can sign requests NOW…
    W->>CK: rewrite client.keys whole (atomic rename)
    W->>W: wdb_insert_agent + wdb_set_agent_groups_csv
    CK-->>R: inotify / periodic reload
    Note over R: …but remoted only accepts it from here on
```

### Validation

Checked before the keystore is mutated:

| Field | Rule |
|---|---|
| `name` | two validators, deliberately different — see below |
| `ip` | a syntactic IPv4/IPv6/CIDR, or `any`. `use_source_ip` overrides whatever the caller claims |
| `groups` | every group must exist (`9014`) |
| version | rejected if newer than the manager's, unless `<agents><allow_higher_versions>` is `yes` |

The agent limit is not on that list because it is not a separate check: `OS_AddNewAgent()` enforces
`max_agents` itself and returns `OS_ADDAGENT_LIMIT_REACHED`, which becomes `9013`. The same sentinel
covers the id-assignment counter (`id_counter`) reaching `INT_MAX`: both are "no capacity left"
conditions and neither leaves a corrupted record behind.

**The name is checked by two different validators, and the difference is intentional.** The TLS
port 1515 path applies `OS_IsValidName()` — 2–128 characters, no leading `.`, a restricted charset.
The local socket applies only `is_storable_agent_name()`, a **storage-safety floor**: non-empty, at
most 128 bytes, no leading `#` or `!` (those mark removed and comment lines in `client.keys`), and no
control byte, space or `DEL` (any of them would break the file's `<id> <name> <ip> <key>` field
split). A name that clears the floor but not the stricter rule is rejected with `9017`.

The looser floor is what lets an operator register a name the self-enrollment path would refuse.
remoted's `/enroll` applies its own validator, tighter than both, before it ever reaches the socket.

### Id and key assignment

`OS_AddNewAgent()` picks the id — always the next free one, **never a recycled one** (see
[Why an id is never reused](#durability-and-the-id-mark)) — and generates the key. The caller then
reads both straight out of the entry it just created:

```c
os_strdup(keys.keyentries[index]->id,      *id);
os_strdup(keys.keyentries[index]->raw_key, *key);
```

An insertion may also *name* an id explicitly (`manage_agents`, `POST /agents/insert`). That path is
refused rather than served when the id is taken (`9012`) or still owes a purge (`9018`); self-enrolling
agents never send one.

## Duplicate handling and force replacement

When the name or IP already exists, `w_auth_replace_agent()` decides whether the newcomer may take it
over. **Every guard has to allow it**, and they are evaluated in this order — the first one that
refuses ends the decision:

```mermaid
flowchart TB
    S["duplicate name or IP found"] --> G1{"&lt;force&gt; enabled?"}
    G1 -->|no| X1["refuse:<br/>force option is disabled"]
    G1 -->|yes| G2{"agent-info readable<br/>in wazuh-db?"}
    G2 -->|no| X2["refuse:<br/>Failed to get agent-info"]
    G2 -->|yes| G3{"disconnected_time<br/>satisfied?"}
    G3 -->|"still connected"| X3["refuse:<br/>can't be replaced since<br/>it is not disconnected"]
    G3 -->|"disconnected too recently"| X4["refuse:<br/>has not been disconnected<br/>long enough"]
    G3 -->|ok| G4{"registered longer ago<br/>than after_registration_time?"}
    G4 -->|no| X5["refuse:<br/>doesn't comply with the<br/>registration time"]
    G4 -->|yes| G5{"key_mismatch: does the<br/>presented key_hash match?"}
    G5 -->|"matches"| X6["refuse:<br/>key already exists<br/>on the manager"]
    G5 -->|"differs / absent"| OK["Removing old agent<br/>add_remove + OS_DeleteKey"]
```

Two consequences worth internalising:

- **A replacement is a deletion.** It runs `add_remove()` and `OS_DeleteKey()` — the same two calls
  `DELETE /agents` makes — so everything in [Agent removal](#agent-removal) applies to it, including
  the queued indexer purge. A fleet re-enrolling under names that already exist generates one deletion
  per agent with nobody touching the API.
- **A replacement never reuses the id.** The replacing agent is a new registration with a new id.

`key_hash` is the caller's `SHA1(id ‖ name ‖ raw_key)` over its *current* credential — the same value
the legacy `K:` field carried, computed by `w_get_key_hash()` on both sides. It is a proof of
possession, not the key itself, and it is the last guard consulted rather than the first.

## Cluster

A worker node runs no writer: `if (!config.worker_node)` gates it, and with it every deletion phase. An
enrollment that arrives at a worker is forwarded to the master, and **the worker keeps nothing**.

```mermaid
sequenceDiagram
    participant A as Agent
    participant WK as Worker authd
    participant MA as Master authd
    participant WCK as Worker client.keys
    participant WR as Worker remoted

    A->>WK: enroll
    WK->>MA: w_request_agent_add_clustered()
    MA->>MA: validate + OS_AddNewAgent (master's keystore)
    MA-->>WK: new_id + new_key
    WK-->>A: id + key
    Note over WK: no local add, no write_pending —<br/>new_key is relayed and discarded
    MA->>MA: master's writer rewrites its client.keys
    MA-->>WCK: cluster integrity sync (~9 s + transfer)
    WCK-->>WR: reload
    Note over A,WR: until this point the agent holds a valid key<br/>that the worker's remoted cannot verify
```

Because of that, on a worker the window between "the agent has its key" and "remoted accepts it" is a
property of the cluster sync interval, not of authd's own speed. The `<force>` settings are ignored on
a worker — the master decides — and a worker that cannot reach the master answers `9016`.

## The enrollment password

With `use_password` enabled, `etc/authd.pass` holds the shared secret. The master generates one at
first start if none exists and logs that it did. Workers receive the file through the same cluster
sync as `client.keys`, which is why they run the **authpass watcher**: a worker that has not received
it yet fails closed — it rejects enrollments rather than validating against a null password.

remoted's `/enroll` route does not present this password as-is; it derives an AES-256-CMAC key from it
with HKDF-SHA256 and signs the request (`Authorization: WazuhEnroll <timestamp>:<mac>`). See the
[agent API reference](../remoted/agent-api.yaml).

## Error codes

The local socket answers a numeric code that the server API maps onto its own, and remoted's
`/enroll` maps onto HTTP:

| Code | Meaning | `/enroll` |
|---|---|---|
| 9001 / 9002 / 9009 | internal error, JSON parse failure, key generation failure | `500` |
| 9003 / 9004 / 9005 / 9006 / 9014 / 9017 | no such function/argument/name/IP, invalid groups, invalid agent name | `400` |
| 9007 / 9008 / 9012 | duplicate IP, name or id | `409` |
| 9010 / 9011 | no such agent id / agent id not found | — |
| 9013 | `max_agents` reached, or the id-assignment counter (`id_counter`) exhausted at `INT_MAX` | `503` — the latter is reachable from ordinary self-enrollment, since it never sends an id of its own |
| 9015 / 9016 | request not valid on a worker / cannot reach the master | `503` |
| 9018 | the id still has a pending deletion | — |
| 9019 / 9020 | invalid caller-supplied key / id (id outside `[1, 2147483647]`, or `0`) | `400` — unreachable from here in practice: self-enrollment never sends a key or an id, mapped for completeness |
| 9021 | too many deletions are pending; the agent was NOT deleted (`1766` through the server API) | — |

## Agent removal

A removal touches four places, and only the first three are immediate.

```mermaid
flowchart LR
    D1["DELETE /agents\n(server API)"] -->|"refused if the deletion\nbacklog is full"| ADD
    D2["enrollment with a name\nthat already exists"] --> ADD
    D3["POST /agents/insert\nwith an explicit id"] -->|"refused if the id\nis not free to reuse"| REJ[["9012 Duplicate ID\n9018 pending deletion"]]

    ADD["add_remove + OS_DeleteKey"] --> M1["1. in-memory keystore\n(immediate)"]
    ADD --> Q[queue_remove]
    Q --> W[Writer pass]
    W --> M2["2. client.keys\n(rewritten whole)"]
    W --> M3["3. Wazuh DB row,\nrids counter, timestamp"]
    W --> M4["4. deletion task recorded,\nnot executed"]
    M4 -->|"journaled BEFORE client.keys,\nrow created only AFTER"| PF[(pending-purges journal)]
    M4 --> MT[(tasks.db)] -->|"first attempt after\nauthd.purge_delay"| DISP[Task Manager dispatcher] --> ISS[inventory_sync_server]
```

Two of those doors are worth calling out:

- **An enrollment whose name already exists is a removal.** `w_auth_replace_agent()` calls the same
  two functions the API path calls, so a fleet that re-enrolls with names that already exist generates
  one deletion per agent without anyone touching the API. Any reasoning about deletion load has to
  account for it.
- **An insertion that names an id explicitly is refused rather than served** when that id belongs to
  an existing agent (`9012`) or still owes a purge (`9018`, reported as `1763` by the server API). A
  recorded purge always runs; cancelling it is never the answer. The id stops being reusable the moment
  the agent is deleted, not when the writer gets around to recording the task: it is reserved in memory
  in between, or an insertion arriving inside that window would take an id whose purge is on its way.
- **A deletion itself can be refused** (`9021`, reported as `1766`) when too many earlier ones are
  still pending. It is decided on the REQUEST thread, before the agent leaves the keystore, so the
  agent is untouched and the caller can retry. One line later there would be nothing left to refuse
  and nobody to tell — which is why the previous design, discovering a full queue in the writer, could
  only drop the purge and orphan the documents.

### Why the purge waits

The deletion task's first attempt is set `authd.purge_delay` seconds out (default `120`), because the
purge has to outlast three intervals. A `_delete_by_query` is a *search*: it cannot match
documents the indexer has not made searchable yet, and in a cluster a worker node that still holds the
previous `client.keys` keeps accepting that agent's data and writing it. **Whatever the purge misses
survives forever**, because with the agent gone nothing overwrites it.

```mermaid
flowchart LR
    T0["t0 · agent deleted\nclient.keys and Wazuh DB updated"] --> T1
    T1["~1 s · index refresh\nthe agent's last documents become searchable"] --> T2
    T2["9 s · cluster integrity sync\nworkers reload client.keys"] --> T3
    T3["120 s · keepalive tolerance\nthe longest a worker can be behind"] --> T4
    T4[["t0 + authd.purge_delay\nthe task becomes eligible"]]
```

See [`authd.purge_delay`](configuration.md#authdpurge_delay) for the full reasoning and for when a
single-node manager can lower it.

### Durability and the id mark

**Why a file at all.** The durable record of a deletion is its row in `tasks.db`, but that row cannot
be created before `client.keys` is written — doing so would put a Wazuh DB round trip in front of
every key write, so a database outage would block enrollment. The file covers the gap: it records the
*intent* locally, before the point of no return, and it is normally **empty**, because it drains as
fast as Wazuh DB answers rather than as fast as the indexer does.

```mermaid
flowchart TB
    subgraph AUTHD["wazuh-manager-authd"]
        WR["Writer thread"]
        MEM[("deletion journal\nin memory")]
    end
    CK[(client.keys)]
    PF[("queue/authd/pending-purges\nlast_update - last_id - last_seq - purge id epoch seq")]
    MT[(tasks.db)]
    ISS["inventory_sync_server"]

    WR -->|"1. journals the id, timestamp and sequence"| MEM
    MEM -->|"persisted BEFORE client.keys"| PF
    WR ==>|"2. rewrites client.keys - the point of no return"| CK
    WR -->|"also: last_id, the highest id ever handed out"| PF
    WR -->|"3. creates the task, only if 2 succeeded"| MT
    MT -.->|"ok = committed, not buffered"| WR
    WR -->|"4. drops the journal line"| PF
    MT --> DISP["Task Manager dispatcher"] --> ISS
    PF ==>|"on startup: every line compared against client.keys,\nowed tasks created, id counter raised"| MEM
```

The journal lives in `queue/authd/pending-purges`, written through a temporary and an atomic rename:

```
last_update 1787582136
last_id 161
last_seq 4
purge 003 1787582014 4
```

The four phases, and what each failure costs:

| # | Phase | Where | A failure costs |
|---|---|---|---|
| 0 | admit or refuse (`9021`) | request thread, before the agent leaves the keystore | the deletion is refused; the agent is untouched |
| 1 | journal the intent | writer, before `client.keys` | a warning; the phases continue |
| 2 | rewrite `client.keys` | writer | logged, and **phase 3 is skipped** |
| 3 | create the deletion task | writer, over Wazuh DB | the journal line stays; the next cycle retries |
| 4 | drop the journal lines | writer, on Wazuh DB's acknowledgement | the lines stay; the next start re-creates the tasks and the ids collide, which is success |

Phase 0 is taken by **both** paths that delete an agent: the API's `remove`, and a force replacement,
which is the higher-volume one — a mass re-enrollment produces one deletion per agent. A replacement
refused there is an enrollment refused, and the existing agent keeps its registration.

Phase 3 is gated on phase 2 because the writer *logs* a failed key write and carries on, so without
the gate authd would record purges for agents that are still listed on disk. Phase 4 can only drop a
line because the task's creation commits inside its own Wazuh DB command — its `ok` is a durability
acknowledgement rather than a buffered write. It drops the batch's lines in one write, and only the
ones whose tasks are durable: the journal file is rewritten whole on every drop, so dropping per entry
would make a bulk deletion quadratic in file writes.

Every surviving journal line is resolved on the next start against the `client.keys` just read: an
agent still listed there means the deletion never became final, so the line is dropped; an absent one
means the task is still owed and is created now. That comparison closes the window this design exists
for — a crash between the key write and the task's creation, which the previous relay design lost
silently.

- If the clock is **earlier** than `last_update` on startup, every stored timestamp is untrustworthy
  and they are all re-stamped, so each deletion waits its full delay again.
- `last_seq` is a monotonic per-entry sequence, and the deletion task's id is derived from the agent
  and its sequence. That is what makes the two legitimate creators — the writer and startup recovery —
  produce the *same* id, so the second one collides harmlessly instead of duplicating the work.
  Sequences are never reused and never reset; a wall-clock stamp could not promise that, and two
  deletions of one agent that derived one id would silently become one.
- `last_id` is the highest agent id ever handed out. On startup the id counter is raised to it if
  needed, so **an id is never reused**: a purge matches by agent id, and nothing in a state document
  distinguishes one owner of an id from the next.

### What a rebuilt manager inherits

`queue/` survives an upgrade and a plain package removal, so the id mark survives with it — and so
does `tasks.db`, which holds the deletions themselves. A full package purge — or an install into a clean tree — takes the file with it, and the id
counter starts over while the indexer still holds the previous fleet's documents. **Deleting a manager
should include deleting its indexer data**, or new agents can inherit documents from the agents that
held their ids before, in the indices they do not resynchronise themselves.

## Storage

| Path | Contents |
|---|---|
| `etc/client.keys` | one line per agent: `<id> <name> <ip> <key>`; rewritten whole, never edited in place. A removed agent is kept as a `!name` line unless `<purge>` is `yes` |
| `etc/agents-timestamp` | per-agent registration timestamp |
| `etc/authd.pass` | enrollment password |
| `queue/authd/pending-purges` | deletions between phase 1 and phase 4, plus the highest id and sequence ever handed out. Normally empty |
| `queue/rids/<id>` | per-agent anti-replay counters, removed with the agent |

## Observability

| Line | Meaning |
|---|---|
| `Recovered N agent deletion(s) that were interrupted...` | startup reconciliation found deletions whose task was never created, and is creating them now |
| `Dropped N journaled deletion(s) whose agents are still listed in client.keys` | those deletions never became final; nothing is owed |
| `Converted N deletion(s) from the previous file format` | a journal written before sequences existed; the entries were numbered by position |
| `Raising the agent id counter from X to Y` | the counter would have gone backwards; ids are not reused |
| `The deletion of agent 'N' could not be recorded...` | phase 3 failed; the journal line stays and the next writer cycle retries |
| `Refusing the deletion: ...` | phase 0 said no (`9021`); the agent is untouched and the request can be repeated. A force replacement refused by the same bound reports `Agent 'N' can't be replaced: too many deletions are in progress` |
| `Shutting down with N agent deletion(s) still being recorded` | they stay in the journal and are reconciled on the next start |

The purge's own outcome — the `deleteByQuery` and its flush — is reported by
[inventory_sync_server](../inventory-sync-server/architecture.md#agent-deletion) and recorded as the
task's status, not by authd: authd's responsibility ends at the durable task row.

## Related

- [Authd overview](README.md) and [configuration](configuration.md)
- [`src/os_auth/README.md`](https://github.com/wazuh/wazuh/blob/main/src/os_auth/README.md) — the
  developer map: invariants, tests and the reasoning behind each ordering decision
- [Inventory Sync Server architecture](../inventory-sync-server/architecture.md) — the module that
  applies the deletion, on the other side of `POST /_internal/agents/delete`
