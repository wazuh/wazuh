# Data Flow and Sequence of Calls

This document traces the **sequence of calls between the agent, the manager, and the Wazuh Indexer** for an Inventory Sync session, and then explains the same flow **from the most abstract level down to the specific classes and functions**, using the Vulnerability Detector (VD) as the worked example.

It complements:

- [Architecture](architecture.md) — manager-side components and responsibilities.
- [FlatBuffers](flatbuffers.md) — the on-the-wire message schema.
- [Agent Sync Protocol](../utils/sync-protocol/README.md) — the agent-side library that drives the protocol (its [sequence diagrams](../utils/sync-protocol/sequence-diagrams.md) treat the manager as a black box; this document opens that box).

## Who is who

Inventory Sync has **two sides** connected by two transports:

| Side | Component | Where |
|------|-----------|-------|
| Agent | Module (Syscollector / FIM / SCA / agent-info) | `wazuh_modules/*`, `syscheckd/*` |
| Agent | **Agent Sync Protocol** (`AgentSyncProtocol`) + SQLite queue | `src/shared_modules/sync_protocol/` |
| Transport ↑ | MQueue (`SYNC_MQ='s'`) → `wazuh-agentd` → `remoted` → Router topic `inventory-states` | `mqueue_transport.cpp`, `remoted/src/secure.c` |
| Manager | **Inventory Sync** facade, `AgentSession`, `GapSet`, RocksDB, indexer queue | `src/wazuh_modules/inventory_sync/` |
| Manager | **Indexer Connector** → Wazuh Indexer (`wazuh-states-*`) | `src/wazuh_modules/*/indexerConnector` |
| Manager | **Vulnerability Scanner** (for `VDFirst`/`VDSync`) → `wazuh-states-vulnerabilities` | `src/wazuh_modules/vulnerability_scanner/` |
| Transport ↓ | AR datagram socket `queue/sockets/ar` (`<module>_sync` framing) → `remoted` → agent | `responseDispatcher.hpp`, `client-agent/src/receiver.c` |

The two transports are **asymmetric**: requests travel agent → manager over the Router topic `inventory-states`; responses travel manager → agent over the active-response (`ar`) socket, framed as `(msg_to_agent) [] N!s <agentId> <size> <module>_sync <flatbuffer>`.

## 1. Session lifecycle — a normal inventory delta sync

This is the control-plane handshake for `syscollector` / `fim` / `sca` in `ModuleDelta` (or `ModuleFull`). Transport hops (MQueue → agentd → remoted → Router, and the AR socket back) are collapsed into a single **Transport** lane for readability.

```mermaid
sequenceDiagram
    participant Mod as Agent module<br/>(Syscollector/FIM/SCA)
    participant ASP as Agent Sync Protocol<br/>(+ SQLite queue)
    participant Tx as Transport<br/>(MQueue⇄remoted <br/>Router / AR socket)
    participant Fac as InventorySyncFacade<br/>::run
    participant Sess as AgentSession<br/>(+ GapSet)
    participant DB as RocksDB<br/>queue/inventory_sync
    participant IQ as Indexer<br/>completion queue
    participant Idx as IndexerConnector<br/>→ wazuh-indexer

    Note over Mod,ASP: dbsync detects INSERTED/MODIFIED/DELETED rows
    Mod->>ASP: persistDifference(id, op, index, data, version)
    ASP->>ASP: store delta in SQLite

    Mod->>ASP: synchronizeModule(DELTA)
    ASP->>ASP: fetch pending diffs, assign seq = 0..N-1

    rect rgb(240,244,255)
    Note over ASP,Fac: Start phase
    ASP->>Tx: Message{Start(module,mode,size=N,index,option,agent…)}
    Tx->>Fac: publish on topic "inventory-states"
    Fac->>Sess: create AgentSession (random 64-bit session id)
    Sess->>Tx: StartAck(Status_Ok, session)
    Tx->>ASP: (module)_sync → parseResponseBuffer → store session
    end

    rect rgb(240,255,244)
    Note over ASP,DB: Data phase
    loop DataValues packed into ~60 KB DataBatch messages
        ASP->>Tx: Message{DataBatch[DataValue(seq,session,op,id,index,data)]}
        Tx->>Fac: publish
        Fac->>Sess: handleData(dataValue) per item
        Sess->>DB: put "{session}_{seq}" = bytes
        Sess->>Sess: GapSet.observe(seq)
    end
    end

    rect rgb(255,250,240)
    Note over ASP,Idx: End phase
    ASP->>Tx: Message{End(session)}
    Tx->>Fac: publish
    Fac->>Sess: handleEnd()
    alt GapSet complete
        Sess->>IQ: push(Response{context})
        Sess->>Tx: EndAck(Status_Processing)
        Tx->>ASP: keep waiting (no resend, no retry consumed)
        IQ->>Idx: bulkIndex / bulkDelete each "{session}_*" doc
        Note over Idx: _id = {cluster}_{agent}_{id} <br/>manager overlays wazuh.agent.* and cluster.name
        Idx->>IQ: flush → registerNotify callback fires
        IQ->>DB: deleteByPrefix(session)
        IQ->>Tx: EndAck(Status_Ok)
        Tx->>ASP: success → delete synced diffs from SQLite
        ASP->>Mod: return true
    else GapSet has holes
        Sess->>Tx: ReqRet(missing ranges, session)
        Tx->>ASP: parseResponseBuffer → resend only missing seqs
        Note over ASP,Sess: no End resend  manager auto-acks once gaps fill
    end
    end
```

Mode-specific completion (all reach the indexer completion queue the same way, then branch in the facade's `run` callback):

- **`ModuleFull`** — `deleteByQuery(index, agent)` for every Start index first, then bulk-index the session payload.
- **`ModuleDelta`** — bulk-index/delete only the received `DataValue`s.
- **`ModuleCheck`** — no data; compute a checksum-of-checksums from the indexed docs and compare with the agent's `ChecksumModule` (5 retries, 10 s apart) → `EndAck(Ok)` or `EndAck(ChecksumMismatch)`.
- **`MetadataDelta` / `MetadataCheck` / `GroupDelta` / `GroupCheck`** — no data; lock the agent, flush pending bulk work, wait up to 60 s for the agent's other sessions to drain, then run an `update_by_query` (Painless script) across the agent's state indices.

## 2. Vulnerability Detector hand-off (`syscollector_vd`)

`syscollector_vd` is **not a separate module** — it is a second Agent Sync Protocol instance inside Syscollector, backed by its own SQLite DB (`syscollector_vd_sync.db`). It carries the same inventory (packages / OS / hotfixes) but with option `VDFirst` (first full scan, everything as `DataValue`) or `VDSync` (delta: changes as `DataValue`, surrounding unchanged rows the scanner needs for correlation as `DataContext`).

The key difference from a plain inventory sync is the **data-plane hand-off after End**: once the inventory documents are indexed, the facade calls the Vulnerability Scanner, which re-reads the *same RocksDB session data* (including the `_context` entries Inventory Sync itself never indexes) and writes CVE findings to `wazuh-states-vulnerabilities` through its **own** Indexer Connector.

```mermaid
sequenceDiagram
    participant SC as Syscollector (agent)
    participant VDP as ASP (VD instance)<br/>m_spSyncProtocolVD
    participant Tx as Transport
    participant Fac as InventorySyncFacade
    participant DB as RocksDB session store
    participant VD as VulnerabilityScannerFacade
    participant Orch as ScanOrchestrator<br/>(CoR chain)
    participant VIdx as IndexerConnector<br/>→ wazuh-states-vulnerabilities

    Note over SC: package added/removed (dbsync delta)
    SC->>VDP: persistDifference(...) [packages/system/hotfixes → VD instance]
    SC->>VDP: syncModule → synchronizeModule(DELTA, option = VDSync)
    SC->>VDP: processVDDataContext() → attach OS row (+hotfixes on Windows) as DataContext

    VDP->>Tx: Start(module="syscollector_vd", option=VDSync)
    Tx->>Fac: StartAck(session)
    VDP->>Tx: DataBatch[DataValue] (changes) + DataContext (context rows)
    Tx->>Fac: handleData → "{session}_{seq}"  handleDataContext → "{session}_{seq}_context"
    VDP->>Tx: End(session)
    Tx->>Fac: handleEnd → EndAck(Processing), enqueue

    Note over Fac: bulk-index inventory into wazuh-states-inventory-*<br/>(DataContext keys are skipped here)
    Fac->>VD: isInitialized? isFeedReady? (else waitForFeedReady)
    Fac->>VD: runScanner(dataStore, context)
    VD->>Orch: runScan(store, context)
    Orch->>DB: seek("{session}_") — reads DataValue AND _context rows
    Orch->>Orch: buildScanContext → PackageScanner → EventGetCve → …
    Orch->>VIdx: ResultIndexer bulkIndex/bulkDelete CVE docs
    VIdx->>VIdx: flush → wazuh-states-vulnerabilities
    Fac->>Tx: EndAck(Status_Ok)
    Tx->>VDP: success
```

Chain selected by option (built once in `ScanOrchestrator` via `FactoryOrchestrator`):

- **`VDFirst`** → *FirstFullScan*: `OsScanner → PackageScanner → EventDetailsBuilder → ResultIndexer` (alerts suppressed on the first scan). The agent's prior vulnerability docs are `deleteByQuery`-purged first.
- **`VDSync`, packages only** → *PackagesDelta*: `PackageScanner → EventGetCve → EventDetailsBuilder → EventSendReport → ResultIndexer`.
- **`VDSync`, OS/hotfix changed** → *FullScan*: `EventGetContext → OsScanner → PackageScanner → EventDetailsBuilder → EventSendReport → ResultIndexer`.

### Feed-update rescan coordination (bidirectional)

When the CVE feed updates, the scanner rescans every agent — and coordinates with in-flight `syscollector_vd` sessions so nobody is scanned against half-written data or scanned twice:

```mermaid
sequenceDiagram
    participant Feed as DatabaseFeedManager<br/>(post-update callback)
    participant VD as VulnerabilityScannerFacade
    participant IS as InventorySyncFacade
    participant Scan as runScanAfterFeedUpdate

    Feed->>VD: feed changed
    VD->>IS: getAgentsWithActiveSessionForModule("syscollector_vd", VDFirst)
    IS-->>VD: agents already covered by a VDFirst full scan
    VD->>VD: prepareFeedUpdateScan(covered)  [BEFORE feedReady=true]
    VD->>VD: feedReady = true notify waiters
    VD->>IS: waitForAllVDSyncSessions(60s, 5)
    Note over IS: VDSync sessions see isFeedUpdateScanInProgress()<br/>and self-skip their own delta scan
    IS-->>VD: drained
    VD->>Scan: rescan all agents, skipping feed-update-covered ones
    Scan->>VD: (each ends → wazuh-states-vulnerabilities)
```

## 3. From abstract to specific

The same flow, described at four levels of zoom. The worked example is **"a package changes on an agent → a CVE document appears in the indexer."**

### Level 1 — Conceptual

The agent continuously observes local state (files, packages, checks). Instead of shipping full snapshots, it ships **deltas** with sequence numbers over a reliable, session-based protocol. The manager reconciles those deltas into the Wazuh Indexer so `wazuh-states-*` always reflects current agent state. For vulnerability data, the manager additionally runs a scanner that turns package/OS inventory into CVE findings.

### Level 2 — Contracts and boundaries

- **Agent Sync Protocol** (`shared_modules/sync_protocol`) is the single agent-side API every module uses: `persistDifference`, `synchronizeModule`, `requiresFullSync`, `synchronizeMetadataOrGroups`, `notifyDataClean`, `parseResponseBuffer`. State lives in a per-module SQLite queue.
- **Inventory Sync** (`wazuh_modules/inventory_sync`) is the manager-side authority: it owns session state, RocksDB persistence, indexer operations, and response dispatch.
- The **contract** between them is the FlatBuffer schema `inventorySync.fbs` (`Start`, `DataValue`, `DataBatch`, `DataContext`, `DataClean`, `ChecksumModule`, `End`, `StartAck`, `EndAck`, `ReqRet`).
- The **Vulnerability Scanner** consumes an Inventory Sync session's RocksDB contents through `VulnerabilityScannerFacade::runScanner(store, context)` and owns the `wazuh-states-vulnerabilities` index.

### Level 3 — Message and session flow

Start → StartAck(session) → [DataBatch(seq…) + DataContext] → End → EndAck(Processing) → (bulk index + optional scan) → EndAck(Ok/Error/ChecksumMismatch). `GapSet` tracks completeness and drives `ReqRet` retransmission. Metadata/Group and ModuleCheck modes carry no data. See [Architecture › End-to-end flow](architecture.md#end-to-end-flow).

### Level 4 — Specific classes and functions

Agent side (Syscollector VD example):

| Step | Symbol | File |
|------|--------|------|
| dbsync delta callback | `Syscollector::notifyChange` → `m_persistDiffFunction` | `wazuh_modules/syscollector/src/syscollectorImp.cpp` |
| route package/OS/hotfix to the VD stream | `persistDifference` → `m_spSyncProtocolVD` | `syscollectorImp.cpp:2389` |
| pick full vs delta | `syncModule` → `isVDFirstSyncDone()` → `synchronizeModule(Option::VDFIRST/VDSYNC)` | `syscollectorImp.cpp:2324` |
| attach correlation context | `processVDDataContext` → `persistDifference(..., isDataContext=true)` | `syscollectorImp.cpp:2628` |
| emit Start / data / end | `sendStartAndWaitAck`, `sendDataMessages`, `sendDataContextMessages`, `sendEndAndWaitAck` | `shared_modules/sync_protocol/src/agent_sync_protocol.cpp` |
| consume responses | `parseResponseBuffer` (stores `session`, handles StartAck/EndAck/ReqRet) | `agent_sync_protocol.cpp:1168` |
| send on the wire | `MQueueTransport::sendMessage` (`SYNC_MQ='s'`) | `sync_protocol/src/mqueue_transport.cpp` |

Transport:

| Step | Symbol | File |
|------|--------|------|
| publish agent messages on the Router topic | `router_provider_create("inventory-states", …)` | `remoted/src/secure.c` |
| receive `<module>_sync` responses | `receiver.c` → `wmcom_send`/`ag_send_syscheck` → module `.sync` → `parseResponseBuffer` | `client-agent/src/receiver.c`, `wazuh_modules/src/wmcom.c` |

Manager side:

| Step | Symbol | File |
|------|--------|------|
| dispatch by message type | `InventorySyncFacadeImpl::run` | `inventory_sync/src/inventorySyncFacade.hpp:94` |
| session lifecycle | `AgentSession::handleData` / `handleDataContext` / `handleEnd` | `inventory_sync/src/agentSession.hpp` |
| completeness tracking | `GapSet::observe` / `ranges` | `inventory_sync/src/gapSet.hpp` |
| session persistence | RocksDB keys `{session}_{seq}` / `{session}_{seq}_context` | `agentSession.hpp` |
| completion + indexing | indexer-queue callback → `bulkIndex` / `bulkDelete` / `deleteByQuery` / `executeUpdateByQuery` | `inventorySyncFacade.hpp` (indexer-queue lambda) |
| response dispatch | `ResponseDispatcher::sendStartAck` / `sendEndAck` / `sendEndMissingSeq` | `inventory_sync/src/responseDispatcher.hpp` |
| VD hand-off | `VulnerabilityScannerFacade::runScanner` → `ScanOrchestrator::runScan` → `buildScanContext` (reads RocksDB) → CoR chain → `ResultIndexer` | `vulnerability_scanner/src/vulnerabilityScannerFacade.cpp`, `scanOrchestrator/scanOrchestrator.hpp`, `scanOrchestrator/factory/resultIndexer.hpp` |

> Line numbers are provided as navigation hints against the tree this document was written for; treat the symbol names as the stable reference.
