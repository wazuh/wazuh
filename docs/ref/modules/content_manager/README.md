# Content Manager

The Content Manager is a shared library that downloads content from the Wazuh Indexer and hands it,
page by page, to whoever registered for it. Two hosts link it in-process; it has no daemon and no
modulesd module of its own:

- the **Vulnerability Scanner** (in `wazuh-manager-modulesd`) registers its feed topic,
  `vulnerability_feed_manager`, and builds its local CVE database from it;
- the **Engine** (`wazuh-manager-analysisd`) registers one topic per ruleset space (`cmsync`) and one
  per IoC type (`iocsync`), and keeps its ruleset and IoC enrichment databases in step with them.

Source: `src/shared_modules/content_manager/`. Implementation details (the cycle stages, the sink
contract, the internal configuration object) are in the developer README,
`src/shared_modules/content_manager/README.md`.

## How an update runs

The Vulnerability Scanner's topic is updated once when it registers, then every
`feed-update-interval` (default `60m`), and on demand (see [On-demand updates](#on-demand-updates)).
The Engine's topics run on `analysisd.cm_sync_interval` and `analysisd.ioc_sync_interval`. Two
updates of the same topic never overlap: a run that finds one in progress is skipped.

Each update:

1. **Checks that the CTI consumer is ready.** It reads the consumer's document in
   `.wazuh-cti-consumers` (`cti:catalog:consumer:vulnerabilities` for the vulnerability feed) and
   proceeds only when its `status` is `ready`. Any other state (document missing, empty status,
   `running`, `failed`, an unknown value) defers the update, which is retried about a minute later.
2. **Opens a point-in-time (PIT) snapshot** over the content indices *and* the consumer index, and
   checks the consumer status again from **inside** the snapshot. A consumer that starts
   re-indexing between the first check and the snapshot therefore cannot have half-written content
   read as if it were complete.
3. **Decides whether anything changed**, comparing the remote position with the one it stored last
   time:
   - **Vulnerability feed** — every CVE document carries a monotonically increasing `offset`. With
     no stored cursor it performs an **initial load** of the whole index, once the global-map
     documents `FEED-GLOBAL`, `OSCPE-GLOBAL` and `CNA-MAPPING-GLOBAL` are present; otherwise an
     **incremental update** of only the documents whose `offset` is greater than the cursor.
   - **Engine ruleset and IoCs** — the indexer publishes a content hash; when it differs from the
     deployed one the content is reloaded in full, and when it matches nothing is downloaded.
4. **Downloads the snapshot**, `pageSize` documents per request. An initial load of the vulnerability
   feed is split into `numSlices` parallel slices when `numSlices` is greater than 1; incremental
   updates are always sequential.
5. **Lets the host accept the result.** The host promotes the content only once it has all of it. If
   it rejects it — for example, the Vulnerability Scanner finds the local feed not usable — the
   stored position is cleared and the next run, about 30 seconds later, is a full reload.
6. **Stores the new position**, only after the host promoted the content, so the next update
   resumes from it.

An update never waits in a loop. When it cannot proceed it ends and is retried: about a minute
later when the consumer is not ready, and after 30 seconds, doubling up to 5 minutes, while the
indexer is unreachable. A stop of the manager during a download aborts it; the stored position is
kept, so the next run resumes from it.

## Configuration

The Content Manager has no section of its own in `wazuh-manager.conf`. Its settings come from the
hosts:

| Setting | Where it is configured |
|---|---|
| Vulnerability feed: update interval, page size, parallel slices | `feed-update-interval`, `pageSize` and `numSlices` of `<vulnerability-detection>` — see the [Vulnerability Scanner configuration](../vulnerability-scanner/configuration.md) |
| Engine: sync intervals, page sizes, PIT lease, consumer retry | `analysisd.*` internal options — see the [Engine configuration](../engine/configuration.md) |
| Indexer hosts, TLS files, credentials | The `<indexer>` section and the keystore — see the [Indexer Connector configuration](../indexer_connector/configuration.md) |

## Indexer indices

| Index | Use |
|---|---|
| `.wazuh-threatintel-vulnerabilities` | The vulnerability feed (CVE documents and the global maps), read-only |
| `wazuh-threatintel-{kvdbs,decoders,filters,integrations,policies}` | Engine ruleset resources (`cmsync`), read-only |
| `wazuh-threatintel-enrichments` | Engine IoC documents and their per-type hash manifest (`iocsync`), read-only |
| `.wazuh-cti-consumers` | Consumer readiness documents, read before every update and again inside its snapshot |

## State on disk

| Path | Contents |
|---|---|
| `/var/wazuh-manager/queue/vd/vd_updater/rocksdb/updater_vulnerability_feed_manager_metadata/` | Vulnerability feed: RocksDB database holding the cursor (`current_offset` column) |
| Engine store documents `cmsync/status/0`, `iocsync/status/0` | Engine: the deployed hash of each ruleset space and IoC type |

If the vulnerability feed's cursor database cannot be opened or repaired, it is rebuilt empty and
the next update is an initial load.

## On-demand updates

The vulnerability feed can be updated on request through the `POST /ondemand` route of the
Vulnerability Scanner's local socket, `/var/wazuh-manager/queue/sockets/vd-http.sock`, with
`{"topic": "vulnerability_feed_manager"}`. An `offset` of `0` in the body discards the stored cursor
and forces an initial load; `-1` (the default) keeps it. The route, its status codes and its limits
are documented in the [Vulnerability Scanner API reference](../vulnerability-scanner/api-reference.md#post-ondemand).

The Engine's topics are triggered through its API socket with `POST /content/ruleset/update` and
`POST /content/ioc/sync`, which answer as soon as the request is queued; progress is read from
`GET /status`. Both are documented in the [Engine public API reference](../engine/public-api-reference.md).

## Logs

The Content Manager logs to `/var/wazuh-manager/logs/wazuh-manager.log`, tagged by the host it runs
in: `wazuh-manager-modulesd:content-updater` for the vulnerability feed and
`wazuh-manager-analysisd:content-updater` for the Engine's ruleset and IoC topics. It has no
connection of its own: it reads through the host's indexer connector, so a failed request to the
indexer is reported once, by that connector, under the host's own indexer-connector tag. Lines to
look for:

| Message | Meaning |
|---|---|
| `Content cycle for '<topic>' created (changeDetection=<mode>, indices=<n>, slices=<n>, pageSize=<n>)` | The topic was registered |
| `Consumer '<id>' in '<index>' is still not ready (<status>); content download is deferred.` | The CTI consumer is still indexing the content |
| `Consumer '<id>' is not present in '<index>' yet; content cannot be downloaded until the indexer publishes it.` | The consumer document is missing — the normal state of a fresh install |
| `Starting sliced fetch for '<topic>' with <n> slices, pageSize=<n>` | A parallel initial load started |
| `Content update for '<topic>' completed: <n> document(s), token '<token>'.` | An update finished and its new position was stored |
| `Content update for '<topic>' deferred: <reason>. Retrying in <n>s.` | The update could not start yet and will be retried |
| `Content update for '<topic>' failed: <error>. Retrying in <n>s.` | The update failed and will be retried |
| `Content update for '<topic>' was rejected on commit (<reason>); the stored token was cleared and the next cycle will perform a full reload.` | The host refused the downloaded content |
