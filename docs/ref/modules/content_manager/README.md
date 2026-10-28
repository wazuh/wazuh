# Content Manager

The Content Manager is the shared library (`libcontent_manager.so`) that downloads the vulnerability
feed from the Wazuh Indexer and hands it, page by page, to the Vulnerability Scanner, which builds its
local CVE database from it. It runs inside `wazuh-manager-modulesd`: the `content_manager` module
(`src/wazuh_modules/src/wm_content_manager.c`), which has no configuration section and is always
loaded on a manager, loads the library at start, and the Vulnerability Scanner, which links the same
library, registers its feed topic, `vulnerability_feed_manager`, with it. With
`<vulnerability-detection>` disabled no topic is registered, so nothing is downloaded.

Source: `src/shared_modules/content_manager/`. Implementation details (the pipeline stages, the
callback contract, the internal configuration object) are in the developer README,
`src/shared_modules/content_manager/README.md`.

## How an update runs

The topic is updated once when the Vulnerability Scanner registers it, then `feed-update-interval`
(default `60m`) after the previous scheduled update **finished** — the interval is counted from the
end of one run, not from its start, so a run that takes 10 minutes moves every later run by 10
minutes — and on demand (see [On-demand updates](#on-demand-updates)).
Two updates of the same topic never overlap: a scheduled run that finds one in progress is skipped.

Each update:

1. **Waits for the CTI consumer to be ready.** It reads the document
   `cti:catalog:consumer:vulnerabilities` of `.wazuh-cti-consumers` and proceeds only when its
   `status` is `ready`. Any other state (document missing, empty status, `running`, `failed`, an
   unknown value, or an unreachable indexer) is retried every minute.
2. **Chooses a full or an incremental download** from the cursor it stored last time (the highest
   `offset` it has processed):
   - **Initial load** (no cursor): first waits until the global-map documents `FEED-GLOBAL`,
     `OSCPE-GLOBAL` and `CNA-MAPPING-GLOBAL` are present in `.wazuh-threatintel-vulnerabilities`
     (checked every 30 seconds), then downloads every document of the index. If the download fails
     or the index returns no documents, it retries every 30 seconds.
   - **Incremental update** (cursor stored): downloads only the documents whose `offset` is greater
     than the cursor.
3. **Downloads with a point-in-time (PIT) snapshot**, sorted by `offset` and `_id`, `pageSize`
   documents per request. An initial load splits the index into `numSlices` parallel slices when
   `numSlices` is greater than 1; incremental updates are always sequential.
4. **Asks the Vulnerability Scanner to validate the result.** If the scanner reports the local feed
   as not usable, the stored cursor is invalidated and a full reload is retried after 30 seconds.
5. **Stores the new cursor**, so the next update resumes from it.

A stop of the manager during a download aborts it. The cursor already stored is kept for a sequential
download; an interrupted parallel (sliced) initial load stores no cursor, so the next run starts the
initial load again.

## Configuration

The Content Manager has no section of its own in `wazuh-manager.conf`. Its settings come from two
places:

| Setting | Where it is configured |
|---|---|
| Update interval, page size, parallel slices | `feed-update-interval`, `pageSize` and `numSlices` of `<vulnerability-detection>` — see the [Vulnerability Scanner configuration](../vulnerability-scanner/configuration.md) |
| Indexer hosts, TLS files, credentials | The `<indexer>` section and the keystore — see the [Indexer Connector configuration](../indexer_connector/configuration.md) |

## Indexer indices

| Index | Use |
|---|---|
| `.wazuh-threatintel-vulnerabilities` | The vulnerability feed (CVE documents and the global maps), read-only |
| `.wazuh-cti-consumers` | Readiness document `cti:catalog:consumer:vulnerabilities`, read before every update |

## State on disk

| Path | Contents |
|---|---|
| `/var/wazuh-manager/queue/vd/vd_updater/rocksdb/updater_vulnerability_feed_manager_metadata/` | RocksDB database holding the cursor (`current_offset` column) |

The Vulnerability Scanner deletes the whole `queue/vd/vd_updater/` directory when it finds its own
feed database (`queue/vd/feed`) incomplete or unreadable at start, which forces the next update to be
an initial load.

## On-demand updates

The topic can be updated on request through the `POST /ondemand` route of the Vulnerability
Scanner's local socket, `/var/wazuh-manager/queue/sockets/vd-http.sock`, with
`{"topic": "vulnerability_feed_manager"}`. An `offset` of `0` in the body discards the stored cursor
and forces an initial load; `-1` (the default) keeps it. The route, its status codes and its limits
are documented in the [Vulnerability Scanner API reference](../vulnerability-scanner/api-reference.md#post-ondemand).

## Logs

The Content Manager logs to `/var/wazuh-manager/logs/wazuh-manager.log` under the tag
`wazuh-manager-modulesd:content-updater`. Lines to look for:

| Message | Meaning |
|---|---|
| `IndexerDownloader: Consumer '<id>' in index '<index>' is ready. Starting feed download.` | The readiness gate passed |
| `IndexerDownloader: Consumer '<id>' not found in '<index>'. Waiting 60s before retrying.` | The CTI consumer has not registered its status document yet (normal on a fresh indexer) |
| `IndexerDownloader: Consumer '<id>' is still running in '<index>'. Waiting 60s before retrying.` | The CTI consumer is still indexing the feed |
| `IndexerDownloader: Global-map documents not yet indexed in '<index>' (<n>/3 found). Waiting 30s before retrying.` | An initial load is waiting for the global maps |
| `IndexerDownloader: Global-map documents present in '<index>'. Starting initial load.` | The global maps are indexed; the initial load proceeds |
| `IndexerDownloader: Starting initial full load (slices=<n>)` | A full download started |
| `IndexerDownloader: Slice <i> (<i+1>/<n>) in progress — <n> documents so far, cursor '<c>', <s>s elapsed` | A sliced full download is advancing (one line per slice at most once a minute) |
| `IndexerDownloader: Slice <i> (<i+1>/<n>) complete — <n> docs in <ms>ms` | One slice of a full download finished (`interrupted` instead of `complete` when the module is stopping) |
| `IndexerDownloader: Download in progress — <n> documents so far, cursor '<c>', <s>s elapsed` | A sequential download (full load with `numSlices` = 1, or an incremental update) is advancing (at most once a minute) |
| `IndexerDownloader: Starting incremental update from offset <n>` | An incremental download started |
| `IndexerDownloader: Initial load download phase complete — <n> documents, cursor: '<n>'` | A full download finished |
| `IndexerDownloader: Incremental update download phase complete — <n> documents, new cursor: '<n>'` | An incremental download finished |
| `IndexerDownloader: Slice <i> failed: <error>` | One slice of a sliced full download failed; the whole download fails with it and is retried (same warning/debug split as the line below) |
| `IndexerDownloader: Initial load failed (<error>) — retrying in 30s.` | The indexer failed during a full download (a warning from the third attempt on; earlier attempts log at debug level) |
| `IndexerDownloader: Indexer index not ready (0 documents) — retrying in 30s.` | A full download found the feed index empty (a warning from the third attempt on; earlier attempts log at debug level) |
| `IndexerDownloader: Stop requested <when> — aborting.` (or `— slice <i> aborting.`, or `… while waiting for …`) | The module is stopping; the wait or download in progress is abandoned |
| `Action for 'vulnerability_feed_manager' failed: <error>.` | The update ended with an error; the next scheduled run retries it |
| `Rejected <n> on-demand request(s) with 404 <period>: unknown topic (last: '<topic>').` | `POST /ondemand` named a topic that is not registered (throttled: one line per burst) |
| `Rejected <n> on-demand update(s) with 503 <period>: the on-demand lane is full (4 slot(s)) (last topic: '<topic>').` | More than 4 on-demand requests were waiting; the extra ones were refused |
| `Answered <n> on-demand request(s) with 409 <period>: an update for that topic was already running (last: '<topic>').` | The on-demand request coincided with a run in progress; nothing was lost |
| `On-demand lane stopped; <n> queued update(s) were answered 503.` | The module stopped with on-demand requests still queued |
