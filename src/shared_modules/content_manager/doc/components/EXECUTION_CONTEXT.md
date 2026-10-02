# Execution Context stage

## Details

The [ExecutionContext](../../src/components/executionContext.hpp) stage prepares the shared
`UpdaterBaseContext` of a topic. `ActionOrchestrator` runs it **once, when the provider is created**,
not on every update.

It performs, in order:

- **Database initialization** (only when `configData.databasePath` is present and non-empty):
  - creates `databasePath` if it does not exist and opens the RocksDB database
    `<databasePath>/updater_<topicName>_metadata`;
  - creates the `current_offset` and `downloaded_file_hash` columns when missing;
  - loads the last `downloaded_file_hash` value (empty on a first run);
  - reads the stored offset from `current_offset`; when there is none it writes `"0"`;
  - reads `configData.offset` (required here, must be non-negative) and, when it is greater than the
    stored offset, writes it to `current_offset`.

  The [Indexer Downloader](INDEXER_DOWNLOADER.md) treats a stored `"0"` as "no cursor" and performs an
  initial load; any other value is the lower bound of an incremental update.
- **Output folders creation** (only when `configData.contentSource` is not `indexer`): sets
  `outputFolder` from `configData.outputFolder` (default: `<temp dir>/output_folder`), deletes it if it
  exists, and creates it with its `downloads/` and `contents/` subfolders. The Indexer pipeline streams
  pages to the callback and never uses them.
- **User agent**: sets `httpUserAgent` to `<consumerName>/<version>`. A missing or empty
  `configData.consumerName` throws `Missing or empty consumerName`, which fails the provider creation.

## Relation with the UpdaterContext

The context fields related to this stage are:

- `configData`
  + `databasePath`: Location of the database.
  + `offset`: Overrides the stored offset when greater.
  + `contentSource`: Decides whether the output folders are created.
  + `outputFolder`: Output folder, when created.
  + `consumerName`: Base of the user agent.
- `topicName`: Used to compose the name of the database.
- `spRocksDB`: Database connector this stage opens.
- `outputFolder`, `downloadsFolder`, `contentsFolder`: Set when the output folders are created.
- `downloadedFileHash`: Loaded from the database.
- `httpUserAgent`: Set from `consumerName`.
