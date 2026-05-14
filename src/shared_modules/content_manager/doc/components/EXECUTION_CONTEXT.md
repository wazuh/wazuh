# Execution Context stage

## Details

The [execution context](../../src/components/executionContext.hpp) stage is part of the Content Manager orchestration initialization and is in charge of preparing the execution environment before any orchestration is started. This stage implementation can be seen in the [ExecutionContext](../../src/components/executionContext.hpp) class.

The tasks that this stage performs are:
- **Set up context**: Configure some of the fields present on the Updater Context.
- **Database initialization**: Initializes the RocksDB database, creating the necessary columns, and retrieving the API offset stored in it as well as the last downloaded file hash. It also defines which offset will be considered as the current one between the offset in the database and the offset in the input configuration.
- **Output folders creation**: It creates the folders needed to store the execution files, such as downloaded and uncompressed files. If the output folder already exists, it gets deleted and re-created.

It is important to note that this stage is only called once for each Content Manager execution.

## Relation with the UpdaterContext

The context fields related to this stage are:

- `configData`
  + `outputFolder`: Used to set the output folder.
  + `databasePath`: Used to set the database files location.
  + `offset`: Used to override (if greater than) the offset from the database.
- `topicName`: Used to compose the name of the database.
- `spRocksDB`: Used to initialize the database connector.
- `outputFolder`: Used to create the output files location.
- `downloadedFileHash`: Used to store the file hash from the database.
