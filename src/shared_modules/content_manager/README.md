# Content Manager

The Content Manager is a module that is in charge of obtaining the Wazuh Content from an external repository, as well as maintaining the periodic updates that the manager will obtain.

## Usage

The input configuration of the Content Manager is described below:

- `topicName`: Topic name, used to represent the actions being executed.
- `interval`: Interval, in seconds, between each action execution.
- `ondemand`: If true, the module will be executed on demand.
- `configData`: Configuration data to create the orchestration of the module.
  + `contentSource`: Source of the content. Can be any of `api`, `cti-api`, `file`, or `offline`.
  + `compressionType`: Compression type of the content. Can be any of `gzip`, `zip`, or `xz`.
  + `versionedContent`: Type of versioned content. Can be any of `false` (content versioning disabled) or `cti-api`.
  + `deleteDownloadedContent`: If true, the downloaded content will be deleted after being processed.
  + `url`: URL from where the content will be downloaded or copied.
  + `outputFolder`: If defined, the content (downloads and uncompressed content) will be downloaded in this folder.
  + `dataFormat`: Content data format. Examples: `json`, `xml`, `txt`.
  + `contentFileName`: Used by some downloaders to know where to store the downloaded content.
  + `databasePath`: Path from where the RocksDB database should be read. The database stores the last offset fetched (when using the `cti-api` content source).

### Download offsets from CTI API

```json
{
    "topicName": "CTI API offset fetching",
    "interval": 10,
    "ondemand": true,
    "configData":
    {
        "contentSource": "cti-api",
        "compressionType": "raw",
        "versionedContent": "cti-api",
        "deleteDownloadedContent": true,
        "url": "https://cti-dev.wazuh.com/api/v1/catalog/contexts/test_context/consumers/test_consumer",
        "outputFolder": "/tmp/output_folder",
        "dataFormat": "json",
        "contentFileName": "content.json",
        "databasePath": "/tmp/content_updater/rocksdb"
    }
}
```

The config above will make the Content Manager to launch each `10` seconds an orchestration that will download the content offsets from the Wazuh CTI API (context: `test_context`, consumer: `test_consumer`). The Content Manager will store the offsets, by groups of 1000, into output files located at `/tmp/output_folder`.

Executing the Content Manager for the first time, with a starting with offset `975000`, will download from offset `975000` to the last available offset (`978576` on this example):
```bash
# ./content_manager_test_tool 
ActionOrchestrator - Starting process
API offset to be used: 975000
Output folders created.
FactoryContentUpdater - Starting process
Creating 'cti-api' downloader
Creating 'raw' content decompressor
Creating 'cti-api' version updater
Downloaded content cleaner created
FactoryContentUpdater - Finishing process
ActionOrchestrator - Finishing process
ActionOrchestrator - Running process
CtiApiDownloader - Starting
CtiApiDownloader - Request processed successfully.
CtiApiDownloader - Request processed successfully.
CtiApiDownloader - Request processed successfully.
CtiApiDownloader - Request processed successfully.
CtiApiDownloader - Request processed successfully.
CtiApiDownloader - Finishing
SkipStep - Executing
PubSubPublisher - Data published
```

The output files containing the downloaded offsets are available under `output_folder/contents/`, each of one contains 1000 offsets:
```bash
# tree /tmp/output_folder/
/tmp/output_folder/
|-- contents
|   |-- 976000-content.json
|   |-- 977000-content.json
|   |-- 978000-content.json
|   `-- 978576-content.json
`-- downloads

2 directories, 4 files
```

Given that we are using the `cti-api` content versioner, the last offset fetched is stored and used in the next execution. This is useful to avoid downloading offsets that we have already downloaded. In the log below, we can see that the Content Manager is starting with the last offset from the first execution and, since there are no more offsets to download, nothing is downloaded nor published.

```bash
# ./content_manager_test_tool 
ActionOrchestrator - Starting process
API offset to be used: 978576
The previous output folder: "/tmp/output_folder" will be removed.
Output folders created.
FactoryContentUpdater - Starting process
Creating 'cti-api' downloader
Creating 'raw' content decompressor
Creating 'cti-api' version updater
Downloaded content cleaner created
FactoryContentUpdater - Finishing process
ActionOrchestrator - Finishing process
ActionOrchestrator - Running process
CtiApiDownloader - Starting
CtiApiDownloader - Request processed successfully.
CtiApiDownloader - Finishing
SkipStep - Executing
PubSubPublisher - No data data to publish
All files in the folder have been deleted.
```
