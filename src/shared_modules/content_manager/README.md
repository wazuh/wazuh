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

```json
{
    "topicName": "test",
    "interval": 10,
    "ondemand": true,
    "configData":
    {
        "contentSource": "api",
        "compressionType": "raw",
        "versionedContent": "false",
        "deleteDownloadedContent": true,
        "url": "https://jsonplaceholder.typicode.com/todos/1",
        "outputFolder": "/tmp/testProvider",
        "dataFormat": "json",
        "contentFileName": "example.json",
        "s3FileName": "content.filtered_little.1.xz",
        "databasePath": "/tmp/content_updater/rocksdb",
        "offset": 0
    }
}
```
