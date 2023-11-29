# Content Manager

The Content Manager is a module that is in charge of obtaining the Wazuh Content from an external repository, as well as maintaining the periodic updates that the manager will obtain.

## Usage

The input configuration of the Content Manager is described below:

- `topicName`: Topic name, used to represent the actions being executed.
- `interval`: Interval, in seconds, between each action execution.
- `ondemand`: If `true`, the module will be executed on demand.
- `configData`: Configuration data to create the orchestration of the module.
  + `contentSource`: Source of the content. Can be any of `api`, `cti-api`, `file`, or `offline`. See the [use cases section](#use-cases) for more information.
  + `compressionType`: Compression type of the content. Can be any of `gzip`, `zip`, `xz`, or `raw`.
  + `versionedContent`: Type of versioned content. Can be any of `false` (content versioning disabled) or `cti-api` (only useful if using the `cti-api` content source).
  + `deleteDownloadedContent`: If `true`, the downloaded content will be deleted after being processed.
  + `url`: URL from where the content will be downloaded or copied. Depending on the `contentSource` type, it supports HTTP/S and filesystem paths.
  + `outputFolder`: If defined, the content (downloads and uncompressed content) will be downloaded in this folder.
  + `dataFormat`: Content data format. Examples: `json`, `xml`, `txt`, etc.
  + `contentFileName`: Used as output content file name by the API and CTI API downloaders. If not provided, it will be defaulted as `<temp_dir>/output_folder`, being `<temp_dir>` a directory location suitable for temporary files.
  + `databasePath`: Path for the RocksDB database. The database stores the last offset fetched (when using the `cti-api` content source).

> The Content Manager counts with a [test tool](./testtool/main.cpp) that can be used to perform tests, try out different configurations, and to better understand the module.

## Use cases

The Content Manager module can be used in many ways depending on the user's needs. Here is a summary of the possible use cases:

- [Download offsets from CTI API](#download-offsets-from-cti-api)
- [Download from regular API](#download-from-regular-api)
- [Remote file download](#remote-file-download)
- [Offline download](#offline-download)

### Download offsets from CTI API

One of the most important capabilities of the Content Manager is to download content deltas (called _offsets_) from a _Cyber Threat Intelligence_ (CTI) API. The module will try to download all available offsets, starting from the last offset fetched from the previous execution (stored in the RocksDB database), until it reaches the last offset available in the API.

All the downloaded content will be stored in the filesystem, making it available to other modules that may want to consume it.

```json
{
    "topicName": "CTI API offset fetching",
    "interval": 10,
    "ondemand": false,
    "configData":
    {
        "contentSource": "cti-api",
        "compressionType": "raw",
        "versionedContent": "cti-api",
        "deleteDownloadedContent": true,
        "url": "https://cti.wazuh.com/api/v1/catalog/contexts/test_context/consumers/test_consumer",
        "outputFolder": "/tmp/output_folder",
        "contentFileName": "content.json",
        "databasePath": "/tmp/content_updater/rocksdb"
    }
}
```

> For simplicity, only the usage case-related configurations are shown.

The configuration above will make the Content Manager launch each `10` seconds an orchestration that will download the content offsets from the Wazuh CTI API (context: `test_context`, consumer: `test_consumer`). The Content Manager will store the offsets, by groups of 1000, into output files located in `/tmp/output_folder`.

Executing the Content Manager for the first time, with a starting offset of `975000`, will download from offset `975000` to the last available offset (`978576` in this example).

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

The output files containing the downloaded offsets are available under `output_folder/contents/`, each of which contains 1000 offsets (the last one can contain fewer offsets if the total amount of offsets is not multiple of 1000).

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

> If the content was compressed, the output files would be stored in the _downloads_ folder.

The `/tmp/output_folder/contents/*-content.json` paths are published for the consumers to read.

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
PubSubPublisher - No data to publish
All files in the folder have been deleted.
```

### Download from regular API

The Content Manager can also download content from a regular API. The functionality is quite straightforward: Download from a given URL and store the content in an output file. No API parameters are handled nor added by the module.

```json
{
    "topicName": "API content download",
    "interval": 5,
    "ondemand": false,
    "configData":
    {
        "contentSource": "api",
        "compressionType": "raw",
        "url": "https://jsonplaceholder.typicode.com/todos/1",
        "outputFolder": "/tmp/output_folder",
        "contentFileName": "content.json"
    }
}
```

> For simplicity, only the usage case-related configurations are shown.

The configuration above will make the Content Manager launch each `5` seconds an orchestration that will download the content from the API `https://jsonplaceholder.typicode.com/todos/1` and store the content in `/tmp/output_folder`.


```bash
# ./content_manager_test_tool
ActionOrchestrator - Starting process
API offset to be used: 0
Output folders created.
FactoryContentUpdater - Starting process
Creating 'api' downloader
Creating 'raw' content decompressor
Version updater not needed
Downloaded content cleaner created
FactoryContentUpdater - Finishing process
ActionOrchestrator - Finishing process
ActionOrchestrator - Running process
APIDownloader - Starting
APIDownloader - Finishing - Download done successfully
SkipStep - Executing
PubSubPublisher - Data published
SkipStep - Executing
All files in the folder have been deleted.
```

The downloaded content will be all stored in a unique file called `content.json`:

```bash
# tree /tmp/output_folder/  
/tmp/output_folder/
|-- contents
|   `-- content.json
`-- downloads

2 directories, 1 file
```

```bash
# cat /tmp/output_folder/contents/content.json
{
  "userId": 1,
  "id": 1,
  "title": "delectus aut autem",
  "completed": false
}
```

> If the content was compressed, the output file would be stored in the _downloads_ folder.

The `/tmp/output_folder/contents/content.json` path is published for the consumers to read.

### Remote file download

The Content Manager has the capability of downloading a content file from a URL. The file will be stored in the output folder and, if compressed, it will be decompressed in the contents folder.

When downloading files, the Content Manager keeps track of the last downloaded file hash. In this way, if downloading the same file twice in a row, the second time no data will be published, preventing the consumers from re-process the content.

```json
{
    "topicName": "File content download",
    "interval": 5,
    "configData":
    {
        "contentSource": "file",
        "compressionType": "zip",
        "deleteDownloadedContent": false,
        "url": "https://cti.wazuh.com/cti-snapshots/store/contexts/test_context/consumers/test_consumer/1000_2000.zip",
        "outputFolder": "/tmp/output_folder"
    }
}
```

> For simplicity, only the usage case-related configurations are shown.

The configuration above will make the Content Manager launch each `5` seconds an orchestration that will download a compressed (ZIP) content file from a URL.

```bash
# ./content_manager_test_tool
ActionOrchestrator - Starting process
API offset to be used: 0
Output folders created.
FactoryContentUpdater - Starting process
Creating 'file' downloader
Creating 'zip' content decompressor
Version updater not needed
Downloaded content cleaner not needed
FactoryContentUpdater - Finishing process
ActionOrchestrator - Finishing process
ActionOrchestrator - Running process
FileDownloader - Download done successfully
ZipDecompressor - Finishing process
PubSubPublisher - Data published
SkipStep - Executing
SkipStep - Executing
Action: Initiating scheduling action for test
ActionOrchestrator - Running process
Content file didn't change from last download
FileDownloader - Download done successfully
ZipDecompressor - Finishing process
PubSubPublisher - No data to publish
SkipStep - Executing
SkipStep - Executing
```

The content is downloaded and, since it's compressed, stored in the _downloads_ folder, and decompressed in the _contents_ folder. If `deleteDownloadedContent` was equal to `true`, the compressed file would be deleted after the decompression, just keeping the JSON data file.

```bash
# tree /tmp/output_folder/
/tmp/output_folder/
|-- contents
|   `-- test_context_test_consumer_1000_2000.json
`-- downloads
    `-- 1000_2000.zip

2 directories, 2 files
```

The `/tmp/output_folder/contents/test_context_test_consumer_1000_2000.json` path is published for the consumers to read. The second time the orchestration is launched, no data is published since the downloaded file didn't change.

### Offline download

The Content Manager has the capability of processing a content file in an offline mode: Depending on the URL prefix, the content source will be either copied from the local filesystem or downloaded from a local HTTP server.

The file will be stored in the output folder and, if compressed, it will be decompressed in the contents folder.

When processing files, the Content Manager keeps track of the last processed file hash. In this way, if processing the same file twice in a row, the second time no data is published, preventing the consumers from re-process the content.

In the offline mode, the compression type is deduced from the URL extension, ignoring the compression type set in the input configuration. For example, if the URL finishes with the `.xz` prefix, an XZ decompressor will be instantiated in the orchestration. Any extension outside the supported ones will be treated as a raw (not compressed) file format.

```json
{
    "topicName": "Offline content download from filesystem",
    "interval": 120,
    "configData":
    {
        "contentSource": "offline",
        "deleteDownloadedContent": false,
        "url": "file:///home/data/content.xz",
        "outputFolder": "/tmp/output_folder",
        "dataFormat": "xml"
    }
}
```

```json
{
    "topicName": "Offline content download from HTTP server",
    "interval": 120,
    "configData":
    {
        "contentSource": "offline",
        "deleteDownloadedContent": false,
        "url": "http://localhost:8888/content.xz",
        "outputFolder": "/tmp/output_folder",
        "dataFormat": "xml"
    }
}
```

> For simplicity, only the usage case-related configurations are shown.

The configurations above will make the Content Manager launch each `120` seconds an orchestration that will process a compressed (XZ) content file copied from the filesystem and downloaded from an HTTP server, respectively.

The URL prefix is very important: If it's equal to `file://`, it will try to copy the file from the filesystem. If it's equal to `http://` of `https://`, it will try to download the file from a server. Any other prefix is not allowed.

```bash
# ./content_manager_test_tool
ActionOrchestrator - Starting process
API offset to be used: 0
Output folders created.
FactoryContentUpdater - Starting process
Creating 'offline' downloader
Creating 'xz' content decompressor
Version updater not needed
Downloaded content cleaner not needed
FactoryContentUpdater - Finishing process
ActionOrchestrator - Finishing process
ActionOrchestrator - Running process
OfflineDownloader - Download done successfully
PubSubPublisher - Data published
SkipStep - Executing
SkipStep - Executing
```

```bash
# tree /tmp/output_folder/
/tmp/output_folder/
|-- contents
|   `-- content.xml
`-- downloads
    `-- content.xz

2 directories, 2 files
```

The content is downloaded (or copied) and, since it's compressed, stored in the _downloads_ folder, and decompressed in the _contents_ folder. If `deleteDownloadedContent` was equal to `true`, the compressed file would be deleted after the decompression, just keeping the XML data.

The `/tmp/output_folder/contents/content.xml` path is published for the consumers to read.
