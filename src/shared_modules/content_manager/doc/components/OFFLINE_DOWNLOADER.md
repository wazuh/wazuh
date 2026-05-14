# Offline Downloader stage

## Details

The [offline downloader](../../src/components/offlineDownloader.hpp) stage is part of the Content Manager orchestration and is in charge of downloading a file in offline mode by whether copying a file from the local filesystem or downloading it from an HTTP server (the stage will deduce which approach to use depending on the URL prefix). The input file hash is calculated and stored in order to avoid processing the same file multiple times in the next orchestration executions.

The download will be made into any of the following output directories:
- Downloads folder: If the input file is compressed.
- Contents folder: If the input file is not compressed.

If the download is successful, this stage also updates the context [data paths](../../src/components/updaterContext.hpp) field with the destination path of the downloaded file. For the copy case, if the input file doesn't exist, no paths will be appended.

## Relation with the UpdaterContext

The context fields related to this stage are:

- `configData`
  + `url`: Used as input file URL. **IMPORTANT**: If it has the `file://` prefix, the file will be copied from the filesystem. If it has the `http://` or `https://` prefixes, the file will be downloaded from a server pointed by the URL. Any other prefix will invalidate the URL.
  + `compressionType`: Used to know whether the input file is compressed or not.
- `downloadsFolder`: Used as output folder when the input file is compressed.
- `contentsFolder`: Used as output folder when the input file is not compressed.
- `data`: Used to read and update the paths under the `paths` key. The stage status is also updated on this member.
- `outputFolder`: Used as the destination file path base.
- `downloadedFileHash`: Used to store the last input file hash. A file will be copied only if its hash is different from this one.
