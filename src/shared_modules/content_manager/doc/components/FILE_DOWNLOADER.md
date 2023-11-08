# File Downloader stage

## Details

The [file downloader](../../src/components/fileDownloader.hpp) stage is part of the Content Manager orchestration and is in charge of downloading an input file from a given URL to be processed by the following stages. The input file hash is calculated and stored in order to avoid processing the same file multiple times in the next orchestration executions.

The download will be made into any of the following output directories:
- Downloads folder: If the downloaded file is compressed.
- Contents folder: If the downloaded file is not compressed.

If the download is successful, this stage also updates the context [data paths](../../src/components/updaterContext.hpp) field with the destination path of the downloaded file.

## Relation with the UpdaterContext

The context fields related to this stage are:

- `configData`
  + `url`: Used as the URL from where the file will be downloaded.
  + `compressionType`: Used to know whether the downloaded file is compressed or not.
  + `contentfileName`: Used as name for the output content file.
- `downloadsFolder`: Used as output folder when the downloaded file is compressed.
- `contentsFolder`: Used as output folder when the downloaded file is not compressed.
- `data`: Used to read and update the paths under the `paths` key. The stage status is also updated on this member.
- `outputFolder`: Used as the destination file path base.
- `downloadedFileHash`: Used to store the last input file hash. A filepath will be published only if its file hash is different from this one.
