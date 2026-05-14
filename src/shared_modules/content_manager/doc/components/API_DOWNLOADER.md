# API Downloader stage

## Details

The [API downloader](../../src/components/APIDownloader.hpp) stage is part of the Content Manager orchestration and is in charge of downloading content from an API to be then processed by the following stages. The downloaded content is stored in an output file, whose path will be then published for the consumers to read.

The output content file can be stored into any of the two following output directories:
- Downloads folder: If the input file is compressed.
- Contents folder: If the input file is not compressed.

If the download is successful, this stage also updates the context [data paths](../../src/components/updaterContext.hpp) with the download destination path.

## Relation with the UpdaterContext

The context fields related to this stage are:

- `configData`
  + `url`: Used as the API URL to download from.
  + `compressionType`: Used to determine whether the input file is compressed or not.
  + `contentfileName`: Used as name for the output content file.
- `downloadsFolder`: Used as output folder when the input file is compressed.
- `contentsFolder`: Used as output folder when the input file is not compressed.
- `data`: Used to read and update the paths under the `paths` key. The stage status is also updated on this member.
- `outputFolder`: Used as the destination file path base.
