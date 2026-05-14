# CTI Offset Downloader stage

## Details

The [CTI offset downloader](../../src/components/CtiOffsetDownloader.hpp) stage is part of the Content Manager orchestration and is in charge of downloading content from a CTI API to be then processed by the following stages. The downloaded content is stored in one or multiple output files, whose paths will be then published for the consumers to read.

The output content files will be stored in any of the following output directories:
- Downloads folder: If the input files are compressed.
- Contents folder: If the input files are not compressed.

The download process can be summarized as follows:
1. Get the last CTI API consumer offset. This is done by performing an HTTP GET query to CTI. This value will be used as the last possible offset to query.
2. Set the range of offsets to be downloaded, starting from `currentOffset` (set in the context) and with a range-width of `1000`. So, for example, if the current offset is equal to `N`, the range will be from offset `N` to offset `N + 1000`.
3. Download the offsets range from **step 2**. The download will be retried indefinitely if the server responds with an 5xx HTTP error code. The `currentOffset` isn't updated in this phase but in the processing callback.
4. Dump the downloaded offsets into an output file. This file path will be generated as `<output-folder>/<currentOffset>-<contentFileName>`.
5. Push the new file path (from **step 4**) to the context [data paths](../../src/components/updaterContext.hpp).
6. If the last possible offset (from **step 1**) has been downloaded, the process finishes. Otherwise, the process continues with the **step 2**.

### Download process example

Given the following conditions:
- Last possible offset: `3200`.
- Initial current offset: `0` (first execution ever).
- Content compressed: No.
- Output folder: `/tmp/`.
- Content filename: `data.json`.

The output files will be:
- `/tmp/contents/1000-data.json` (data from offsets 0 to 1000)
- `/tmp/contents/2000-data.json` (data from offsets 1000 to 2000)
- `/tmp/contents/3000-data.json` (data from offsets 2000 to 3000)
- `/tmp/contents/3200-data.json` (data from offsets 3000 to 3200)

## Relation with the UpdaterContext

The context fields related to this stage are:

- `configData`
  + `url`: Used as the CTI API URL to download from.
  + `compressionType`: Used to determine whether the input file is compressed or not.
  + `contentfileName`: Used as name for the output content file.
- `downloadsFolder`: Used as output folder when the input file is compressed.
- `contentsFolder`: Used as output folder when the input file is not compressed.
- `data`: Used to read and update the paths under the `paths` key. The stage status is also updated on this member.
- `outputFolder`: Used as the destination file path base.
- `currentOffset`: Used as the first offset that will be fetched from the API. The next time the download begins from the offset read from the DB, only the processing data callback after a successful operation updates the value in the context.
