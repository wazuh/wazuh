# Offline Downloader stage

## Details

The `offline downloader` stage is part of the Content Manager orchestration and is in charge of copying an input file from the local filesystem to be processed by the following stages. The input file hash is calculated and stored in order to avoid processing the same file multiple times in the next orchestration executions.

The copy can be made into any of the two following output directories:
- Downloads folder: If the input file is compressed.
- Contents folder: If the input file is not compressed.

If the copy is successful, this stage also updates the context [data paths](../../src/components/updaterContext.hpp) with the copy destination path.

> Note: Despite the class name, there is no such download performed. The copy is made entirely locally.

## Relation with the UpdaterContext

The context fields related to this stage are:

- `configData`
  + `url`: Used as input file path. The prefix `file://` is allowed.
  + `compressionType`: Used to know whether the input file is compressed or not.
- `downloadsFolder`: Used as output folder when the input file is compressed.
- `contentsFolder`: Used as output folder when the input file is not compressed.
- `data`: Used to read and update the paths under the `paths` key. The stage status is also updated on this member.
- `outputFolder`: Used as the destination file path base.
- `downloadedFileHash`: Used to store the last input file hash. A file will be copied only if its hash is different from this one.
