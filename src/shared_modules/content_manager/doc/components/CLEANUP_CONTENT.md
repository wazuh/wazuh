# Cleanup Content stage

## Details

The [cleanup content](../../src/components/cleanUpContent.hpp) stage is part of the Content Manager orchestration and is in charge of cleaning the downloads folder by removing and re-creating it.

This stage is placed at the end of the orchestration and is useful for cleaning files that will no longer be needed in posterior executions.

> Note: This stage will not be instanciated if the `deleteDownloadedContent` config key is equal to `false`.

## Relation with the UpdaterContext

The context fields related to this stage are:

- `downloadsFolder`: Used to determine which folder to clean.
