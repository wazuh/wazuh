# Xz Decompressor stage

## Details

The [XZ decompressor](../../src/components/XZDecompressor.hpp) stage is part of the Content Manager orchestration and is in charge of decompressing the `.xz` files fetched in the download stage. If the decompression is successful, this stage updates the [context data](../../src/components/updaterContext.hpp) paths and stage status.

### Paths update example

Paths before stage execution:
```json
"paths": [
    "/tmp/outputFolder/downloads/file1.json.xz",
    "/tmp/outputFolder/downloads/file2.xml.xz"
]
```

Paths after stage execution:
```json
"paths": [
    "/tmp/outputFolder/contents/file1.json",
    "/tmp/outputFolder/contents/file2.xml"
]
```

> Note: In order to generate the output files names, the stage copies the input files names and removes their final extensions. That being said, if an input file name has only the `.xz` extension, its respective output file will have no extension at all. For example, for an input file called `content.xz`, the output file will be called just `content`.

## Relation with the UpdaterContext

The context fields related to this stage are:

- `data`: Used to read and update the paths and stage status.
- `outputFolder`: Used to read the downloaded files and to store the decompressed files.
