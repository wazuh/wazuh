# Gzip Decompressor stage

## Details

The [gzip decompressor](../../src/components/gzipDecompressor.hpp) stage is part of the Content Manager orchestration and is in charge of decompressing the `.gz` files fetched in the download stage. If the decompression is successful, this stage also updates the context [data paths](../../src/components/updaterContext.hpp).

### Paths update example

Paths before stage execution:
```json
"paths": [
    "/tmp/outputFolder/downloads/file1.json.gz",
    "/tmp/outputFolder/downloads/file2.xml.gz"
]
```

Paths after stage execution:
```json
"paths": [
    "/tmp/outputFolder/contents/file1.json",
    "/tmp/outputFolder/contents/file2.xml"
]
```

> Note: In order to generate the output files names, the stage copies the input files names and removes their final extensions. That being said, if an input file name has only the `.gz` extension, its respective output file will have no extension at all. For example, for an input file called `content.gz`, the output file will be called just `content`.

## Relation with the UpdaterContext

The context fields related to this stage are:

- `data`: Used to read and update the paths under the `paths` key.
- `outputFolder`: Used to read the downloaded files and to store the decompressed files.
