# Zip Decompressor stage

## Details

The [zip decompressor](../../src/components/zipDecompressor.hpp) stage is part of the Content Manager orchestration and is in charge of decompressing the `.zip` files fetched in the download stage. If the decompression is successful, this stage also updates the context [data paths](../../src/components/updaterContext.hpp).

### Paths update example

Paths before stage execution:
```json
"paths": [
    "/tmp/outputFolder/downloads/file.zip"
]
```

`file.zip` content:
```bash
|-- data
|   |-- file_b.xml
|   `-- file_c.xml
`-- file_a.json
```

Paths after stage execution:
```json
"paths": [
    "/tmp/outputFolder/contents/file_a.json",
    "/tmp/outputFolder/contents/file_b.xml",
    "/tmp/outputFolder/contents/file_c.xml"
]
```

## Relation with the UpdaterContext

The context fields related to this stage are:

- `data`: Used to read and update the paths under the `paths` key. The stage status is also appended.
- `outputFolder`: Used to read the downloaded files and to store the decompressed files.
