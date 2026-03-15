# VD Indexer smoke fixtures

Safe fixtures and smoke checks for validating the Vulnerability Detector indexer-sourced feed path.

## What is included

- `payloads/mapping.json`: index mapping for the smoke index.
- `payloads/cve_2024_1234_published.json`: realistic PUBLISHED CVE payload.
- `payloads/cve_2024_5678_published.json`: realistic PUBLISHED CVE payload.
- `payloads/cve_2024_9999_rejected.json`: realistic REJECTED CVE payload.
- `payloads/query_incremental_offset_gt_1001.json`: incremental validation query.
- `vd_indexer_smoke.sh`: safe smoke workflow script.

## Safety defaults

- Uses a dedicated index by default: `.cti-cves-smoke`.
- Does not delete anything unless `--reset` or `--cleanup` is explicitly provided.
- Existing index is reused in safe mode.

## Usage

From this directory:

```bash
chmod +x ./vd_indexer_smoke.sh
./vd_indexer_smoke.sh --seed --verify
```

By default, `--verify` includes assertions:

- `_count` must match `EXPECTED_COUNT` (default `3`)
- incremental `_search` total must match `EXPECTED_INCREMENTAL_TOTAL` (default `2`)
- incremental hit IDs must match `EXPECTED_INCREMENTAL_IDS` (default `CVE-2024-5678,CVE-2024-9999`)

With custom connection settings:

```bash
INDEXER_URL=https://localhost:9200 \
INDEXER_USER=admin \
INDEXER_PASS=admin \
INDEX_NAME=.cti-cves-smoke \
./vd_indexer_smoke.sh --seed --verify
```

To customize assertions:

```bash
EXPECTED_COUNT=3 \
EXPECTED_INCREMENTAL_TOTAL=2 \
EXPECTED_INCREMENTAL_IDS="CVE-2024-5678,CVE-2024-9999" \
./vd_indexer_smoke.sh --verify
```

To skip assertions and only print verification payloads:

```bash
./vd_indexer_smoke.sh --verify --no-assert
```

To force a clean run:

```bash
./vd_indexer_smoke.sh --seed --reset --verify
```

To remove smoke index at the end:

```bash
./vd_indexer_smoke.sh --seed --verify --cleanup
```

## Why these payloads

The payloads follow the same shape consumed by the indexer downloader path:

- `offset`
- `document.cveMetadata.cveId`
- `document.cveMetadata.state` (`PUBLISHED` or `REJECTED`)

This allows end-to-end checks for initial/incremental feed ingestion and REJECTED handling.
