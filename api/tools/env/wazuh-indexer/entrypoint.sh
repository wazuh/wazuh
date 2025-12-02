#!/bin/bash
set -e

if [[ "${SKIP_INDEXER_DOWNLOAD:-}" == "true" ]]; then
  echo "INFO: SKIP_INDEXER_DOWNLOAD is true -> skipping indexer artifact download"
else
  if [ -z "$GH_TOKEN" ]; then
    echo "ERROR: GH_TOKEN not set and SKIP_INDEXER_DOWNLOAD not enabled"
    echo "Set GH_TOKEN=<token> or SKIP_INDEXER_DOWNLOAD=true to skip this step"
    exit 1
  fi

  echo "Using GH_TOKEN (masked): ${GH_TOKEN:0:5}********"

  # Run download script (which may need sudo for certain operations)
  bash /usr/share/opensearch/download_indexer.sh || {
    echo "ERROR: download_indexer.sh failed. If this is a dev environment and you don't need remote artifacts, try setting SKIP_INDEXER_DOWNLOAD=true in your .env or docker-compose.${SKIP_INDEXER_DOWNLOAD:+ (SKIP_INDEXER_DOWNLOAD is currently set)}"
    exit 1
  }
fi

# Execute OpenSearch entrypoint (must be exec so OpenSearch runs as PID 1)
exec /usr/share/opensearch/opensearch-docker-entrypoint.sh
