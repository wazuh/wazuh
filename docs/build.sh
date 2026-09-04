#! /bin/sh

# The manager configuration reference is generated from the schema: refuse to build a stale copy.
python3 "$(dirname "$0")/tools/gen-manager-conf-ref.py" --check || exit 1

mdbook build
