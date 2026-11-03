#! /bin/sh

# The manager configuration reference is generated from the schema: refuse to build a stale copy.
python3 "$(dirname "$0")/tools/gen-manager-conf-ref.py" --check || exit 1

mdbook build || exit 1

# Links, anchors, page publication, example syntax and diagrams, over the book and the developer
# READMEs; it reads heading ids from the book just built.
python3 "$(dirname "$0")/tools/check-docs.py" --book book
