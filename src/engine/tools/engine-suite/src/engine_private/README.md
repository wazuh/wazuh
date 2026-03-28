# Engine Private

## CM commands

The CM private commands operate with JSON payloads for resources and policies.

- `cm get` returns JSON output by default.
- `cm upsert` expects JSON content from `--content` or `stdin`.
- `cm policy-upsert` expects JSON content from `--content` or `stdin`.

The protobuf request fields still keep legacy names such as `ymlContent`, but for CM resources and policies the
effective payload format is JSON.
