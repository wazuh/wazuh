# 006_bulk_error_visibility

Regression guard for per-item `_bulk` rejections: a document rejected by the indexer must not
corrupt or block the other documents sent in the same batch.

`template.json` is the production groups template with `group.uuid` removed from the mappings
(and from `query.default_field`). The mappings stay `dynamic: strict`, so the only input that
carries `group_uuid` (agent `003`) is rejected by OpenSearch with a per-item
`strict_dynamic_mapping_exception` inside an HTTP 200 `_bulk` response, while agents `001` and
`002` are indexed normally.

`result.json` therefore expects exactly agents `001` and `002`. The rejection itself is not
logged by the indexer connector today; asserting on that log output is not possible at this
level, only on index content.
