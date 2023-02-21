from engine_schema.field import Field, FieldTree, IndexerType


def _ecs_to_indexer_type(ecs_type: str) -> IndexerType:
    if 'match_only_text' == ecs_type:
        return IndexerType.TEXT
    if 'constant_keyword' == ecs_type:
        return IndexerType.KEYWORD
    if 'wildcard' == ecs_type:
        return IndexerType.KEYWORD
    if 'flattened' == ecs_type:
        return IndexerType.OBJECT
    if 'number' == ecs_type:
        return IndexerType.LONG
    else:
        return IndexerType.from_str(ecs_type)


def _flat_entry_to_field(entry_name: str, entry_value: dict) -> Field:
    indexer_type = _ecs_to_indexer_type(entry_value['type'])
    description = entry_value["description"]

    # Indexer details
    indexer_details = None
    if 'ignore_above' in entry_value:
        indexer_details = {'ignore_above': entry_value['ignore_above']}

    return Field('ecs', entry_name, description, indexer_type, "array" in entry_value['normalize'], indexer_details)


def build_field_tree(flat_definition: dict) -> FieldTree:
    fieldTree = FieldTree()
    for name_path, entry in flat_definition.items():
        fieldTree.add_field(name_path, _flat_entry_to_field(name_path, entry))

    return fieldTree
