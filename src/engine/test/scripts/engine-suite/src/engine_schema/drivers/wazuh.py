from engine_schema.field import Field, FieldTree, IndexerType


def _entry_to_field(entry_name: str, entry_value: dict) -> Field:
    indexer_type = IndexerType.from_str(entry_value['type'])
    description = entry_value["description"]
    array = False if 'array' not in entry_value else entry_value['array']

    # Indexer details
    indexer_details = None
    if 'ignore_above' in entry_value:
        indexer_details = {'ignore_above': entry_value['ignore_above']}

    return Field('ecs', entry_name, description, indexer_type, array, indexer_details)


def build_field_tree(yaml_definition: dict) -> FieldTree:
    fieldTree = FieldTree()
    for name_path, entry in yaml_definition.items():
        fieldTree.add_field(name_path, _entry_to_field(name_path, entry))

    return fieldTree
