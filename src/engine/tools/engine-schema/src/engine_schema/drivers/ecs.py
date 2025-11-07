from engine_schema.field import Field, FieldTree, IndexerType


def _flat_entry_to_field(entry_name: str, entry_value: dict) -> Field:
    indexer_type = IndexerType.from_str(entry_value['type'])
    description = entry_value["description"]

    # Indexer details
    indexer_details = None
    if 'ignore_above' in entry_value:
        indexer_details = {'ignore_above': entry_value['ignore_above']}
    if 'scaling_factor' in entry_value:
        indexer_details = {'scaling_factor': entry_value['scaling_factor']}

    if 'multi_fields' in entry_value:
        if not indexer_details:
            indexer_details = dict()

        indexer_details['multi_fields'] = entry_value['multi_fields']
        for field in indexer_details['multi_fields']:
            field['type'] = str(IndexerType.from_str(field['type']))

    return Field('ecs', entry_name, description, indexer_type, indexer_details)


def build_field_tree(flat_definition: dict) -> FieldTree:
    fieldTree = FieldTree()
    for name_path, entry in flat_definition.items():
        fieldTree.add_field(name_path, _flat_entry_to_field(name_path, entry))

    return fieldTree

def to_engine_schema(flat_definition: dict) -> dict:
    engine_schema = dict()

    for name_path, entry in flat_definition.items():
        field = _flat_entry_to_field(name_path, entry)
        engine_schema[field.name] = dict()
        engine_schema[field.name]['type'] = str(field.indexer_type)

    return engine_schema
