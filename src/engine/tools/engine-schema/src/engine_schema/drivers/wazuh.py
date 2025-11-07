from engine_schema.field import Field, FieldTree, IndexerType


def _entry_to_field(module_name: str, entry_name: str, entry_value: dict) -> Field:
    indexer_type = IndexerType.from_str(entry_value['type'])
    description = entry_value["description"]
    array = False if 'array' not in entry_value else entry_value['array']

    # Indexer details
    indexer_details = None
    if 'ignore_above' in entry_value:
        indexer_details = {'ignore_above': entry_value['ignore_above']}

    return Field(module_name, entry_name, description, indexer_type, array, indexer_details)


def build_field_tree(yaml_definition: dict, module_name: str) -> FieldTree:
    fieldTree = FieldTree()
    for name_path, entry in yaml_definition.items():
        fieldTree.add_field(name_path, _entry_to_field(module_name, name_path, entry))

    return fieldTree

def to_engine_schema(yaml_definition: dict, module_name: str) -> dict:
    engine_schema = dict()

    for name_path, entry in yaml_definition.items():
        field = _entry_to_field(module_name, name_path, entry)
        engine_schema[field.name] = dict()
        engine_schema[field.name]['type'] = str(field.indexer_type)
        engine_schema[field.name]['array'] = field.array

    return engine_schema
