import json
from typing import Tuple

import shared.resource_handler as rs

from .drivers import ecs, wazuh


def ECS_FLAT_URL(
    x): return f'https://raw.githubusercontent.com/elastic/ecs/{x}/generated/ecs/ecs_flat.yml'


def make_error(msg):
    print(msg)
    print('Aborted.')
    exit(1)


def generate(ecs_version: str, modules: list, resource_handler: rs.ResourceHandler) -> Tuple[dict, dict, dict, dict]:

    print(f'Using target ECS version: {ecs_version}')

    print('Loading resources...')
    ecs_flat_url = ECS_FLAT_URL(ecs_version)
    print(f'Downloading {ecs_flat_url}...')
    ecs_flat = resource_handler.download_file(ecs_flat_url)
    print(f'Loading schema template...')
    fields_template = resource_handler.load_internal_file('fields.template')
    print(f'Loading mappings template...')
    mappings_template = resource_handler.load_internal_file(
        'mappings.template')
    print(f'Loading logpar overrides template...')
    logpar_template = resource_handler.load_internal_file('logpar_types')

    # Generate field tree from ecs_flat
    print('Building field tree from ecs definition...')
    field_tree = ecs.build_field_tree(ecs_flat)
    field_tree.add_logpar_overrides(logpar_template['fields'])
    print('Success.')

    # Engine schema
    print('Generating engine schema...')
    engine_schema = dict()
    engine_schema['name'] = 'schema/engine-schema/0'
    engine_schema['fields'] = dict()
    engine_schema['fields'] = ecs.to_engine_schema(ecs_flat)

    # Add modules
    for module in modules:
        print(f'Adding module {module}...')
        print('Loading resources...')
        fields_definition, logpar_overrides, module_name = resource_handler.load_module_files(
            module)
        print('Generating field tree...')
        module_tree = wazuh.build_field_tree(fields_definition, module_name)
        print('Adding logpar overrides...')
        if logpar_overrides:
            module_tree.add_logpar_overrides(logpar_overrides)
        print('Merging module...')
        field_tree.merge(module_tree)
        print('Adding to engine schema...')
        engine_schema['fields'] = {
            **engine_schema['fields'], **wazuh.to_engine_schema(fields_definition, module_name)}
        print('Success.')

    # Get schema properties
    print('Generating fields schema properties...')
    jproperties = field_tree.get_jschema()
    fields_template['properties'] = {
        **fields_template['properties'], **jproperties}
    print('Success.')

    # Get index mappings
    print('Generating indexer mappings...')
    jmappings = field_tree.get_jmapping()
    mappings_template['template']['mappings']['properties'] = {
        **mappings_template['template']['mappings'].get('properties', {}),
        **jmappings
    }
    print('Success.')

    # Get the logpar configuration file
    print('Generating logpar configuration...')
    logpar_template['fields'] = field_tree.get_jlogpar()
    print('Success.')

    return fields_template, mappings_template, logpar_template, engine_schema
