from typing import Dict, Set, Tuple
from copy import deepcopy

import shared.resource_handler as rs

from .drivers import ecs


def _is_allowed(path: str, allowed: Set[str]) -> bool:
    """Matches if exact or if there is an allowed prefix (e.g., 'a.b' allows 'a.b.c')."""
    if path in allowed:
        return True
    for p in allowed:
        if path.startswith(p + "."):
            return True
    return False


def _partition_schema(props: Dict[str, dict], allowed: Set[str], parent_path: str = "") -> Tuple[Dict[str, dict], Dict[str, dict]]:
    """Splits a property dictionary into (rules_props, dec_props) preserving the structure."""
    rules_props: Dict[str, dict] = {}
    dec_props: Dict[str, dict] = {}

    for name, schema in props.items():
        full_path = name if not parent_path else f"{parent_path}.{name}"
        r_node, d_node = _partition_node(schema, full_path, allowed)
        if r_node is not None:
            rules_props[name] = r_node
        if d_node is not None:
            dec_props[name] = d_node

    return rules_props, dec_props


def _partition_node(schema: dict, path: str, allowed: Set[str]) -> Tuple[dict | None, dict | None]:
    """
    Returns (schema_para_rules, schema_para_decoders) for this node.
    Preserves 'properties' or 'items.properties' when filtering children.
    """
    allowed_here = _is_allowed(path, allowed)

    # Detect children (object or object array)
    has_obj_children = isinstance(schema, dict) and 'properties' in schema and isinstance(schema['properties'], dict)
    has_array_obj_children = (
        isinstance(schema, dict) and
        'items' in schema and isinstance(schema['items'], dict) and
        'properties' in schema['items'] and isinstance(schema['items']['properties'], dict)
    )

    # If the path is allowed, the entire subtree goes to rules and nothing to decoders.
    if allowed_here:
        return deepcopy(schema), None

    # If not allowed here, there may be allowed descendants.
    if has_obj_children:
        r_children, d_children = _partition_schema(schema['properties'], allowed, path)

        # rules: include only if there are allowed children
        r_copy = None
        if r_children:
            r_copy = deepcopy(schema)
            r_copy['properties'] = r_children

        # decoders: include the node with the children that did not go to rules (plugin)
        d_copy = None
        if d_children:
            d_copy = deepcopy(schema)
            d_copy['properties'] = d_children
        else:
            # If there are no children left and the node was not allowed, we do not contribute anything to decoders.
            d_copy = None

        return r_copy, d_copy

    if has_array_obj_children:
        r_children, d_children = _partition_schema(schema['items']['properties'], allowed, path)

        r_copy = None
        if r_children:
            r_copy = deepcopy(schema)
            r_copy['items']['properties'] = r_children

        d_copy = None
        if d_children:
            d_copy = deepcopy(schema)
            d_copy['items']['properties'] = d_children

        return r_copy, d_copy

    return None, deepcopy(schema)


def _build_fields_schema(base_template: dict, properties: dict, file_id: str, name: str) -> dict:
    t = deepcopy(base_template)
    t['$id'] = file_id            # p.ej. "rule_fields.json" or "decoder_fields.json"
    t['name'] = name              # p.ej. "schema/rule-fields/0"
    t['properties'] = properties  # filtered tree
    return t


def generate(wcs_path: str, resource_handler: rs.ResourceHandler, allowed_fields_path: str) -> Tuple[dict, dict, dict, dict, dict]:

    print('Loading resources...')
    print(f'Loading WCS file from {wcs_path}...')
    wcs_flat = resource_handler.load_file(wcs_path)
    print(f'Loading schema template...')
    fields_template = resource_handler.load_internal_file('fields.template')
    print(f'Loading mappings template...')
    mappings_template = resource_handler.load_internal_file(
        'mappings.template')
    print(f'Loading logpar overrides template...')
    logpar_template = resource_handler.load_internal_file('logpar_types')

    # Generate field tree from ecs_flat
    print('Building field tree from WCS definition...')
    field_tree = ecs.build_field_tree(wcs_flat)
    field_tree.add_logpar_overrides(logpar_template["fields"])
    print('Success.')

    # Engine schema
    print('Generating engine schema...')
    engine_schema = dict()
    engine_schema['name'] = 'schema/engine-schema/0'
    engine_schema['fields'] = dict()
    engine_schema['fields'] = ecs.to_engine_schema(wcs_flat)

    # Get schema properties
    print('Generating fields schema properties...')
    jproperties = field_tree.get_jschema()
    # Load allowed_fields.json
    allowed_json = resource_handler.load_file(allowed_fields_path)
    allowed_set = set(allowed_json.get('allowed_fields', {}).get('rule', []))

    # Split the tree
    rules_props, dec_props = _partition_schema(jproperties, allowed_set, parent_path="")

    # Build the two schemas from the template
    rule_fields_schema = _build_fields_schema(fields_template, rules_props,
                                              file_id='fields_rule.json',
                                              name='schema/fields-rule/0')

    decoder_fields_schema = _build_fields_schema(fields_template, dec_props,
                                                 file_id='fields_decoder.json',
                                                 name='schema/fields-decoder/0')
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
    logpar_template["fields"] = field_tree.get_jlogpar()
    print('Success.')

    return decoder_fields_schema, rule_fields_schema, mappings_template, logpar_template, engine_schema
