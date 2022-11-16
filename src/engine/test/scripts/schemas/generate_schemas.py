import requests
import json
import os
from yaml import load, dump
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

# Settings 8.5.0
CUSTOM_ECS_TEMPLATE = "custom-ecs-field.template.json"
CUSTOM_ECS_OUTPUT = "custom-ecs-field.json"
ECS_NESTED_URL = 'https://raw.githubusercontent.com/elastic/ecs/v8.5.0-rc1/generated/ecs/ecs_nested.yml'
ECS_FLAT_URL = 'https://raw.githubusercontent.com/elastic/ecs/v8.5.0-rc1/generated/ecs/ecs_flat.yml'

LOGPAR_TYPES_TEMPLATE = "wazuh-logpar-types.template.json"
LOGPAR_TYPES_OUTPUT = "wazuh-logpar-types.json"
LOGPAR_TYPES_STORE_OUTPUT = "schema/wazuh-logpar-types"

def make_error(msg):
    print(msg)
    print("Aborted.")
    exit(1)

def transformToSupportedType(ecsRype):
    if "match_only_text" == ecsRype:
        return "text"
    if "constant_keyword" == ecsRype:
        return "keyword"
    if "wildcard" == ecsRype:
        return "keyword"
    if "flattened" == ecsRype:
        return "object"
    if "number" == ecsRype:
        return "long"

    return ecsRype

def strip_fields(field_value):
    entry = {}
    entry['description'] = 'Not available'
    entry['ecs_type'] = 'keyword'
    if 'description' in field_value:
        entry['description'] = field_value['description']
    if 'type' in field_value:
        entry['ecs_type'] = transformToSupportedType(field_value['type'])

    entry['description'] += "\n\nECS type: {}".format(entry['ecs_type'])

    if len(field_value['normalize']) > 0:
        entry['type'] = field_value['normalize']
    else:
        json_type = ecs_type_to_json_type(entry['ecs_type'])
        entry['type'] = [json_type]
    if 'string' not in entry['type']:
        entry['type'].append('string')
        entry['pattern'] = '^[\\+\\$].+'

    return entry

def ecs_type_to_json_type(ecs_type):
    if ecs_type == 'date':
        return 'string'
    elif ecs_type == 'ip':
        return 'string'
    elif ecs_type == 'object':
        return 'object'
    elif ecs_type == 'text':
        return 'string'
    elif ecs_type == 'long':
        return 'integer'
    elif ecs_type == 'boolean':
        return 'boolean'
    elif ecs_type == 'geo_point':
        return 'string'
    elif ecs_type == 'scaled_float':
        return 'number'
    elif ecs_type == 'keyword':
        return 'string'
    elif ecs_type == 'nested':
        return 'object'
    elif ecs_type == "float":
        return "number"
    else:
        return 'string'

def main():
    print("Generating schemas...")

    # Load custom_ecs_field template
    print(f"Loading json schema template [{CUSTOM_ECS_TEMPLATE}]...")
    with open(CUSTOM_ECS_TEMPLATE, "r") as f:
        custom_ecs_field = json.load(f)

    if not custom_ecs_field:
        make_error("Failed to load custom_ecs_field template.")
    else:
        print("Loaded.")

    # Get ECS schemas
    print(F"Getting yaml ECS [{ECS_FLAT_URL}]...")
    rFlat = requests.get(ECS_FLAT_URL)
    if not rFlat.ok:
        make_error("Error: {}".format(rFlat.status_code))
    else:
        print("Success.")

    print(F"Getting yaml ECS [{ECS_NESTED_URL}]...")
    rNested = requests.get(ECS_NESTED_URL)
    if not rNested.ok:
        make_error("Error: {}".format(rNested.status_code))
    else:
        print("Success.")

    # Load yaml file from response
    print("Loading yaml files...")
    ecs_nested_schema = load(rNested.text, Loader=Loader)
    if not ecs_nested_schema:
        make_error("Error: failed to load yaml file.")
    else:
        print("Success.")

    # Load yaml file from response
    print("Loading yaml files...")
    ecs_flat_schema = load(rFlat.text, Loader=Loader)
    if not ecs_flat_schema:
        make_error("Error: failed to load yaml file.")
    else:
        print("Success.")

    # Load all leaf fields and add them to definitions
    print("Generating Wazuh custom ECS fields...")
    wazuh_ecs_schema = {field: strip_fields(value) for field, value in ecs_flat_schema.items()}
    custom_ecs_field['definitions'] = wazuh_ecs_schema

    # Add all groups and leaf fields to properties, leaf fields are added as references to definitions
    nested_map = {}
    for key in wazuh_ecs_schema.keys():
        splitted = key.split('.')
        if len(splitted) > 1:
            base = splitted[0]
            # Add base if not exists
            if base not in nested_map:
                nested_map[base] = dict()

                # Base ecs field
                if base in ecs_nested_schema:
                    nested_map[base]['description'] = ecs_nested_schema[base]['description']
                else:
                    # Weird case only for tracing as of now
                    print(F"Base field {base} not found in ecs_nested_schema")
                    nested_map[base]['description'] = 'Not available'

                nested_map[base]['type'] = ['object', 'string']
                nested_map[base]['pattern'] = '^[\\+\\$].+'
                nested_map[base]['properties'] = dict()

            # Add group childs
            current = nested_map[base]['properties']
            for i in range(1, len(splitted)):
                if splitted[i] not in current:
                    current[splitted[i]] = dict()
                    # Search if current field is in ecs_flat_schema
                    search_key = '.'.join(splitted[:i+1])
                    if search_key in ecs_flat_schema:
                        # If type is object or nested this is a group
                        if ecs_flat_schema[search_key]['type'] == 'object' or ecs_flat_schema[search_key]['type'] == 'nested':
                            # if normalize contains a value as of now is an array
                            if 'normalize' in ecs_flat_schema[search_key] and len(ecs_flat_schema[search_key]['normalize']) == 1:
                                current[splitted[i]]['type'] = ecs_flat_schema[search_key]['normalize']
                            # If not is an object
                            else:
                                current[splitted[i]]['type'] = ['object']
                        # If not is a field, set up the reference and add the propertie if not added
                        else:
                            current[splitted[i]]['$ref'] = '#/definitions/' + search_key
                            if search_key not in custom_ecs_field['properties']:
                                custom_ecs_field['properties'][search_key] = {}
                                custom_ecs_field['properties'][search_key]['$ref'] = '#/definitions/' + search_key
                    # If not, it is an object group not defined in ecs
                    else:
                        current[splitted[i]]['type'] = ['object']

                    #If we added a group, add properties/items and add string helper type
                    if 'type' in current[splitted[i]]:
                        current[splitted[i]]['type'].append('string')
                        current[splitted[i]]['pattern'] = '^[\\+\\$].+'
                        if'object' in current[splitted[i]]['type']:
                            current[splitted[i]]['properties'] = dict()
                            current[splitted[i]]['additionalProperties'] = False
                        # If array, add items
                        elif 'array' in current[splitted[i]]['type']:
                            current[splitted[i]]['items'] = {'type': 'object', 'properties': dict()}
                            current[splitted[i]]['items']['additionalProperties'] = False
                        else:
                            make_error(F"Error: {search_key} is not an object or array")

                # Update current to next level
                if i < len(splitted) - 1:
                    if 'object' in current[splitted[i]]['type']:
                        current = current[splitted[i]]['properties']
                    elif 'array' in current[splitted[i]]['type']:
                        current = current[splitted[i]]['items']['properties']
                    else:
                        make_error(F"Error: {search_key} is not an object or array")
        # root leaf fields
        else:
            custom_ecs_field['properties'][key] = {'$ref': '#/definitions/' + key}

    # Add all groups to properties
    custom_ecs_field['properties'] = {**custom_ecs_field['properties'], **nested_map}

    # Write json schema to file
    print(F"Writing json schema to file [{CUSTOM_ECS_OUTPUT}]...")
    with open(CUSTOM_ECS_OUTPUT, "w") as f:
        json.dump(custom_ecs_field, f, indent=2)
    print("Success.")

    # Generate logpar types
    print("Generating logpar types...")
    # Load template
    print(f"Loading json schema template [{LOGPAR_TYPES_TEMPLATE}]...")
    with open(LOGPAR_TYPES_TEMPLATE, "r") as f:
        logpar_types = json.load(f)

    if not logpar_types:
        make_error("Failed to load logpar_types template.")
    else:
        print("Loaded.")

    # Add custom_ecs_field to logpar_types
    print("Adding ECS field types to logpar_types...")
    # Only add fields that have ecs_type set
    logpar_types = {**logpar_types, **{field: value['ecs_type'] for field, value in custom_ecs_field['definitions'].items() if value.get('ecs_type')}}
    print("Success.")
    # Write logpar_types to file
    print(F"Writing logpar_types to file [{LOGPAR_TYPES_OUTPUT}]...")
    with open(LOGPAR_TYPES_OUTPUT, "w") as f:
        json.dump(logpar_types, f, indent=2)

    os.makedirs(LOGPAR_TYPES_STORE_OUTPUT)
    with open(LOGPAR_TYPES_STORE_OUTPUT+"/0", "w") as f:
        json.dump(logpar_types, f)
    print("Success.")

    ecs_types = list({field['ecs_type'] for field in custom_ecs_field['definitions'].values() if field.get('ecs_type')})
    with open('ecs_types.json', "w") as f:
        json.dump(ecs_types, f, indent=2)


    print("All done.")
    return

if __name__ == '__main__':
    main()
