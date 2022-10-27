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
ECS_URL = 'https://raw.githubusercontent.com/elastic/ecs/v8.5.0-rc1/generated/ecs/ecs_flat.yml'

LOGPAR_TYPES_TEMPLATE = "wazuh-logpar-types.template.json"
LOGPAR_TYPES_OUTPUT = "wazuh-logpar-types.json"
LOGPAR_TYPES_STORE_OUTPUT = "schema/wazuh-logpar-types"

# ECS integrations
INTEGRATIONS = [

]

def main():
    print("Generating schemas...")

    # Load custom_ecs_field template
    print(f"Loading json schema template [{CUSTOM_ECS_TEMPLATE}]...")
    with open(CUSTOM_ECS_TEMPLATE, "r") as f:
        custom_ecs_field = json.load(f)

    if not custom_ecs_field:
        make_error("Failed to load custom_ecs_field template.")
        return
    else:
        print("Loaded.")

    print(F"Getting yaml ECS [{ECS_URL}]...")
    r = requests.get(ECS_URL)
    if not r.ok:
        make_error("Error: {}".format(r.status_code))
        return
    else:
        print("Success.")

    # Load yaml file from response
    print("Loading yaml file...")
    ecs_schema = load(r.text, Loader=Loader)
    if not ecs_schema:
        make_error("Error: failed to load yaml file.")
        return
    else:
        print("Success.")
    # Strip unnecessary fields from schema and add json types
    print("Stripping unnecessary fields from schema...")
    stripped_schema = {field: strip_fields(value) for field, value in ecs_schema.items()}
    if not stripped_schema:
        make_error("Error: failed to strip unnecessary fields from schema.")
        return
    else:
        print("Success.")

    # Rename @timestamp to timestamp
    # print("Renaming @timestamp to timestamp...")
    # stripped_schema['timestamp'] = stripped_schema.pop('@timestamp')
    # print("Success.")

    # Generate json schema
    print("Generating json schema from template and stripped schema...")
    custom_ecs_field['properties'] = {**custom_ecs_field['properties'], **stripped_schema}
    print("Success.")

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
        return
    else:
        print("Loaded.")

    # Add custom_ecs_field to logpar_types
    print("Adding ECS field types to logpar_types...")
    # Only add fields that have ecs_type set
    logpar_types = {**logpar_types, **{field: value['ecs_type'] for field, value in custom_ecs_field['properties'].items() if value.get('ecs_type')}}
    print("Success.")
    # Write logpar_types to file
    print(F"Writing logpar_types to file [{LOGPAR_TYPES_OUTPUT}]...")
    with open(LOGPAR_TYPES_OUTPUT, "w") as f:
        json.dump(logpar_types, f, indent=2)

    os.makedirs(LOGPAR_TYPES_STORE_OUTPUT)
    with open(LOGPAR_TYPES_STORE_OUTPUT+"/0", "w") as f:
        json.dump(logpar_types, f)
    print("Success.")

    ecs_types = list({field['ecs_type'] for field in custom_ecs_field['properties'].values() if field.get('ecs_type')})
    with open('ecs_types.json', "w") as f:
        json.dump(ecs_types, f, indent=2)


    print("All done.")
    return

def flatten(schema, root):
    prefix = f'{root}.{schema[0]["name"]}'
    return {f'{prefix}.{field["name"]}': field for field in schema[0]['fields']}

def strip_unsupported_types(ecsRype):
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
    description = 'Not available'
    ecs_type = 'keyword'
    if 'description' in field_value:
        description = field_value['description']
    if 'type' in field_value:
        ecs_type = strip_unsupported_types(field_value['type'])

    description += "\n\nECS type: {}".format(ecs_type)

    return {'description': description,
            'ecs_type': ecs_type}

def make_error(msg):
    print(msg)
    print("Aborted.")
    return

if __name__ == '__main__':
    main()
