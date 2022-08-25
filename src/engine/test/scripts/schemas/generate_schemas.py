import requests
import json
from yaml import load, dump
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

# Settings
CUSTOM_ECS_TEMPLATE = "custom-ecs-field.template.json"
CUSTOM_ECS_OUTPUT = "custom-ecs-field.json"
ECS_URL = 'https://raw.githubusercontent.com/elastic/ecs/main/generated/ecs/ecs_flat.yml'

LOGQL_TYPES_TEMPLATE = "wazuh-logql-types.template.json"
LOGQL_TYPES_OUTPUT = "wazuh-logql-types.json"

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
    print("Renaming @timestamp to timestamp...")
    stripped_schema['timestamp'] = stripped_schema.pop('@timestamp')
    print("Success.")

    # Generate json schema
    print("Generating json schema from template and stripped schema...")
    custom_ecs_field['properties'] = {**custom_ecs_field['properties'], **stripped_schema}
    print("Success.")

    # Process and add integrations
    print("Processing integrations...")
    for integration in INTEGRATIONS:
        print(f"Adding integration [{integration['name']}]...")
        print(f"Getting yaml file [{integration['url']}]...")
        r = requests.get(integration['url'])
        if not r.ok:
            make_error("Error: {}".format(r.status_code))
            return
        else:
            print("Success.")

        # Load yaml file from response
        print("Loading yaml file...")
        integration_schema = load(r.text, Loader=Loader)
        if not integration_schema:
            make_error("Error: failed to load yaml file.")
            return
        else:
            print("Success.")

        # Flattend fields from schema and add json types
        print("Flattening fields from schema...")
        flattend_schema = flatten(integration_schema, integration['root'])
        if not flattend_schema:
            make_error("Error: failed to flatten fields from schema.")
            return
        else:
            print("Success.")

        # Strip unnecessary fields from schema and add json types
        print("Stripping unnecessary fields from schema...")
        stripped_schema = {field: strip_fields(value) for field, value in flattend_schema.items()}
        if not stripped_schema:
            make_error("Error: failed to strip unnecessary fields from schema.")
            return
        else:
            print("Success.")

        # Add integration to custom_ecs_field
        print(f"Adding integration [{integration['name']}] to custom_ecs_field...")
        custom_ecs_field['properties'] = {**custom_ecs_field['properties'], **stripped_schema}
        print("Success.")

    # Write json schema to file
    print(F"Writing json schema to file [{CUSTOM_ECS_OUTPUT}]...")
    with open(CUSTOM_ECS_OUTPUT, "w") as f:
        json.dump(custom_ecs_field, f, indent=2)
    print("Success.")

    # Generate logql types
    print("Generating logql types...")
    # Load template
    print(f"Loading json schema template [{LOGQL_TYPES_TEMPLATE}]...")
    with open(LOGQL_TYPES_TEMPLATE, "r") as f:
        logql_types = json.load(f)

    if not logql_types:
        make_error("Failed to load logql_types template.")
        return
    else:
        print("Loaded.")

    # Add custom_ecs_field to logql_types
    print("Adding ECS field types to logql_types...")
    # Only add fields that have ecs_type set
    logql_types = {**logql_types, **{field: value['ecs_type'] for field, value in custom_ecs_field['properties'].items() if value.get('ecs_type')}}
    print("Success.")
    # Write logql_types to file
    print(F"Writing logql_types to file [{LOGQL_TYPES_OUTPUT}]...")
    with open(LOGQL_TYPES_OUTPUT, "w") as f:
        json.dump(logql_types, f, indent=2)
    print("Success.")

    ecs_types = list({field['ecs_type'] for field in custom_ecs_field['properties'].values() if field.get('ecs_type')})
    with open('ecs_types.json', "w") as f:
        json.dump(ecs_types, f, indent=2)


    print("All done.")
    return

def flatten(schema, root):
    prefix = f'{root}.{schema[0]["name"]}'
    return {f'{prefix}.{field["name"]}': field for field in schema[0]['fields']}

def strip_fields(field_value):
    description = 'Not available'
    ecs_type = 'keyword'
    if 'description' in field_value:
        description = field_value['description']
    if 'type' in field_value:
        ecs_type = field_value['type']

    return {'description': description,
            'ecs_type': ecs_type,
            'type': ["string", "number", "boolean"]}

def make_error(msg):
    print(msg)
    print("Aborted.")
    return

if __name__ == '__main__':
    main()
