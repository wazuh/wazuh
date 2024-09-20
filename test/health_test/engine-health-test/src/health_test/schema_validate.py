import sys
import json
import shared.resource_handler as rs
from pathlib import Path

def load_custom_fields(custom_fields_path):
    """
    Load custom fields from 'custom_fields.yml'.
    """
    try:
        custom_fields = rs.ResourceHandler().load_file(custom_fields_path.as_posix())
        return custom_fields.get('custom_fields', [])
    except Exception as e:
        sys.exit(f"Error loading custom fields from '{custom_fields_path}'")

def transform_dict_to_list(d):
    def extract_keys(d, prefix=""):
        result = []
        for key, value in d.items():
            new_prefix = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict):
                result.extend(extract_keys(value, new_prefix))
            else:
                result.append(new_prefix)
        return result
    
    return extract_keys(d)

def verify_schema_types(schema, expected_json_files, custom_fields):
    """
    Compare the fields in the '_expected.json' files with the schema and custom fields.
    """
    try:
        with open(schema, 'r') as schema_file:
            schema_data = json.load(schema_file)
            schema_fields = set(schema_data.get("fields", {}).keys())
    except Exception as e:
        sys.exit(f"Error reading the JSON schema file '{schema}': {e}")

    custom_fields_set = set(custom_fields)
    
    for json_file in expected_json_files:
        try:
            with open(json_file, 'r') as f:
                expected_data = json.load(f)
                for expected in expected_data:

                    extracted_fields = transform_dict_to_list(expected)
                    def is_custom_field(field, custom_fields_set):
                        if '.' in field:
                            prefix = field.split('.')[0]
                            return prefix in custom_fields_set
                        else:
                            return field in custom_fields_set

                    # Check for invalid fields
                    invalid_fields = [
                        field for field in extracted_fields
                        if field not in schema_fields and not is_custom_field(field, custom_fields_set)
                    ]
                    
                    if invalid_fields:
                        sys.exit(f"Error: Invalid fields found in '{json_file}': {invalid_fields}")
        except Exception as e:
            sys.exit(f"Error reading the file '{json_file}': {e}")

def find_expected_json_files(test_folder):
    return list(test_folder.rglob('*_expected.json'))

def verify(schema, integration: Path):
    if integration.name != 'wazuh-core':
        custom_fields_path = integration / 'test' / 'custom_fields.yml'
        if not custom_fields_path.exists():
            print(f'Error: {custom_fields_path} file does not exist in the integration.')
            sys.exit(1)

        custom_fields = load_custom_fields(custom_fields_path)    
        test_folder = integration / 'test'
        if not test_folder.exists() or not test_folder.is_dir():
            sys.exit(f"No 'test' folder found in '{integration}'.")

        expected_json_files = find_expected_json_files(test_folder)
        if not expected_json_files:
            sys.exit(f"No '_expected.json' files found in '{test_folder}' or its subfolders.")

        verify_schema_types(schema, expected_json_files, custom_fields)

def validator(schema, ruleset_path: Path, integration: str):
    integration_path = ruleset_path / 'integrations'
    if not integration_path.exists() or not integration_path.is_dir():
        sys.exit(f"Error: '{integration_path}' directory does not exist or not found.")

    if integration:
        verify(schema, integration_path / integration)
    else:
        for integration in integration_path.iterdir():
            if integration.is_dir():
                verify(schema, integration)

def run(args):
    env_path = Path(args['environment']).resolve()
    integration = args['integration']
    schema = env_path / "engine/store/schema/engine-schema/0"

    ruleset_path = (env_path / "ruleset").resolve()
    if not ruleset_path.is_dir():
        print(f"Engine ruleset not found: {ruleset_path}")
        sys.exit(1)

    try:
        print("Running schema tests.")
        validator(schema, ruleset_path, integration)
        print("Success execution")
    except Exception as e:
        print(f"Error running test: {e}")
