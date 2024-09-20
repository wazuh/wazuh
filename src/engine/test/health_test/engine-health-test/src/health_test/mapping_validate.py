import sys
import json
import shared.resource_handler as rs
from pathlib import Path

def load_mandatory_mapping(mandatory_mapping_path: Path):
    """
    Load mandatory_mapping from 'mandatory_mapping.yml'.
    """
    try:
        mandatory_mapping = rs.ResourceHandler().load_file(mandatory_mapping_path.as_posix())
        return mandatory_mapping.get('mandatory_mapping', [])
    except Exception as e:
        sys.exit(f"Error loading mandatory mapping from '{mandatory_mapping_path}'")

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

def verify_mandatory_mapping(expected_json_files, mandatory_mapping):
    """
    Compare the fields in the '_expected.json' files with the mandatory fields.
    """
    mandatory_mapping_set = set(mandatory_mapping)
    
    for json_file in expected_json_files:
        try:
            with open(json_file, 'r') as f:
                expected_data = json.load(f)
                for expected in expected_data:
                    extracted_fields = transform_dict_to_list(expected)
                    for mandatory in mandatory_mapping_set:
                        if mandatory not in extracted_fields:
                            sys.exit(f"Error: {mandatory} field is not present in {json_file} expected")
        except Exception as e:
            sys.exit(f"Error reading the file '{json_file}': {e}")

def find_expected_json_files(test_folder):
    return list(test_folder.rglob('*_expected.json'))

def verify(mandatory_mapping_path, integration: Path):
    mandatory_mapping = load_mandatory_mapping(mandatory_mapping_path)    
    if integration.name != 'wazuh-core':
        test_folder = integration / 'test'
        if not test_folder.exists() or not test_folder.is_dir():
            sys.exit(f"No 'test' folder found in '{integration}'.")

        expected_json_files = find_expected_json_files(test_folder)
        if not expected_json_files:
            sys.exit(f"No '_expected.json' files found in '{test_folder}' or its subfolders.")

        verify_mandatory_mapping(expected_json_files, mandatory_mapping)

def validator(ruleset_path: Path, integration: str):
    integration_path = ruleset_path / 'integrations'
    if not integration_path.exists() or not integration_path.is_dir():
        sys.exit(f"Error: '{integration_path}' directory does not exist or not found.")

    mandatory_mapping_path = ruleset_path / 'mandatory_mapping.yml'
    if not mandatory_mapping_path.exists():
        sys.exit(f'Error: {mandatory_mapping_path} file does not exist in the integration.')

    if integration:
        verify(mandatory_mapping_path, integration_path / integration)
    else:
        for integration in integration_path.iterdir():
            if integration.is_dir():
                verify(mandatory_mapping_path, integration)

def run(args):
    integration = args['integration']
    env_path = Path(args['environment']).resolve()
    ruleset_path = (env_path / "ruleset").resolve()
    if not ruleset_path.is_dir():
        print(f"Engine ruleset not found: {ruleset_path}")
        sys.exit(1)

    try:
        print("Running mapping tests.")
        validator(ruleset_path, integration)
        print("Success execution")
    except Exception as e:
        print(f"Error running test: {e}")
