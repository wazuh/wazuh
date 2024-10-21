import sys
import json
from pathlib import Path
import shared.resource_handler as rs
from health_test.error_managment import ErrorReporter

def load_mandatory_mapping(mandatory_mapping_path: Path):
    """
    Load mandatory_mapping from 'mandatory_mapping.yml'.
    """
    try:
        mandatory_mapping = rs.ResourceHandler().load_file(mandatory_mapping_path.as_posix())
        return mandatory_mapping
    except Exception as e:
        return f"Error loading mandatory mapping from '{mandatory_mapping_path}': {e}"

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

def verify_mandatory_mapping(expected_json_files, mandatory_mapping, integration_name, reporter, key):
    """
    Compare the fields in the '_expected.json' files with the mandatory fields
    under the specified key (either 'decoder' or 'rule').
    Report missing fields once per expected JSON file.
    """
    mandatory_mapping_set = set(mandatory_mapping.get(key, []))
    
    for json_file in expected_json_files:
        try:
            with open(json_file, 'r') as f:
                expected_data = json.load(f)
                missing_fields = set()
                for expected in expected_data:
                    extracted_fields = transform_dict_to_list(expected)
                    missing_fields.update(mandatory for mandatory in mandatory_mapping_set if mandatory not in extracted_fields)
                
                if missing_fields:
                    for field in missing_fields:
                        reporter.add_error(integration_name, json_file, f"{field}")
        except Exception as e:
            sys.exit(f"Error reading the file '{json_file}': {e}")

def find_expected_json_files(test_folder):
    return list(test_folder.rglob('*_expected.json'))

def verify(mandatory_mapping_path, integration: Path, reporter, key):
    mandatory_mapping = load_mandatory_mapping(mandatory_mapping_path)    
    if integration.name != 'wazuh-core':
        test_folder = integration / 'test'
        if not test_folder.exists() or not test_folder.is_dir():
            sys.exit(f"No 'test' folder found in '{integration}'.")

        expected_json_files = find_expected_json_files(test_folder)
        if not expected_json_files:
            sys.exit(f"No '_expected.json' files found in '{test_folder}' or its subfolders.")

        # Verify mandatory mapping for decoders
        verify_mandatory_mapping(expected_json_files, mandatory_mapping, integration.name, reporter, key)

def integration_validator(ruleset_path: Path, integration: str, reporter):
    """
    Validate the mandatory mapping for all integrations or a specific one.
    Accumulate and report errors at the end of the validation.
    """
    integration_path = ruleset_path / 'integrations'
    
    if not integration_path.exists() or not integration_path.is_dir():
        sys.exit(f"Error: '{integration_path}' directory does not exist or not found.")

    mandatory_mapping_path = ruleset_path / 'base-rules' / 'mandatory_mapping.yml'
    if not mandatory_mapping_path.exists():
        sys.exit(f'Error: {mandatory_mapping_path} file does not exist.')

    if integration:
        folder = integration_path / integration
        if not folder.exists():
            sys.exit(f"Integration {integration} does not exist.")
        verify(mandatory_mapping_path, integration_path / integration, reporter, 'decoder')
    else:
        for integration in integration_path.iterdir():
            if integration.is_dir():
                verify(mandatory_mapping_path, integration, reporter, 'decoder')

def rules_validator(ruleset_path: Path, rule_folder: str, reporter):
    rules_path = ruleset_path / 'rules'
    if not rules_path.exists() or not rules_path.is_dir():
        reporter.add_error("Rules Validator", str(rules_path), "Error: 'rules' directory does not exist.")
        return

    mandatory_mapping_path = ruleset_path / 'base-rules' / 'mandatory_mapping.yml'
    if not mandatory_mapping_path.exists():
        sys.exit(f'Error: {mandatory_mapping_path} file does not exist.')

    if rule_folder:
        rule = rules_path / rule_folder
        if not rule.exists():
            sys.exit(f"Rule folder {rule} does not exist.")
        verify(mandatory_mapping_path, rules_path / rule_folder, reporter, 'rule')
    else:
        for rule_folder in rules_path.iterdir():
            if rule_folder.is_dir():
                verify(mandatory_mapping_path, rule_folder, reporter, 'rule')

def run(args):
    ruleset_path = Path(args['ruleset']).resolve()
    integration = args['integration']
    rule_folder = args['rule_folder']

    if not ruleset_path.is_dir():
        sys.exit(f"Engine ruleset not found: {ruleset_path}")

    reporter = ErrorReporter("Validation")

    if rule_folder and integration:
        sys.exit("Error: Only one of 'integration' or 'rule_folder' can be specified at a time.")

    try:
        print("Running mandatory mapping tests.")

        if integration:
            print("Validating integration only.")
            integration_validator(ruleset_path, integration, reporter)

        elif rule_folder:
            print("Validating rules only.")
            rules_validator(ruleset_path, rule_folder, reporter)

        else:
            print("Validating both integration and rules.")
            integration_validator(ruleset_path, integration, reporter)
            rules_validator(ruleset_path, rule_folder, reporter)

        # After both validators have run, check if there are errors and exit if necessary
        reporter.exit_with_errors("There are fields that should be mapped and are not present in the expected event", ruleset_path)
        
        print("Success execution")
    except Exception as e:
        sys.exit(f"Error running test: {e}")
