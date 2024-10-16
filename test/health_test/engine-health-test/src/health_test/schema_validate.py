import sys
import json
from pathlib import Path
import shared.resource_handler as rs
from health_test.error_managment import ErrorReporter


def load_custom_fields(custom_fields_path, reporter):
    """
    Load custom fields from 'custom_fields.yml' into a map of field -> type.
    """
    custom_fields_map = {}
    try:
        custom_fields_data = rs.ResourceHandler().load_file(custom_fields_path.as_posix())
        for item in custom_fields_data:
            custom_fields_map[item['field']] = item['type']
        return custom_fields_map
    except Exception as e:
        reporter.add_error("Load Custom Fields", str(custom_fields_path), f"Error loading custom fields: {e}")
        return {}


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


def should_ignore_field(field, custom_fields_map):
    """
    Determine if a field should be ignored based on its type in custom_fields_map.
    """
    parts = field.split('.')
    for i in range(len(parts)):
        current_field = '.'.join(parts[:i + 1])
        if current_field in custom_fields_map:
            field_type = custom_fields_map[current_field]
            if field_type == 'object':
                return True
            elif field_type == 'array':
                return True
            else:
                return True
    return False


def verify_schema_types(schema, expected_json_files, custom_fields_map, integration_name, reporter):
    """
    Compare the fields in the '_expected.json' files with the schema and custom fields.
    """
    try:
        with open(schema, 'r') as schema_file:
            schema_data = json.load(schema_file)
            schema_fields = set(schema_data.get("fields", {}).keys())
    except Exception as e:
        reporter.add_error(integration_name, str(schema), f"Error reading the JSON schema file: {e}")
        return

    for json_file in expected_json_files:
        try:
            with open(json_file, 'r') as f:
                expected_data = json.load(f)
                for expected in expected_data:
                    extracted_fields = transform_dict_to_list(expected)

                    invalid_fields = [
                        field for field in extracted_fields
                        if field not in schema_fields and not should_ignore_field(field, custom_fields_map)
                    ]

                    if invalid_fields:
                        reporter.add_error(
                            integration_name,
                            json_file,
                            f"{invalid_fields}"
                        )
        except Exception as e:
            reporter.add_error(integration_name, str(json_file), f"Error reading the file: {e}")


def find_expected_json_files(test_folder):
    return list(test_folder.rglob('*_expected.json'))


def verify(schema, integration: Path, reporter):
    if integration.name != 'wazuh-core':
        custom_fields_path = integration / 'test' / 'custom_fields.yml'
        if not custom_fields_path.exists():
            reporter.add_error(integration.name, str(custom_fields_path),
                               "Error: custom_fields.yml file does not exist.")
            return

        custom_fields = load_custom_fields(custom_fields_path, reporter)
        test_folder = integration / 'test'
        if not test_folder.exists() or not test_folder.is_dir():
            reporter.add_error(integration.name, str(test_folder), "Error: No 'test' folder found.")
            return

        expected_json_files = find_expected_json_files(test_folder)
        if not expected_json_files:
            reporter.add_error(integration.name, str(test_folder), "Error: No '_expected.json' files found.")
            return

        verify_schema_types(schema, expected_json_files, custom_fields, integration.name, reporter)


def integration_validator(schema, ruleset_path: Path, integration: str, reporter):
    integration_path = ruleset_path / 'integrations'
    if not integration_path.exists() or not integration_path.is_dir():
        reporter.add_error("Integration Validator", str(integration_path),
                           "Error: 'integrations' directory does not exist.")
        return

    if integration:
        folder = integration_path / integration
        if not folder.exists():
            sys.exit(f"Integration {integration} does not exist.")
        verify(schema, integration_path / integration, reporter)
    else:
        for integration in integration_path.iterdir():
            if integration.is_dir():
                verify(schema, integration, reporter)


def rules_validator(schema, ruleset_path: Path, rule_folder: str, reporter):
    rules_path = ruleset_path / 'rules'
    if not rules_path.exists() or not rules_path.is_dir():
        reporter.add_error("Rules Validator", str(rules_path), "Error: 'rules' directory does not exist.")
        return

    if rule_folder:
        rule = rules_path / rule_folder
        if not rule.exists():
            sys.exit(f"Rule folder {rule} does not exist.")
        verify(schema, rules_path / rule_folder, reporter)
    else:
        for rule_folder in rules_path.iterdir():
            if rule_folder.is_dir():
                verify(schema, rule_folder, reporter)


def run(args):
    ruleset_path = Path(args['ruleset']).resolve()
    integration = args.get('integration')
    rule_folder = args.get('rule_folder')

    if not ruleset_path.is_dir():
        sys.exit(f"Engine ruleset not found: {ruleset_path}")

    schema = ruleset_path / "schemas/engine-schema.json"
    reporter = ErrorReporter("Validation")

    if rule_folder and integration:
        sys.exit("Error: Only one of 'integration' or 'rule_folder' can be specified at a time.")

    try:
        print("Running schema tests.")

        if integration:
            print("Validating integration only.")
            integration_validator(schema, ruleset_path, integration, reporter)

        elif rule_folder:
            print("Validating rules only.")
            rules_validator(schema, ruleset_path, rule_folder, reporter)

        else:
            print("Validating both integration and rules.")
            integration_validator(schema, ruleset_path, integration, reporter)
            rules_validator(schema, ruleset_path, rule_folder, reporter)

        reporter.exit_with_errors(
            "There are fields present in the expected event that are not in the schema and were not defined as custom",
            ruleset_path)

        print("Success execution")
    except Exception as e:
        sys.exit(f"Error running test: {e}")
