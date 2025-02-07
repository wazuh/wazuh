import sys
import json
from pathlib import Path
import shared.resource_handler as rs
from health_test.error_managment import ErrorReporter
import ipaddress
from datetime import datetime


def is_valid_date(value):
    try:
        datetime.fromisoformat(value)
        return True
    except ValueError:
        return False


def is_valid_ip(value):
    """ Check if the value is a valid IP address. """
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def get_validation_function(field_type):
    if field_type == 'object':
        return lambda value: isinstance(value, dict) and bool(value)

    if field_type == 'nested':
        return lambda value: isinstance(value, list) and bool(value)

    if field_type == 'ip':
        return is_valid_ip

    if field_type == 'keyword' or field_type == 'text' or field_type == 'wildcard':
        return lambda value: isinstance(value, str)

    if field_type == 'long' or field_type == 'scaled_float':
        return lambda value: isinstance(value, int)

    if field_type == 'float':
        return lambda value: isinstance(value, float)

    if field_type == 'boolean':
        return lambda value: isinstance(value, bool)

    if field_type == 'date':
        return is_valid_date

    else:
        return lambda value: False


def load_custom_fields(custom_fields_path, reporter: ErrorReporter, allowed_custom_fields_type):
    """
    Load custom fields from 'custom_fields.yml' into a map of field -> (type, validation_function).
    """
    custom_fields_map = {}
    try:
        custom_fields_data = rs.ResourceHandler().load_file(custom_fields_path.as_posix())
        for item in custom_fields_data:
            if item['field']:
                if item['type'] not in allowed_custom_fields_type:
                    reporter.add_error(
                        "Custom Fields", custom_fields_path,
                        f"Invalid type '{item['type']}' for field '{item['field']}'. Allowed types: {allowed_custom_fields_type}"
                    )
                    continue

                validation_fn = get_validation_function(item['type'])
                custom_fields_map[item['field']] = (item['type'], validation_fn)

        return custom_fields_map
    except Exception as e:
        reporter.add_error("Load Custom Fields", str(custom_fields_path), f"Error loading custom fields: {e}")
        return {}


def transform_dict_to_list(d):
    def extract_keys(d, prefix=""):
        result = []
        if isinstance(d, dict):
            for key, value in d.items():
                new_prefix = f"{prefix}.{key}" if prefix else key
                if isinstance(value, dict):
                    result.extend(extract_keys(value, new_prefix))
                elif isinstance(value, list):
                    for i, item in enumerate(value):
                        if isinstance(item, dict):
                            result.extend(extract_keys(item, f"{new_prefix}[{i}]"))
                        else:
                            result.append(f"{new_prefix}")
                else:
                    result.append(new_prefix)
        return result

    return extract_keys(d)


def get_value_from_hierarchy(data, field):
    keys = field.split('.')
    value = data

    for key in keys:
        if isinstance(value, dict) and key in value:
            value = value[key]
        else:
            return None

    return value


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

    invalid_fields = []

    if reporter.has_errors():
        return

    for json_file in expected_json_files:
        try:
            with open(json_file, 'r') as f:
                expected_data = json.load(f)

                for expected in expected_data:
                    extracted_fields = transform_dict_to_list(expected)
                    invalid_fields = [
                        field for field in extracted_fields
                        if field not in schema_fields
                    ]

                    filtered_invalid_fields = set(invalid_fields)

                    for field, (type, validate_function) in custom_fields_map.items():
                        expected_value = get_value_from_hierarchy(expected, field)
                        if expected_value == None:
                            continue
                        if validate_function(expected_value):
                            if type == 'object':
                                for invalid_field in invalid_fields:
                                    if invalid_field.startswith(field + '.'):
                                        filtered_invalid_fields.discard(invalid_field)
                            elif type == 'nested':
                                for invalid_field in invalid_fields:
                                    filtered_invalid_fields.discard(invalid_field)
                            else:
                                filtered_invalid_fields.discard(field)

                    if filtered_invalid_fields:
                        reporter.add_error(
                            integration_name,
                            json_file,
                            f"{filtered_invalid_fields}")

        except Exception as e:
            reporter.add_error(integration_name, str(json_file), f"Error reading the file: {e}")


def find_expected_json_files(test_folder):
    return list(test_folder.rglob('*_expected.json'))


def verify(schema, integration: Path, reporter):
    try:
        with open(schema, 'r') as schema_file:
            schema_data = json.load(schema_file)
    except Exception as e:
        sys.exit(f"Error reading the JSON schema file: {e}")

    allowed_custom_fields_type = {field_info["type"] for field_info in schema_data["fields"].values()}

    if integration.name != 'wazuh-core':
        custom_fields_path = integration / 'test' / 'custom_fields.yml'
        if not custom_fields_path.exists():
            reporter.add_error(integration.name, str(custom_fields_path),
                               "Error: custom_fields.yml file does not exist.")
            return

        custom_fields = load_custom_fields(custom_fields_path, reporter, allowed_custom_fields_type)
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
