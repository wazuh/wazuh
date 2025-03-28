import sys
import json
import re
from pathlib import Path
import shared.resource_handler as rs
from health_test.error_managment import ErrorReporter

def evaluate_description(description):
    feedback = []

    if description == None or description == "":
        return ["Invalid input: The description must be a string."]

    if len(description.split()) < 5:
        feedback.append("The description is too short to be meaningful.")

    if not description[0].isupper():
        feedback.append("The description does not start with an uppercase letter.")

    if not description.strip().endswith(('.', '?', '!')):
        feedback.append("The description does not end with proper punctuation.")

    if re.search(r"(.)\1{3,}", description):
        feedback.append("The description contains repetitive text.")

    if re.match(r"^(bla|lorem|xyz)+", description.lower()):
        feedback.append("The description appears to contain placeholder text ('blablabla', etc.).")

    if re.search(r'\b(\w+)\b(?:\s+\b\1\b)+', description, re.IGNORECASE):
        feedback.append("The description contains consecutive repeated words.")

    return feedback

def load_custom_fields(integration, custom_fields_path, allowed_types, reporter):
    """
    Load custom fields from 'custom_fields.yml' into a map of field -> (type, validation_function).
    """
    try:
        custom_fields_data = rs.ResourceHandler().load_file(custom_fields_path.as_posix())
        for item in custom_fields_data:
            if item['field']:
                if item['type'] not in allowed_types:
                    message = f"\nIntegration: {integration.name}\n"
                    message += f"Invalid type '{item['type']}' for field '{item['field']}'. Allowed types: {allowed_types}\n"
                    reporter.add_error("Decoders Validator", str(integration), "Error: 'integrations' directory does not exist.")
                    continue

        return custom_fields_data
    except Exception as e:
        sys.exit(f"Error loading custom fields from {custom_fields_path}: {e}")

def verify_custom_field_documentation(custom_field_file, integration, reporter):
    for custom_file in custom_field_file:
        if custom_file["field"] != "":
            failures = evaluate_description(custom_file["description"])
            if failures:
                reporter.add_error(integration.name, str(integration), f"The custom field {custom_file['field']} have errors: {failures}")


def verify(integration: Path, allowed_types, reporter):
    if integration.name != 'wazuh-core':
        test_folder = integration / 'test'
        if not test_folder.exists() or not test_folder.is_dir():
            sys.exit(f"No 'test' folder found in '{integration}'.")

        custom_field_path = test_folder / 'custom_fields.yml'
        custom_field = load_custom_fields(integration, custom_field_path, allowed_types, reporter)

        verify_custom_field_documentation(custom_field, integration, reporter)

def integration_validator(ruleset_path: Path, integration: str, reporter):
    """
    Validate the custom field documentation for all integrations or a specific one.
    Accumulate and report errors at the end of the validation.
    """
    integration_path = ruleset_path / 'integrations'
    schema = ruleset_path / "schemas/engine-schema.json"
    try:
        with open(schema, 'r') as schema_file:
            schema_data = json.load(schema_file)
    except Exception as e:
        sys.exit(f"Error reading the JSON schema file: {e}")

    allowed_types = {field_info["type"] for field_info in schema_data["fields"].values()}
    if not integration_path.exists() or not integration_path.is_dir():
        sys.exit(f"Error: '{integration_path}' directory does not exist or not found.")

    if integration:
        folder = integration_path / integration
        if not folder.exists():
            sys.exit(f"Integration {integration} does not exist.")
        verify(integration_path / integration, allowed_types, reporter)
    else:
        for integration in integration_path.iterdir():
            if integration.is_dir():
                verify(integration, allowed_types, reporter)

def integration_rules_validator(ruleset_path: Path, integration_rules: str, reporter):
    integration_rules_path = ruleset_path / 'integrations-rules'
    if not integration_rules_path.exists() or not integration_rules_path.is_dir():
        reporter.add_error("Rules Validator", str(integration_rules_path), "Error: 'rules' directory does not exist.")
        return

    schema = ruleset_path / "schemas/engine-schema.json"
    try:
        with open(schema, 'r') as schema_file:
            schema_data = json.load(schema_file)
    except Exception as e:
        sys.exit(f"Error reading the JSON schema file: {e}")

    allowed_types = {field_info["type"] for field_info in schema_data["fields"].values()}

    if integration_rules:
        rule = integration_rules_path / integration_rules
        if not rule.exists():
            sys.exit(f"Integration rule {rule} does not exist.")
        verify(integration_rules_path / integration_rules, allowed_types, reporter)
    else:
        for integration_rules in integration_rules_path.iterdir():
            if integration_rules.is_dir():
                verify(integration_rules, allowed_types, reporter)

def run(args):
    ruleset_path = Path(args['ruleset']).resolve()
    integration = args['integration']
    integration_rule = args['integration_rule']

    if not ruleset_path.is_dir():
        sys.exit(f"Engine ruleset not found: {ruleset_path}")

    reporter = ErrorReporter("Validation")

    if integration_rule and integration:
        sys.exit("Error: Only one of 'integration' or 'integration_rule' can be specified at a time.")

    try:
        print("Running custom field documentation tests.")

        if integration:
            print("Validating integration only.")
            integration_validator(ruleset_path, integration, reporter)

        elif integration_rule:
            print("Validating rules only.")
            integration_rules_validator(ruleset_path, integration_rule, reporter)

        else:
            print("Validating both integration and rules.")
            integration_validator(ruleset_path, integration, reporter)
            integration_rules_validator(ruleset_path, integration_rule, reporter)

        # After both validators have run, check if there are errors and exit if necessary
        reporter.exit_with_errors("There are fields that should be mapped and are not present in the expected event", ruleset_path)

        print("Success execution")
    except Exception as e:
        sys.exit(f"Error running test: {e}")
