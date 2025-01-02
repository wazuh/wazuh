#!/usr/bin/env python3

import sys
from pathlib import Path
import re
import shared.resource_handler as rs
from health_test.error_managment import ErrorReporter


def load_non_modifiable_fields(non_modifiables_fields_path: Path):
    try:
        non_modifiables_fields = rs.ResourceHandler().load_file(non_modifiables_fields_path.as_posix())
        return non_modifiables_fields
    except Exception as e:
        sys.exit(f"Error loading non modifiable fields from '{non_modifiables_fields_path}': {e}")


def validate_non_modifiable_fields(content, entry, non_modifiables_fields, error_reporter):
    """
    Validate that non-modifiable fields are not present within parse or normalize sections.
    """
    section_patterns = [r'^parse\|.*$', r'^normalize$']
    for section_pattern in section_patterns:
        for key, value in content.items():
            if re.match(section_pattern, key):
                validate_section(key, value, non_modifiables_fields, entry, error_reporter)


def validate_section(key, value, non_modifiables_fields, entry, error_reporter):
    """
    Validate a specific section of the content.
    """
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                validate_item_in_section(key, item, non_modifiables_fields, entry, error_reporter)
            else:
                validate_flat_item(key, item, non_modifiables_fields, entry, error_reporter)


def validate_item_in_section(key, item, non_modifiables_fields, entry, error_reporter):
    """
    Validate items within a section that are dictionaries.
    """
    for field_key, field_values in item.items():
        if key == 'normalize' and field_key != 'check':
            validate_normalize_fields(key, field_values, non_modifiables_fields, entry, error_reporter)
        elif field_key in non_modifiables_fields:
            error_reporter.add_error(
                'non modifiable fields', entry,
                f"Non-modifiable field '{field_key}' found in section '{key}'."
            )


def validate_normalize_fields(key, field_values, non_modifiables_fields, entry, error_reporter):
    """
    Validate fields specifically in the 'normalize' section.
    """
    for field_value in field_values:
        if isinstance(field_value, dict):
            for field in field_value.keys():
                if field in non_modifiables_fields:
                    error_reporter.add_error(
                        'non modifiable fields', entry,
                        f"Non-modifiable field '{field}' found in section '{key}'."
                    )


def validate_flat_item(key, item, non_modifiables_fields, entry, error_reporter):
    """
    Validate items in a section that are not dictionaries.
    """
    non_modifiable_found = [field for field in non_modifiables_fields if field in item]
    for field in non_modifiable_found:
        error_reporter.add_error(
            'non modifiable fields', entry,
            f"Non-modifiable field '{field}' found in section 'parse'."
        )


def process_entry(entry, resource_handler: rs.ResourceHandler, non_modifiables_fields, error_reporter):
    """
    Process a single integration entry, creating tasks for kvdbs and catalog validation.
    """
    original = resource_handler.load_file(entry)
    validate_non_modifiable_fields(original, entry, non_modifiables_fields, error_reporter)


def integration_validator(
        args, ruleset_path: Path, resource_handler: rs.ResourceHandler, non_modifiables_fields, error_reporter):
    integration = args.get('integration')

    if integration:
        integration_path = ruleset_path / 'integrations' / integration
        if not integration_path.exists() or not integration_path.is_dir():
            sys.exit(f"Integration '{integration}' not found in '{ruleset_path / 'integrations'}'.")
        integrations_to_process = [integration_path]
    else:
        integrations_path = ruleset_path / 'integrations'
        if not integrations_path.exists() or not integrations_path.is_dir():
            sys.exit(f"Integrations directory not found in '{ruleset_path}'.")
        integrations_to_process = [d for d in integrations_path.iterdir() if d.is_dir()]

    for integration_path in integrations_to_process:
        manifest = dict()
        try:
            manifest_path = integration_path / 'manifest.yml'
            manifest = resource_handler.load_file(manifest_path.as_posix())
        except Exception as e:
            sys.exit(f'Error: {e}')

        for type_name in manifest.keys():
            if type_name not in ['decoders', 'outputs', 'filters']:
                continue

            path = ruleset_path / type_name
            if not path.exists():
                sys.exit(f'Error: {type_name} directory does not exist')

            for entry in path.rglob('*.yml'):
                original = resource_handler.load_file(entry)
                if original['name'] in manifest['decoders']:
                    if original['name'] != "decoder/core-wazuh-message/0":
                        process_entry(entry, resource_handler, non_modifiables_fields, error_reporter)

    return error_reporter.has_errors()  # Return True if there are errors


def rules_validator(
        args, ruleset_path: Path, resource_handler: rs.ResourceHandler, non_modifiables_fields, error_reporter):
    rule_folder = args.get('rule_folder')

    if rule_folder:
        rule_folder_path = ruleset_path / 'rules' / rule_folder
        if not rule_folder_path.exists() or not rule_folder_path.is_dir():
            sys.exit(f"Rule folder '{rule_folder}' not found in '{ruleset_path / 'rules'}'.")
        rules_to_process = [rule_folder_path]
    else:
        rules_path = ruleset_path / 'rules'
        if not rules_path.exists() or not rules_path.is_dir():
            sys.exit(f"Rules directory not found in '{ruleset_path}'.")
        rules_to_process = [d for d in rules_path.iterdir() if d.is_dir()]

    for rule_folder in rules_to_process:
        for entry in rule_folder.glob('*.yml'):
            process_entry(entry, resource_handler, non_modifiables_fields, error_reporter)

    return error_reporter.has_errors()  # Return True if there are errors


def run(args):
    ruleset_path = Path(args['ruleset']).resolve()
    resource_handler = rs.ResourceHandler()

    if not ruleset_path.is_dir():
        sys.exit(f"Engine ruleset not found: {ruleset_path}")

    error_reporter = ErrorReporter("Validation")
    integration_arg = args.get('integration')
    rule_folder_arg = args.get('rule_folder')

    specified_args = [arg for arg in [integration_arg, rule_folder_arg] if arg]

    if len(specified_args) > 1:
        sys.exit("Error: Only one of 'integration' or 'rule_folder' can be specified at a time.")

    try:
        print("Running non modifiable fields tests.")
        non_modifiables_fields_path = ruleset_path / 'base-rules' / 'non_modifiable_fields.yml'
        if not non_modifiables_fields_path.exists():
            sys.exit(f'Error: {non_modifiables_fields_path} file does not exist.')
        non_modifiables_fields = load_non_modifiable_fields(non_modifiables_fields_path)

        if rule_folder_arg:
            print("Validating rules only.")
            rules_validator(args, ruleset_path, resource_handler, non_modifiables_fields, error_reporter)
        elif integration_arg:
            print("Validating integration only.")
            integration_validator(args, ruleset_path, resource_handler, non_modifiables_fields, error_reporter)
        else:
            print("No specific arguments provided, validating both integration and rules.")
            integration_validator(args, ruleset_path, resource_handler, non_modifiables_fields, error_reporter)
            rules_validator(args, ruleset_path, resource_handler, non_modifiables_fields, error_reporter)

        if error_reporter.has_errors():
            error_reporter.exit_with_errors(
                "There are mandatory fields in the non modifiable fields field that are not present", ruleset_path)
        else:
            print("Success execution")
    except Exception as e:
        print(f"Error running test: {e}")
