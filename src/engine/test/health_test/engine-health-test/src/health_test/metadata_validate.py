import sys
import shared.resource_handler as rs
from pathlib import Path
from health_test.error_managment import ErrorReporter

def validate_metadata(content, entry, error_reporter):
    """
    Validate the metadata of an integration entry and report errors.
    """
    required_metadata_fields = ['module', 'title', 'description', 'compatibility', 'versions', 'references', 'author']
    required_author_fields = ['name', 'date']
    
    metadata = content.get('metadata', {})
    missing_fields = [field for field in required_metadata_fields if field not in metadata]
    
    if missing_fields:
        error_reporter.add_error('metadata', entry, f"Missing required metadata fields: {', '.join(missing_fields)}")

    for field in ['module', 'title', 'description', 'compatibility']:
        if not isinstance(metadata.get(field), str):
            error_reporter.add_error('metadata', entry, f"'{field}' must be of type string")
    
    author_metadata = metadata.get('author', {})
    missing_author_fields = [field for field in required_author_fields if field not in author_metadata]
    
    if missing_author_fields:
        error_reporter.add_error('metadata', entry, f"Missing required author fields: {', '.join(missing_author_fields)}")

    for field in ['name', 'date']:
        if not isinstance(author_metadata.get(field), str):
            error_reporter.add_error('metadata', entry, f"'{field}' in author metadata must be of type string")

    if not isinstance(metadata.get('versions', None), list):
        error_reporter.add_error('metadata', entry, "'versions' must be of type list")

    if not isinstance(metadata.get('references', None), list):
        error_reporter.add_error('metadata', entry, "'references' must be of type list")


def process_entry(entry, resource_handler: rs.ResourceHandler, error_reporter):
    """
    Process a single integration entry, creating tasks for kvdbs and catalog validation.
    """
    original = resource_handler.load_file(entry)
    validate_metadata(original, entry, error_reporter)

def asset_validator(args, ruleset_path: Path, resource_handler: rs.ResourceHandler, asset_type, error_reporter):
    found_asset = False
    asset_path = ''
    if asset_type =='decoder':
        asset_path = ruleset_path / 'decoders'
    else:
        asset_path = ruleset_path / 'rules'

    asset = args[asset_type]
    if not asset_path.exists() or not asset_path.is_dir():
        sys.exit(f"Decoders directory not found in '{ruleset_path}'.")

    yml_files = list(asset_path.rglob('*.yml'))
    for entry in yml_files:
        original = resource_handler.load_file(entry)
        name = original['name']

        if asset:
            if name != asset:
                continue
            found_asset = True

        process_entry(entry, resource_handler, error_reporter)

    if asset and not found_asset:
        sys.exit(f"Error: Asset '{asset}' not found in the provided directory.")

    return error_reporter.has_errors()

def integration_validator(args, ruleset_path: Path, resource_handler: rs.ResourceHandler, error_reporter):
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
                name = original['name']
                if name in manifest[type_name]:
                    process_entry(entry, resource_handler, error_reporter)

    return error_reporter.has_errors()  # Return True if there are errors


def rules_validator(args, ruleset_path: Path, resource_handler: rs.ResourceHandler, error_reporter):
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
            resource_handler.load_file(entry)
            process_entry(entry, resource_handler, error_reporter)

    return error_reporter.has_errors()  # Return True if there are errors

def run(args):
    ruleset_path = Path(args['ruleset']).resolve()
    resource_handler = rs.ResourceHandler()

    if not ruleset_path.is_dir():
        sys.exit(f"Engine ruleset not found: {ruleset_path}")

    error_reporter = ErrorReporter("Validation")
    integration_arg = args.get('integration')
    integration_rule_arg = args.get('integration_rule')
    decoder_arg = args.get('decoder')
    rule_arg = args.get('rule')

    specified_args = [arg for arg in [integration_arg, integration_rule_arg, rule_arg, decoder_arg] if arg]

    if len(specified_args) > 1:
        sys.exit("Error: Only one of 'integration', 'rule_folder', 'rule' or 'decoder' can be specified at a time.")

    try:
        print("Running metadata tests.")
        if integration_rule_arg:
            print("Validating integrations rules only.")
            rules_validator(args, ruleset_path, resource_handler, error_reporter)
        elif integration_arg:
            print("Validating integration only.")
            integration_validator(args, ruleset_path, resource_handler, error_reporter)
        elif decoder_arg:
            print("Validating decoder only.")
            asset_validator(args, ruleset_path, resource_handler, 'decoder', error_reporter)
        elif rule_arg:
            print("Validating decoder only.")
            asset_validator(args, ruleset_path, resource_handler, 'rule', error_reporter)
        else:
            print("No specific arguments provided, validating both integration and rules.")
            integration_validator(args, ruleset_path, resource_handler, error_reporter)
            rules_validator(args, ruleset_path, resource_handler, error_reporter)

        if error_reporter.has_errors():
            error_reporter.exit_with_errors("There are mandatory fields in the metadata field that are not present", ruleset_path)
        else:
            print("Success execution")
    except Exception as e:
        print(f"Error running test: {e}")
