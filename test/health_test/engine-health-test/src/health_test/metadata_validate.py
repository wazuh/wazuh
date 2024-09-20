import sys
import shared.resource_handler as rs
from pathlib import Path
from health_test.error_managment import ErrorReporter

error_reporter = ErrorReporter()

def validate_metadata(content, entry):
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


def process_integration_entry(entry, resource_handler: rs.ResourceHandler):
    """
    Process a single integration entry, creating tasks for kvdbs and catalog validation.
    """
    original = resource_handler.load_file(entry)
    validate_metadata(original, entry)


def validator(args, ruleset_path: Path, resource_handler: rs.ResourceHandler):
    integration = args.get('integration')
    asset = args.get('asset')

    if asset and not integration:
        sys.exit("Error: An asset cannot be specified without an integration.")

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

    asset_found = False

    for integration_path in integrations_to_process:
        manifest = dict()
        try:
            manifest_path = integration_path / 'manifest.yml'
            manifest = resource_handler.load_file(manifest_path.as_posix())
        except Exception as e:
            sys.exit(f'Error: {e}')

        for type_name in manifest.keys():
            if type_name not in ['decoders', 'rules', 'outputs', 'filters']:
                continue

            path = ruleset_path / type_name
            if not path.exists():
                sys.exit(f'Error: {type_name} directory does not exist')

            for entry in path.rglob('*.yml'):
                original = resource_handler.load_file(entry)
                name = original['name']
                if asset:
                    if asset == name:
                        process_integration_entry(entry, resource_handler)
                        asset_found = True
                        break
                else:
                    if name in manifest[type_name]:
                        process_integration_entry(entry, resource_handler)

    if asset and not asset_found:
        sys.exit(f"Error: Asset '{asset}' not found.")

    error_reporter.exit_with_errors("There are mandatory fields in the metadata field that are not present", ruleset_path)

def run(args):
    ruleset_path = Path(args['ruleset']).resolve()
    resource_handler = rs.ResourceHandler()

    if not ruleset_path.is_dir():
        print(f"Engine ruleset not found: {ruleset_path}")
        sys.exit(1)

    try:
        print("Running metadata tests.")
        validator(args, ruleset_path, resource_handler)
    except Exception as e:
        print(f"Error running test: {e}")
