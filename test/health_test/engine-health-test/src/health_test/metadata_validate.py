import sys
import shared.resource_handler as rs
from pathlib import Path

def validate_metadata(content):
    """
    Validate the metadata of an integration entry.
    """
    required_metadata_fields = ['module', 'title', 'description', 'compatibility', 'versions', 'references', 'author']
    required_author_fields = ['name', 'date']
    
    metadata = content.get('metadata', {})
    missing_fields = [field for field in required_metadata_fields if field not in metadata]
    
    if missing_fields:
        raise Exception(f"Missing required metadata fields: {', '.join(missing_fields)}")
    
    # Check that certain fields are of type string
    for field in ['module', 'title', 'description', 'compatibility']:
        if not isinstance(metadata.get(field), str):
            raise Exception(f"'{field}' must be of type string")
    
    author_metadata = metadata.get('author', {})
    missing_author_fields = [field for field in required_author_fields if field not in author_metadata]
    
    if missing_author_fields:
        raise Exception(f"Missing required author fields: {', '.join(missing_author_fields)}")
    
    # Check that author fields are of type string
    for field in ['name', 'date']:
        if not isinstance(author_metadata.get(field), str):
            raise Exception(f"'{field}' in author metadata must be of type string")
    
    # Check that 'versions' and 'references' are lists
    if not isinstance(metadata.get('versions', None), list):
        raise Exception("'versions' must be of type list")
    
    if not isinstance(metadata.get('references', None), list):
        raise Exception("'references' must be of type list")
    

def process_integration_entry(entry, resource_handler: rs.ResourceHandler):
    """
    Process a single integration entry, creating tasks for kvdbs and catalog validation.
    """
    original = resource_handler.load_file(entry)
    
    try:
        validate_metadata(original)
    except Exception as e:
        sys.exit(f'Error in metadata validation for {entry}: {e}')
    

def validator(args, ruleset_path: Path, resource_handler: rs.ResourceHandler):
    integration = args.get('integration')
    asset = args.get('asset')

    # Restrict specifying an asset without an integration
    if asset and not integration:
        sys.exit("Error: An asset cannot be specified without an integration.")

    if integration:
        integration_path = ruleset_path / 'integrations' / integration
        if not integration_path.exists() or not integration_path.is_dir():
            sys.exit(f"Integration '{integration}' not found in '{ruleset_path / 'integrations'}'.")
        integrations_to_process = [integration_path]
    else:
        # If no integration is provided, process all integration directories
        integrations_path = ruleset_path / 'integrations'
        if not integrations_path.exists() or not integrations_path.is_dir():
            sys.exit(f"Integrations directory not found in '{ruleset_path}'.")
        integrations_to_process = [d for d in integrations_path.iterdir() if d.is_dir()]

    for integration_path in integrations_to_process:
        working_path = str(integration_path.resolve())
        print(f'Validating metadata from: {working_path}')

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
                        break
                else:
                    if name in manifest[type_name]:
                        process_integration_entry(entry, resource_handler)

def run(args):
    env_path = Path(args['environment']).resolve()
    resource_handler = rs.ResourceHandler()

    ruleset_path = (env_path / "ruleset").resolve()
    if not ruleset_path.is_dir():
        print(f"Engine ruleset not found: {ruleset_path}")
        sys.exit(1)

    try:
        print("Running metadata tests.")
        validator(args, ruleset_path, resource_handler)
    except Exception as e:
        print(f"Error running test: {e}")
