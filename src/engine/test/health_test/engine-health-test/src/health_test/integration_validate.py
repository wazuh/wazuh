import sys
import shared.resource_handler as rs
import shared.executor as exec
from pathlib import Path
from engine_handler.handler import EngineHandler

DEFAULT_NAMESPACE = 'user'

def process_integration_entry(api_socket, entry, kvdbs, added_kvdbs_paths, executor, resource_handler, namespace):
    """
    Process a single integration entry, creating tasks for kvdbs and catalog validation.
    """
    original = resource_handler.load_file(entry)
    
    name = original['name']

    if entry.parent.as_posix() not in added_kvdbs_paths:
        added_kvdbs_paths.append(entry.parent.as_posix())
        for kvdb_entry in entry.parent.glob('*.json'):
            if kvdb_entry.stem not in kvdbs:
                recoverable_task = resource_handler.get_create_kvdb_task(
                    api_socket, kvdb_entry.stem, str(kvdb_entry))
                executor.add(recoverable_task)

    task = resource_handler.get_validate_catalog_task(
        api_socket, name.split('/')[0], name, original, namespace)
    executor.add(task)

def validator(args, ruleset_path: Path, resource_handler: rs.ResourceHandler, api_socket: str):
    integration = args.get('integration')
    asset = args.get('asset')
    kvdbs = resource_handler.get_kvdb_list(api_socket)["data"]["dbs"]

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

    executor = exec.Executor()
    added_kvdbs_paths = []

    for integration_path in integrations_to_process:
        working_path = str(integration_path.resolve())
        print(f'Validating integration from: {working_path}')

        manifest = dict()
        integration_full_name = ''
        try:
            manifest_path = integration_path / 'manifest.yml'
            manifest = resource_handler.load_file(manifest_path.as_posix())
            integration_full_name = manifest['name']
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
                        process_integration_entry(api_socket, entry, kvdbs, added_kvdbs_paths, executor, resource_handler, DEFAULT_NAMESPACE)
                        break
                else:
                    if name in manifest[type_name]:
                        process_integration_entry(api_socket, entry, kvdbs, added_kvdbs_paths, executor, resource_handler, DEFAULT_NAMESPACE)

        print(f'Validating {integration_full_name} to the catalog')

    print('\nTasks:')
    executor.list_tasks()
    print('\nExecuting tasks...')
    executor.execute()
    print('\nDone')

def run(args):
    if 'environment' not in args:
        sys.exit("It is mandatory to indicate the '-e' environment path")
    env_path = Path(args['environment']).resolve()
    resource_handler = rs.ResourceHandler()
    conf_path = (env_path / "engine/general.conf").resolve()
    if not conf_path.is_file():
        print(f"Configuration file not found: {conf_path}")
        sys.exit(1)

    bin_path = (env_path / "bin/wazuh-engine").resolve()
    if not bin_path.is_file():
        print(f"Engine binary not found: {bin_path}")
        sys.exit(1)

    ruleset_path = (env_path / "ruleset").resolve()
    if not ruleset_path.is_dir():
        print(f"Engine ruleset not found: {ruleset_path}")
        sys.exit(1)
    
    print("Starting engine...")
    engine_handler = EngineHandler(bin_path.as_posix(), conf_path.as_posix())
    api_socket = engine_handler.api_socket_path

    try:
        engine_handler.start()
        print("Engine started.")
        validator(args, ruleset_path, resource_handler, api_socket)
    except Exception as e:
        print(f"Error running test: {e}")
    finally:
        print("Stopping engine...")
        engine_handler.stop()
        print("Engine stopped.")
