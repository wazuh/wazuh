import sys
import yaml
import shared.resource_handler as rs
import shared.executor as exec
from pathlib import Path
from engine_handler.handler import EngineHandler
from api_communication.client import APIClient
from api_communication.proto import catalog_pb2 as api_catalog
from api_communication.proto import kvdb_pb2 as api_kvdb
from api_communication.proto.engine_pb2 import GenericStatus_Response

DEFAULT_NAMESPACE = 'user'

def add_kvdb_task(executor: exec.Executor, client: APIClient, kvdb_path: Path) -> None:
    def do():
        json_request = dict()
        json_request['name'] = kvdb_path.stem
        json_request['path'] = kvdb_path.as_posix()

        error, _ = client.jsend(
            json_request, api_kvdb.managerPost_Request(), GenericStatus_Response())
        if error:
            return error

        return None

    def undo():
        json_request = dict()
        json_request['name'] = kvdb_path.stem

        error, _ = client.jsend(
            json_request, api_kvdb.managerDelete_Request(), GenericStatus_Response())
        if error:
            return error

        return None

    executor.add(exec.RecoverableTask(do, undo, f'Add KVDB: {kvdb_path.stem}'))

def validate_asset_task(executor: exec.Executor, client: APIClient, asset_name: str, asset_content: str, namespace: str) -> None:
    def do():
        json_request = dict()
        json_request['content'] = asset_content
        json_request['namespaceid'] = namespace
        json_request['format'] = 'yaml'
        json_request['name'] = asset_name

        error, _ = client.jsend(
            json_request, api_catalog.ResourceValidate_Request(), GenericStatus_Response())
        if error:
            return error
        return None

    def undo():
        return None

    executor.add(exec.RecoverableTask(do, undo, f'Validate Asset: {asset_name}'))

def process_integration_entry(api_socket, entry, kvdbs, added_kvdbs_paths, executor, resource_handler, namespace):
    """
    Process a single integration entry, creating tasks for kvdbs and catalog validation.
    """
    original = resource_handler.load_file(entry)
    name = original['name']
    # Recover original content
    content = yaml.dump(original, sort_keys=False)

    api_client: APIClient
    try:
        api_client = APIClient(api_socket)
    except Exception as e:
        sys.exit(f'Error: {e}')

    if entry.parent.as_posix() not in added_kvdbs_paths:
        added_kvdbs_paths.append(entry.parent.as_posix())
        for kvdb_entry in entry.parent.glob('*.json'):
            if kvdb_entry.stem not in kvdbs:
                add_kvdb_task(executor, api_client, kvdb_entry)

    validate_asset_task(executor, api_client, name, content, namespace)

def validate_integrations(integrations_to_process, api_socket, kvdbs, ruleset_path, executor, resource_handler):
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
            if type_name not in ['decoders', 'outputs', 'filters']:
                continue

            path = ruleset_path / type_name
            if not path.exists():
                sys.exit(f'Error: {type_name} directory does not exist')

            for entry in path.rglob('*.yml'):
                original = resource_handler.load_file(entry)
                name = original['name']
                if name in manifest[type_name]:
                    process_integration_entry(api_socket, entry, kvdbs, added_kvdbs_paths, executor, resource_handler, DEFAULT_NAMESPACE)

        print(f'Validating {integration_full_name} to the catalog')

def validate_rules(rules_to_process, api_socket, kvdbs, executor, resource_handler):
    for rule_folder_path in rules_to_process:
        for entry in rule_folder_path.glob('*.yml'):
            process_integration_entry(api_socket, entry, kvdbs, [], executor, resource_handler, DEFAULT_NAMESPACE)

def validate_decoders(decoders_to_process, api_socket, kvdbs, executor, resource_handler):
    for decoder_path in decoders_to_process:
        for entry in decoder_path.rglob('*.yml'):
            process_integration_entry(api_socket, entry, kvdbs, [], executor, resource_handler, DEFAULT_NAMESPACE)

def validator(args, ruleset_path: Path, resource_handler: rs.ResourceHandler, api_socket: str):
    integration = args.get('integration')
    decoder = args.get('decoder')
    rule_folder = args.get('rule_folder')

    request = dict()
    request['must_be_loaded'] = False

    api_client: APIClient
    try:
        api_client = APIClient(api_socket)
    except Exception as e:
        sys.exit(f'Error: {e}')

    error, response = api_client.jsend(request, api_kvdb.managerGet_Request(), api_kvdb.managerGet_Response())
    if error:
        sys.exit(f"Error: {response}")

    kvdbs = response['dbs']

    specified_args = [arg for arg in [integration, rule_folder, decoder] if arg]
    if len(specified_args) > 1:
        sys.exit("Error: Only one of 'integration', 'rule_folder', or 'decoder' can be specified at a time.")

    executor = exec.Executor()

    if integration:
        integration_path = ruleset_path / 'integrations' / integration
        if not integration_path.exists() or not integration_path.is_dir():
            sys.exit(f"Integration '{integration}' not found in '{ruleset_path / 'integrations'}'.")
        integrations_to_process = [integration_path]
        validate_integrations(integrations_to_process, api_socket, kvdbs, ruleset_path, executor, resource_handler)

    elif rule_folder:
        rule_folder_path = ruleset_path / 'rules' / rule_folder
        if not rule_folder_path.exists() or not rule_folder_path.is_dir():
            sys.exit(f"Rules folder '{rule_folder}' not found in '{ruleset_path / 'rules'}'.")
        rules_to_process = [rule_folder_path]
        validate_rules(rules_to_process, api_socket, kvdbs, executor, resource_handler)

    elif decoder:
        print("Validating decoder only.")
        found_decoder = False
        decoders_path = ruleset_path / 'decoders'
        if not decoders_path.exists() or not decoders_path.is_dir():
            sys.exit(f"Decoders directory not found in '{ruleset_path}'.")

        yml_files = list(decoders_path.rglob('*.yml'))
        for entry in yml_files:
            original = resource_handler.load_file(entry)
            name = original['name']

            if decoder:
                if name != decoder:
                    continue
                found_decoder = True
            process_integration_entry(api_socket, entry, kvdbs, [], executor, resource_handler, DEFAULT_NAMESPACE)

        if decoder and not found_decoder:
            sys.exit(f"Error: Decoder '{decoder}' not found in the provided decoders directory.")

    else:
        integrations_path = ruleset_path / 'integrations'
        if not integrations_path.exists() or not integrations_path.is_dir():
            sys.exit(f"Integrations directory not found in '{ruleset_path}'.")
        integrations_to_process = [d for d in integrations_path.iterdir() if d.is_dir()]
        validate_integrations(integrations_to_process, api_socket, kvdbs, ruleset_path, executor, resource_handler)

        rules_path = ruleset_path / 'rules'
        if not rules_path.exists() or not rules_path.is_dir():
            sys.exit(f"Rules directory not found in '{ruleset_path}'.")
        rules_to_process = [d for d in rules_path.iterdir() if d.is_dir()]
        validate_rules(rules_to_process, api_socket, kvdbs, executor, resource_handler)

    print('\nTasks:')
    executor.list_tasks()
    print('\nExecuting tasks...')
    executor.execute()
    print('\nDone')

def run(args):
    env_path = Path(args['environment']).resolve()
    resource_handler = rs.ResourceHandler()
    conf_path = (env_path / "config.env").resolve()
    if not conf_path.is_file():
        sys.exit(f"Configuration file not found: {conf_path}")

    bin_path = (env_path / "wazuh-engine").resolve()
    if not bin_path.is_file():
        sys.exit(f"Engine binary not found: {bin_path}")

    ruleset_path = (env_path / "ruleset").resolve()
    if not ruleset_path.is_dir():
        sys.exit(f"Engine ruleset not found: {ruleset_path}")

    print("Starting engine...")
    engine_handler = EngineHandler(bin_path.as_posix(), conf_path.as_posix())
    api_socket = engine_handler.api_socket_path

    try:
        engine_handler.start()
        print("Engine started.")
        validator(args, ruleset_path, resource_handler, api_socket)
    except Exception as e:
        print(f"Error running test: {e}. Stopping engine...")
        engine_handler.stop()
        sys.exit(1)

    print("Stopping engine...")
    engine_handler.stop()
    print("Engine stopped.")
