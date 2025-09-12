import yaml
import sys
from pathlib import Path
from google.protobuf.json_format import ParseDict

from engine_handler.handler import EngineHandler
from api_communication.proto import engine_pb2 as api_engine
from api_communication.proto import policy_pb2 as api_policy
from api_communication.proto import tester_pb2 as api_tester
from shared.default_settings import Constants

import shared.resource_handler as ResourceHandler
from engine_integration.cmds.add import add_integration as engine_integration_add

def load_rules(ruleset_path: Path, engine_handler: EngineHandler) -> None:
    for integration_dir in (ruleset_path / 'integrations-rules').iterdir():
        ns = "system" if integration_dir.name == 'wazuh-core' else "wazuh"

        # Load integration
        print(f"Loading integrations rules...\n")
        rs = ResourceHandler.ResourceHandler()
        engine_integration_add(engine_handler.api_socket_path, ns, integration_dir.resolve().as_posix(), False, rs, False)
        print(f"Integration loaded.")

def load_policy(ruleset_path: Path, engine_handler: EngineHandler, stop_on_warn: bool) -> None:
    # Add all rules
    for integration_dir in (ruleset_path / 'integrations-rules').iterdir():
        if integration_dir.name == 'wazuh-core':
            continue

        integration_name = f'integration/{integration_dir.name}-rules/0'
        request = api_policy.AssetPost_Request()
        request.asset = integration_name
        request.policy = "policy/wazuh/0"
        request.namespace = "wazuh"
        print(f"Adding {integration_name}...\n{request}")
        error, response = engine_handler.api_client.send_recv(request)
        if error:
            sys.exit(error)
        parsed_response = ParseDict(
            response, api_policy.AssetPost_Response())
        if parsed_response.status == api_engine.ERROR:
            sys.exit(parsed_response.error)
        if len(parsed_response.warning) > 0 and stop_on_warn:
            sys.exit(parsed_response.warning)
        print(f"{integration_name} added.")

def reload_session(engine_handler: EngineHandler) -> None:
    request = api_tester.SessionReload_Request()
    request.name = Constants.DEFAULT_SESSION
    print(f"Reloading session...\n{request}")
    error, response = engine_handler.api_client.send_recv(request)
    if error:
        sys.exit(error)
    parsed_response = ParseDict(response, api_engine.GenericStatus_Response())
    if parsed_response.status == api_engine.ERROR:
        sys.exit(parsed_response.error)
    print("Session reloaded.")

def run(args):
    env_path = Path(args['environment']).resolve()

    conf_path = (env_path / "config.env").resolve()
    if not conf_path.is_file():
        print(f"Configuration file not found: {conf_path}")
        sys.exit(1)

    bin_path = (env_path / "wazuh-engine").resolve()
    if not bin_path.is_file():
        print(f"Engine binary not found: {bin_path}")
        sys.exit(1)

    ruleset_path = (env_path / "ruleset").resolve()
    if not ruleset_path.is_dir():
        print(f"Engine ruleset not found: {ruleset_path}")
        sys.exit(1)

    stop_on_warn = args.get('stop_on_warning', False)

    print("Starting the engine...")
    engine_handler = EngineHandler(
        bin_path.as_posix(), conf_path.as_posix())
    engine_handler.start()
    print("Engine started.")

    # Load rules
    load_rules(ruleset_path, engine_handler)

    # Create policy
    load_policy(ruleset_path, engine_handler, stop_on_warn)

    # Reload Session
    reload_session(engine_handler)

    print("Stopping the engine...")
    engine_handler.stop()
    print("Engine stopped.")
