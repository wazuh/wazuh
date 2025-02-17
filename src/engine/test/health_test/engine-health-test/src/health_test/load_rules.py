import yaml
import sys
from pathlib import Path
from google.protobuf.json_format import ParseDict

from engine_handler.handler import EngineHandler
from api_communication.proto import catalog_pb2 as api_catalog
from api_communication.proto import engine_pb2 as api_engine
from api_communication.proto import policy_pb2 as api_policy


def load_rules(ruleset_path: Path, engine_handler: EngineHandler) -> None:
    rules_directory = ruleset_path / 'rules'

    if not rules_directory.exists() or not rules_directory.is_dir():
        sys.exit(f"The directory {rules_directory} was not found.")

    for subdirectory in rules_directory.iterdir():
        if subdirectory.is_dir():
            for rule_file in subdirectory.glob('*.yml'):
                request = api_catalog.ResourcePost_Request()
                request.type = api_catalog.ResourceType.rule
                if subdirectory.name == 'wazuh-core':
                    request.namespaceid = "system"
                else:
                    request.namespaceid = "wazuh"
                request.content = rule_file.read_text()
                request.format = api_catalog.ResourceFormat.yml

                print(f"Loading rule...\n{request}")
                error, response = engine_handler.api_client.send_recv(request)

                if error:
                    sys.exit(error)

                parsed_response = ParseDict(response, api_engine.GenericStatus_Response())
                if parsed_response.status == api_engine.ERROR:
                    sys.exit(parsed_response.error)

                print(f"Rules loaded.")


def load_policy(ruleset_path: Path, engine_handler: EngineHandler, stop_on_warn: bool) -> None:
    request = api_policy.DefaultParentPost_Request()
    request.parent = "rule/enrichment/0"
    request.namespace = "wazuh"
    request.policy = "policy/wazuh/0"
    print(f"Setting default parent...\n{request}")
    error, response = engine_handler.api_client.send_recv(request)
    if error:
        sys.exit(error)
    parsed_response = ParseDict(
        response, api_policy.DefaultParentPost_Response())
    if parsed_response.status == api_engine.ERROR:
        sys.exit(parsed_response.error)
    if len(parsed_response.warning) > 0 and stop_on_warn:
        sys.exit(parsed_response.warning)
    print("Default parent set.")

    # Add enrichment rule
    request = api_policy.AssetPost_Request()
    request.asset = "rule/enrichment/0"
    request.policy = "policy/wazuh/0"
    request.namespace = "system"
    print(f"Adding enrichment rule...\n{request}")
    error, response = engine_handler.api_client.send_recv(request)
    if error:
        sys.exit(error)
    parsed_response = ParseDict(response, api_policy.AssetPost_Response())
    if parsed_response.status == api_engine.ERROR:
        sys.exit(parsed_response.error)
    if len(parsed_response.warning) > 0 and stop_on_warn:
        sys.exit(parsed_response.warning)
    print("enrichment rule added.")

    # Add rest of rules
    for ruleset_dir in (ruleset_path / 'rules').iterdir():
        if ruleset_dir.name == 'wazuh-core':
            continue

        for yaml_file in ruleset_dir.glob("*.yml"):
            with open(yaml_file, 'r') as f:
                content = yaml.safe_load(f)
                rule_name = content['name']

            request = api_policy.AssetPost_Request()
            request.asset = rule_name
            request.policy = "policy/wazuh/0"
            request.namespace = "wazuh"
            print(f"Adding {rule_name}...\n{request}")
            error, response = engine_handler.api_client.send_recv(request)
            if error:
                sys.exit(error)
            parsed_response = ParseDict(
                response, api_policy.AssetPost_Response())
            if parsed_response.status == api_engine.ERROR:
                sys.exit(parsed_response.error)
            if len(parsed_response.warning) > 0 and stop_on_warn:
                sys.exit(parsed_response.warning)
            print(f"{rule_name} added.")


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

    print("Stopping the engine...")
    engine_handler.stop()
    print("Engine stopped.")
