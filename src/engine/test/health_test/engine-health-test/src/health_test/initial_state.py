#!/usr/bin/env python3
import subprocess
import argparse
import sys
from pathlib import Path
from typing import Optional, Tuple
from google.protobuf.json_format import ParseDict
from shutil import copytree, copy

from engine_updown.handler import EngineHandler
from api_communication.proto import geo_pb2 as api_geo
from api_communication.proto import catalog_pb2 as api_catalog
from api_communication.proto import engine_pb2 as api_engine
from api_communication.proto import policy_pb2 as api_policy
from api_communication.proto import router_pb2 as api_router

PLACEHOLDER = "ENV_PATH_PLACEHOLDER"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Sets the initial state for the Engine health test')
    parser.add_argument('-e', '--environment',
                        help='Specify environment directory', required=True)
    parser.add_argument(
        '-b', '--binary', help='Specify the path to the engine binary', required=True)
    parser.add_argument('-r', '--ruleset',
                        help='Specify the path to the ruleset directory', required=True)
    parser.add_argument(
        '-t', '--test-dir', help='Specify the path to the test directory', required=True)

    return parser.parse_args()


def cpy_conf(env_path: Path, health_test_path: Path) -> Path:
    serv_conf_file = health_test_path / 'configuration_files' / 'general.conf'
    dest_conf_file = env_path / 'engine' / 'general.conf'

    conf_str = serv_conf_file.read_text().replace(PLACEHOLDER, env_path.as_posix())
    dest_conf_file.write_text(conf_str)

    return dest_conf_file


def cpy_mmdb(env_path: Path, health_test_path: Path) -> Tuple[Path, Path]:
    mmdb_asn_path = health_test_path / 'testdb-asn.mmdb'
    dest_mmdb_asn_path = env_path / 'engine' / 'etc' / 'testdb-asn.mmdb'
    mmdb_city_path = health_test_path / 'testdb-city.mmdb'
    dest_mmdb_city_path = env_path / 'engine' / 'etc' / 'testdb-city.mmdb'

    dest_mmdb_asn_path.write_bytes(mmdb_asn_path.read_bytes())
    dest_mmdb_city_path.write_bytes(mmdb_city_path.read_bytes())

    return dest_mmdb_asn_path, dest_mmdb_city_path


def cpy_ruleset(env_path: Path, ruleset_path: Path) -> Path:
    dest_ruleset_path = env_path / 'ruleset/engine'
    copytree(ruleset_path, dest_ruleset_path)

    # Modify outputs paths
    for output_file in (dest_ruleset_path / 'outputs').rglob('*.yml'):
        output_file.write_text(output_file.read_text().replace(
            '/var/ossec', env_path.as_posix()))

    log_alerts_path = env_path / 'logs' / 'alerts'
    log_alerts_path.mkdir(parents=True, exist_ok=True)

    return dest_ruleset_path


def cpy_bin(env_path: Path, bin_path: Path) -> Path:
    dest_bin_path = env_path / 'bin/wazuh-engine'
    dest_bin_path.parent.mkdir(parents=True, exist_ok=True)

    return copy(bin_path, dest_bin_path)


def load_mmdb(engine_handler: EngineHandler, mmdb_path: Path, mmdb_type: str) -> None:
    request = api_geo.DbPost_Request()
    request.path = mmdb_path.as_posix()
    request.type = mmdb_type
    print(f"Loading MMDB file...\n{request}")
    error, response = engine_handler.api_client.send_recv(request)
    if error:
        raise Exception(error)

    parsed_response = ParseDict(response, api_engine.GenericStatus_Response())
    if parsed_response.status == api_engine.ERROR:
        raise Exception(parsed_response.error)
    print(f"MMDB file loaded.")


def load_filters(ruleset_path: Path, engine_handler: EngineHandler) -> None:
    for filter_file in (ruleset_path / 'filters').rglob('*.yml'):
        request = api_catalog.ResourcePost_Request()
        request.type = api_catalog.ResourceType.filter
        request.namespaceid = "system"
        request.content = filter_file.read_text()
        request.format = api_catalog.ResourceFormat.yml
        print(f"Loading filter...\n{request}")
        error, response = engine_handler.api_client.send_recv(request)
        if error:
            raise Exception(error)

        parsed_response = ParseDict(
            response, api_engine.GenericStatus_Response())
        if parsed_response.status == api_engine.ERROR:
            raise Exception(parsed_response.error)
        print(f"Filter loaded.")


def load_integrations(ruleset_path: Path, engine_handler: EngineHandler) -> None:
    for integration_dir in (ruleset_path / 'integrations').iterdir():
        ns = "system" if integration_dir.name == 'wazuh-core' else "wazuh"
        command_str = f'engine-integration add --api-sock {engine_handler.api_socket_path} --namespace {ns} {integration_dir.resolve().as_posix()}'
        print(f"Loading integration...\n{command_str}")
        subprocess.run(command_str, check=True, shell=True)
        print(f"Integration loaded.")


def load_policy(ruleset_path: Path, engine_handler: EngineHandler, stop_on_warn: bool) -> None:
    # Create policy
    request = api_policy.StorePost_Request()
    request.policy = "policy/wazuh/0"
    print(f"Creating policy...\n{request}")
    error, response = engine_handler.api_client.send_recv(request)
    if error:
        raise Exception(error)
    parsed_response = ParseDict(response, api_engine.GenericStatus_Response())
    if parsed_response.status == api_engine.ERROR:
        raise Exception(parsed_response.error)
    print("Policy created.")

    # Set default parents for wazuh and user namespaces
    request = api_policy.DefaultParentPost_Request()
    request.parent = "decoder/integrations/0"
    request.namespace = "wazuh"
    request.policy = "policy/wazuh/0"
    print(f"Setting default parent...\n{request}")
    error, response = engine_handler.api_client.send_recv(request)
    if error:
        raise Exception(error)
    parsed_response = ParseDict(
        response, api_policy.DefaultParentPost_Response())
    if parsed_response.status == api_engine.ERROR:
        raise Exception(parsed_response.error)
    if len(parsed_response.warning) > 0 and stop_on_warn:
        raise Exception(parsed_response.warning)
    print("Default parent set.")

    request = api_policy.DefaultParentPost_Request()
    request.parent = "decoder/integrations/0"
    request.namespace = "user"
    request.policy = "policy/wazuh/0"
    print(f"Setting default parent...\n{request}")
    error, response = engine_handler.api_client.send_recv(request)
    if error:
        raise Exception(error)
    parsed_response = ParseDict(
        response, api_policy.DefaultParentPost_Response())
    if parsed_response.status == api_engine.ERROR:
        raise Exception(parsed_response.error)
    if len(parsed_response.warning) > 0 and stop_on_warn:
        raise Exception(parsed_response.warning)
    print("Default parent set.")

    # Add wazuh-core
    request = api_policy.AssetPost_Request()
    request.asset = "integration/wazuh-core/0"
    request.policy = "policy/wazuh/0"
    request.namespace = "system"
    print(f"Adding wazuh-core...\n{request}")
    error, response = engine_handler.api_client.send_recv(request)
    if error:
        raise Exception(error)
    parsed_response = ParseDict(response, api_policy.AssetPost_Response())
    if parsed_response.status == api_engine.ERROR:
        raise Exception(parsed_response.error)
    if len(parsed_response.warning) > 0 and stop_on_warn:
        raise Exception(parsed_response.warning)
    print("wazuh-core added.")

    # Add rest of integrations
    for integration_dir in (ruleset_path / 'integrations').iterdir():
        if integration_dir.name == 'wazuh-core':
            continue

        integration_name = f'integration/{integration_dir.name}/0'
        request = api_policy.AssetPost_Request()
        request.asset = integration_name
        request.policy = "policy/wazuh/0"
        request.namespace = "wazuh"
        print(f"Adding {integration_name}...\n{request}")
        error, response = engine_handler.api_client.send_recv(request)
        if error:
            raise Exception(error)
        parsed_response = ParseDict(
            response, api_policy.AssetPost_Response())
        if parsed_response.status == api_engine.ERROR:
            raise Exception(parsed_response.error)
        if len(parsed_response.warning) > 0 and stop_on_warn:
            raise Exception(parsed_response.warning)
        print(f"{integration_name} added.")

    # Load environment
    request = api_router.RoutePost_Request()
    request.route.name = "default"
    request.route.policy = "policy/wazuh/0"
    request.route.filter = "filter/allow-all/0"
    request.route.priority = 254
    request.route.description = "Default route"
    print(f"Loading environment...\n{request}")
    error, response = engine_handler.api_client.send_recv(request)
    if error:
        raise Exception(error)
    parsed_response = ParseDict(response, api_engine.GenericStatus_Response())
    if parsed_response.status == api_engine.ERROR:
        raise Exception(parsed_response.error)
    print("Environment loaded.")


def init(env_path: Path, bin_path: Path, ruleset_path: Path, health_test_path: Path, stop_on_warn: bool) -> None:
    engine_handler: Optional[EngineHandler] = None

    try:
        print(f"Copying configuration file to {env_path}...")
        config_path = cpy_conf(env_path, health_test_path)
        print("Configuration file copied.")

        print("Copying MMDB test files...")
        asn_path, city_path = cpy_mmdb(env_path, health_test_path)
        print("MMDB test files copied.")

        print("Copying ruleset files...")
        ruleset_path = cpy_ruleset(env_path, ruleset_path)
        print("Ruleset files copied.")

        print("Copying engine binary...")
        bin_path = cpy_bin(env_path, bin_path)
        print("Engine binary copied.")

        print("Starting the engine...")
        engine_handler = EngineHandler(
            bin_path.as_posix(), config_path.as_posix())
        engine_handler.start()
        print("Engine started.")

        # Load mmdbs
        load_mmdb(engine_handler, asn_path, "asn")
        load_mmdb(engine_handler, city_path, "city")

        # Load filters
        load_filters(ruleset_path, engine_handler)

        # Load integrations
        load_integrations(ruleset_path, engine_handler)

        # Create policy
        load_policy(ruleset_path, engine_handler, stop_on_warn)

        print("Stopping the engine...")
        engine_handler.stop()
        print("Engine stopped.")

    except Exception as e:
        print(f"An error occurred: {e}")
        if engine_handler:
            print("Stopping the engine...")
            engine_handler.stop()
            print("Engine stopped.")

        sys.exit(1)

    sys.exit(0)


def run(args):
    env_path = Path(args['environment']).resolve()
    bin_path = Path(args['binary']).resolve()
    ruleset_path = Path(args['ruleset']).resolve()
    health_test_path = Path(args['test_dir']).resolve()
    stop_on_warning = args.get('stop_on_warning', False)

    init(env_path, bin_path, ruleset_path, health_test_path, stop_on_warning)
