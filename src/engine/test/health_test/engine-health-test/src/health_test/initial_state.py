#!/usr/bin/env python3
import subprocess
import argparse
import sys
from pathlib import Path
from typing import Optional, Tuple
from google.protobuf.json_format import ParseDict
from shutil import copytree, copy

from engine_handler.handler import EngineHandler
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
    parser.add_argument('-r', '--ruleset',
                        help='Specify the path to the ruleset directory', required=True)
    parser.add_argument(
        '-t', '--test-dir', help='Specify the path to the test directory', required=True)

    return parser.parse_args()


def cpy_conf(env_path: Path, health_test_path: Path) -> Path:
    serv_conf_file = health_test_path / 'configuration_files' / 'config.env'
    dest_conf_file = env_path / 'config.env'

    if dest_conf_file.is_file():
        dest_conf_file.rename(dest_conf_file.with_suffix('.bak'))

    if not serv_conf_file.is_file():
        raise FileNotFoundError(
            f"Copy configuration file failed: File {serv_conf_file} does not exist")

    conf_str = serv_conf_file.read_text().replace(PLACEHOLDER, env_path.as_posix())
    dest_conf_file.write_text(conf_str)

    return dest_conf_file


def cpy_mmdb(env_path: Path, health_test_path: Path) -> Tuple[Path, Path]:
    mmdb_asn_path = health_test_path / 'testdb-asn.mmdb'
    dest_mmdb_asn_path = env_path / 'mmdb' / 'testdb-asn.mmdb'
    mmdb_city_path = health_test_path / 'testdb-city.mmdb'
    dest_mmdb_city_path = env_path / 'mmdb' / 'testdb-city.mmdb'

    if not mmdb_asn_path.is_file():
        raise FileNotFoundError(
            f"Copy mmdb failed: File {mmdb_asn_path} does not exist")
    if not mmdb_city_path.is_file():
        raise FileNotFoundError(
            f"Copy mmdb failed: File {mmdb_city_path} does not exist")

    dest_mmdb_asn_path.parent.mkdir(parents=True, exist_ok=True)

    dest_mmdb_asn_path.write_bytes(mmdb_asn_path.read_bytes())
    dest_mmdb_city_path.write_bytes(mmdb_city_path.read_bytes())

    return dest_mmdb_asn_path, dest_mmdb_city_path


def cpy_ruleset(env_path: Path, ruleset_path: Path) -> Path:
    dest_ruleset_path = env_path / 'ruleset'
    copytree(ruleset_path, dest_ruleset_path)

    # Modify outputs paths
    for output_file in (dest_ruleset_path / 'outputs').rglob('*.yml'):
        output_file.write_text(output_file.read_text().replace(
            '/var/ossec', env_path.as_posix()))

    log_alerts_path = env_path / 'logs' / 'alerts'
    log_alerts_path.mkdir(parents=True, exist_ok=True)

    return dest_ruleset_path


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


def init(env_path: Path, ruleset_path: Path, health_test_path: Path, stop_on_warn: bool) -> None:
    engine_handler: Optional[EngineHandler] = None

    try:
        print(f"Copying configuration file to {env_path}...")
        config_path = cpy_conf(env_path, health_test_path)
        print("Configuration file copied.")

        print("Copying MMDB test files...")
        asn_path, city_path = cpy_mmdb(env_path, health_test_path)
        print("MMDB test files copied.")

        print("Copying ruleset files...")
        print(ruleset_path)
        ruleset_path = cpy_ruleset(env_path, ruleset_path)
        print("Ruleset files copied.")

        bin_path = env_path / 'wazuh-engine'

        print("Starting the engine...")
        engine_handler = EngineHandler(
            bin_path.as_posix(), config_path.as_posix())
        engine_handler.start()
        print("Engine started.")

        # Load mmdbs
        load_mmdb(engine_handler, asn_path, "asn")
        load_mmdb(engine_handler, city_path, "city")

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
    ruleset_path = Path(args['ruleset']).resolve()
    health_test_path = Path(args['test_dir']).resolve()
    stop_on_warning = args.get('stop_on_warning', False)

    init(env_path, ruleset_path, health_test_path, stop_on_warning)
