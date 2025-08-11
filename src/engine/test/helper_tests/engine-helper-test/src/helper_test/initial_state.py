#!/usr/bin/env python3
import shutil

import sys
import os
import pwd
import grp
from typing import Optional, Tuple
from pathlib import Path
from google.protobuf.json_format import ParseDict

from api_communication.proto import engine_pb2 as api_engine
from api_communication.proto import geo_pb2 as api_geo
from engine_handler.handler import EngineHandler
from shared.default_settings import Constants
from engine_handler.handler import EngineHandler


def configure(subparsers):
    parser = subparsers.add_parser('init',
                                   help="Update configuration, create kvdbs and mmdbs"
                                   )

    parser.add_argument("--mmdb", required=True,
                        help="Directory path where the as and geo databases are located")
    parser.add_argument("--conf", required=True,
                        help="File path where the engine configuration file is")

    parser.set_defaults(func=run)


def cpy_conf(env_path: Path, conf_path: Path) -> Path:
    if not conf_path.is_file():
        raise FileNotFoundError(f"File {conf_path} does not exist")
    serv_conf_file = conf_path
    dest_conf_file = env_path / 'config.env'

    if dest_conf_file.is_file():
        dest_conf_file.rename(dest_conf_file.with_suffix('.bak'))

    # Read the source config once
    conf_str = serv_conf_file.read_text()

    # Replace path placeholder
    conf_str = conf_str.replace(Constants.PLACEHOLDER, env_path.as_posix())

    # Write updated config to destination
    dest_conf_file.write_text(conf_str)

    return dest_conf_file


def cpy_mmdb(env_path: Path, health_test_path: Path) -> Tuple[Path, Path]:
    mmdb_asn_path = health_test_path / 'testdb-asn.mmdb'
    dest_mmdb_asn_path = env_path / 'mmdbs' / 'testdb-asn.mmdb'
    mmdb_city_path = health_test_path / 'testdb-city.mmdb'
    dest_mmdb_city_path = env_path / 'mmdbs' / 'testdb-city.mmdb'

    if not mmdb_asn_path.is_file():
        raise FileNotFoundError(f"Copy mmdb failed: File {mmdb_asn_path} does not exist")
    if not mmdb_city_path.is_file():
        raise FileNotFoundError(f"Copy mmdb failed: File {mmdb_city_path} does not exist")

    dest_mmdb_asn_path.parent.mkdir(parents=True, exist_ok=True)

    dest_mmdb_asn_path.write_bytes(mmdb_asn_path.read_bytes())
    dest_mmdb_city_path.write_bytes(mmdb_city_path.read_bytes())

    return dest_mmdb_asn_path, dest_mmdb_city_path


def cpy_kvdb(env_path: Path):
    kvdb_path = env_path / "tmp" / "kvdb_test.json"
    kvdb_path.parent.mkdir(parents=True, exist_ok=True)
    kvdb_path.write_text(
        '{"test": {"key": "value"}, "test_bitmask": {"33": "some_data"}}')


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


def init(env_path: Path, conf_path: Path, mmdb_dir: Path):
    engine_handler: Optional[EngineHandler] = None

    print(f"Copying configuration file to {env_path}...")
    config_path = cpy_conf(env_path, conf_path)
    print("Configuration file copied.")

    print("Copying MMDB test files...")
    asn_path, city_path = cpy_mmdb(env_path, mmdb_dir)
    print("MMDB test files copied.")

    print("Creating KVDB...")
    cpy_kvdb(env_path)
    print("KVDB created.")

    binary_path = env_path / 'wazuh-engine'

    try:
        print("Starting engine...")
        engine_handler = EngineHandler(
            binary_path.as_posix(), config_path.as_posix())
        engine_handler.start()

        load_mmdb(engine_handler, asn_path, "asn")
        load_mmdb(engine_handler, city_path, "city")

        print("Stopping the engine...")
        engine_handler.stop()
        print("Engine stopped.")

    except:
        if engine_handler:
            print("Stopping the engine...")
            engine_handler.stop()
            print("Engine stopped.")

        raise


def run(args):
    env_path = Path(args['environment']).resolve()
    conf_dir = Path(args['conf']).resolve()
    mmdb_dir = Path(args['mmdb']).resolve()

    try:
        init(env_path, conf_dir, mmdb_dir)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)

    sys.exit(0)
