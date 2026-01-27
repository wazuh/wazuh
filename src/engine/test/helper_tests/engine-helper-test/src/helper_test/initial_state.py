#!/usr/bin/env python3
import shutil

import sys
import os
import pwd
import grp
from typing import Optional, Tuple
from pathlib import Path
from google.protobuf.json_format import ParseDict
from datetime import datetime, timezone
import json
import hashlib

from api_communication.proto import engine_pb2 as api_engine
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
    dest_mmdb_asn_path = env_path / 'geo' / 'testdb-asn.mmdb'
    mmdb_city_path = health_test_path / 'testdb-city.mmdb'
    dest_mmdb_city_path = env_path / 'geo' / 'testdb-city.mmdb'

    if not mmdb_asn_path.is_file():
        raise FileNotFoundError(f"Copy mmdb failed: File {mmdb_asn_path} does not exist")
    if not mmdb_city_path.is_file():
        raise FileNotFoundError(f"Copy mmdb failed: File {mmdb_city_path} does not exist")

    dest_mmdb_asn_path.parent.mkdir(parents=True, exist_ok=True)

    dest_mmdb_asn_path.write_bytes(mmdb_asn_path.read_bytes())
    dest_mmdb_city_path.write_bytes(mmdb_city_path.read_bytes())

    return dest_mmdb_asn_path, dest_mmdb_city_path


def md5_file(path: Path) -> str:
    """Calculate MD5 hash of a file."""
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def init_geo_store(env_path: Path, city_mmdb: Path, asn_mmdb: Path):
    """
    Initialize geo store structure and JSON metadata for geo databases.

    Args:
        env_path: Environment root path
        city_mmdb: Path to CITY mmdb file
        asn_mmdb: Path to ASN mmdb file
    """
    geo_dest_path = env_path / "geo"
    geo_store_path = env_path / "store" / "geo"

    # Create directories
    geo_dest_path.mkdir(parents=True, exist_ok=True)
    geo_store_path.mkdir(parents=True, exist_ok=True)

    # Current timestamp in ISO 8601 format
    generated_at = int(datetime.now(timezone.utc).timestamp() * 1000)

    for mmdb_file, db_type in (
        (city_mmdb, "city"),
        (asn_mmdb, "asn"),
    ):
        if not mmdb_file.exists():
            raise FileNotFoundError(f"Geo DB not found: {mmdb_file}")

        if mmdb_file.suffix != ".mmdb":
            raise ValueError(f"Invalid Geo DB extension (expected .mmdb): {mmdb_file}")

        db_hash = md5_file(mmdb_file)

        metadata = {
            "path": mmdb_file.resolve().as_posix(),
            "type": db_type,
            "hash": db_hash,
            "generated_at": generated_at
        }

        store_json_path = geo_store_path / f"{mmdb_file.name}.json"
        with open(store_json_path, "w") as f:
            json.dump(metadata, f, indent=2)

        print(f"  Initialized {mmdb_file.name} ({db_type}): hash={db_hash[:8]}...")


def cpy_kvdb(env_path: Path):
    kvdb_path = env_path / "tmp" / "kvdb_test.json"
    kvdb_path.parent.mkdir(parents=True, exist_ok=True)
    kvdb_path.write_text(
        '{"test": {"key": "value"}, "test_bitmask": {"33": "some_data"}}')


def init(env_path: Path, conf_path: Path, mmdb_dir: Path):
    engine_handler: Optional[EngineHandler] = None

    print(f"Copying configuration file to {env_path}...")
    config_path = cpy_conf(env_path, conf_path)
    print("Configuration file copied.")

    print("Copying MMDB test files...")
    asn_path, city_path = cpy_mmdb(env_path, mmdb_dir)
    init_geo_store(env_path, city_path, asn_path)
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
