#!/usr/bin/env python3

import os
import shutil
import argparse
from pathlib import Path


def setup_engine(engine_src_dir, environment_dir):
    schemas = ["wazuh-logpar-overrides", "engine-schema", "allowed-fields"]

    for schema in schemas:
        print(f"Copying schema {schema}")
        schema_dir = os.path.join(environment_dir, 'store/schema', schema)
        os.makedirs(schema_dir, exist_ok=True)
        schema_json_path = os.path.join(engine_src_dir, 'ruleset/schemas', f'{schema}.json')
        shutil.copy(schema_json_path, os.path.join(schema_dir, '0'))

    dirs_to_create = [
        os.path.join(environment_dir, 'queue/sockets'),
        os.path.join(environment_dir, 'kvdb'),
        os.path.join(environment_dir, 'logs'),
    ]

    for directory in dirs_to_create:
        os.makedirs(directory, exist_ok=True)

    # Copy TZDB to bin directory (Remove this fix when the issue tzdb is fixed)
    tzdb_path = Path(engine_src_dir) / 'build' / 'tzdb'
    tzdb_dest = Path(environment_dir) / 'tzdb'
    print(f"Copying from {tzdb_path} to {tzdb_dest}")
    # If source not exists, show error message
    if not tzdb_path.exists():
        print(f"Error: TZDB in {tzdb_path} not exists, compile the engine first")
        exit(1)
    shutil.copytree(tzdb_path, tzdb_dest)

    # Copy engine binary
    engine_bin = Path(engine_src_dir) / 'build' / 'main'
    engine_bin_dest = Path(environment_dir) / 'wazuh-engine'
    print(f"Copying from {engine_bin} to {engine_bin_dest}")
    # If source not exists, show error message
    if not engine_bin.exists():
        print(f"Error: {engine_bin} not exists, compile the engine first")
        exit(1)
    shutil.copy(engine_bin, engine_bin_dest)


def main():
    parser = argparse.ArgumentParser(description='Setup engine directories.')
    parser.add_argument('-e', '--environment', help='Environment directory')

    args = parser.parse_args()

    environment_directory = args.environment
    if environment_directory is None:
        print("environment_directory is optional. For default is wazuh directory. Usage: python script.py -e <environment_directory>")

    SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
    ENGINE_SRC_DIR = os.path.join(SCRIPT_DIR, '../')
    WAZUH_DIR = os.path.realpath(os.path.join(SCRIPT_DIR, '../../../'))
    ENVIRONMENT_DIR = environment_directory or os.path.join(WAZUH_DIR, 'environment')
    ENVIRONMENT_DIR = str(Path(ENVIRONMENT_DIR).resolve())

    setup_engine(ENGINE_SRC_DIR, ENVIRONMENT_DIR)


if __name__ == "__main__":
    main()
