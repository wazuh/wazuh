#!/usr/bin/env python3

import os
import shutil
import argparse
from pathlib import Path


def setup_engine(engine_dir, engine_src_dir, environment_dir):
    schemas = ["wazuh-logpar-types", "wazuh-asset", "wazuh-policy", "engine-schema"]

    for schema in schemas:
        schema_dir = os.path.join(engine_dir, 'store/schema', schema)
        os.makedirs(schema_dir, exist_ok=True)
        schema_json_path = os.path.join(engine_src_dir, 'ruleset/schemas', f'{schema}.json')
        shutil.copy(schema_json_path, os.path.join(schema_dir, '0'))

    dirs_to_create = [
        engine_dir,
        os.path.join(environment_dir, 'engine'),
        os.path.join(environment_dir, 'queue/sockets'),
        os.path.join(environment_dir, 'logs'),
        os.path.join(engine_dir, 'etc/kvdb')
    ]

    for directory in dirs_to_create:
        os.makedirs(directory, exist_ok=True)


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
    ENGINE_DIR = os.path.join(ENVIRONMENT_DIR, 'engine')

    setup_engine(ENGINE_DIR, ENGINE_SRC_DIR, ENVIRONMENT_DIR)


if __name__ == "__main__":
    main()
