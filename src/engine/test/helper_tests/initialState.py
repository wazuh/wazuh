#!/usr/bin/env python3

import argparse
import os
import shutil
import subprocess
from pathlib import Path

LEVELS_UP = 3


def update_conf(script_dir: Path, environment_dir: Path):
    # Define source and destination paths using pathlib
    serv_conf_file_src = script_dir / "configuration_files" / "general.conf"
    serv_conf_file_dest = environment_dir / "engine" / "general.conf"

    # Copy the configuration file
    shutil.copy(serv_conf_file_src, serv_conf_file_dest)

    # Read and update the path in the configuration file
    with open(serv_conf_file_dest, "r") as f:
        lines = f.readlines()

    # Update the file content
    with open(serv_conf_file_dest, "w") as f:
        for line in lines:
            # Replace the desired string
            updated_line = line.replace("github_workspace", environment_dir.as_posix())
            f.write(updated_line)


def set_mmdb(engine_src_dir: Path, environment_dir: Path):
    # Define the source and destination paths using pathlib
    mmdb_asn_src = engine_src_dir / 'test' / 'helper_tests' / 'testdb-asn.mmdb'
    mmdb_asn_dest = environment_dir / 'engine' / 'etc' / 'testdb-asn.mmdb'

    # Copy the ASN database file
    shutil.copy(mmdb_asn_src, mmdb_asn_dest)

    mmdb_city_src = engine_src_dir / 'test' / 'helper_tests' / 'testdb-city.mmdb'
    mmdb_city_dest = environment_dir / 'engine' / 'etc' / 'testdb-city.mmdb'

    # Copy the City database file
    shutil.copy(mmdb_city_src, mmdb_city_dest)


def set_kvdb(environment_dir: Path):
    kvdb_path = environment_dir / "engine" / "etc" / "kvdb" / "test.json"

    os.makedirs(os.path.dirname(kvdb_path), exist_ok=True)
    with open(kvdb_path, 'w') as file:
        file.write('{"key": "value"}')


def main():
    parser = argparse.ArgumentParser(
        description="Update configuration and create dummy integrations."
    )
    parser.add_argument("-e", "--environment", help="Environment directory")

    args = parser.parse_args()

    environment_directory = args.environment
    if environment_directory is None:
        print("environment_directory is optional. For default is wazuh directory. Usage: python script.py", end=' ')
        print("-e <environment_directory>")

    SCRIPT_DIR = Path(__file__).resolve().parent
    WAZUH_DIR = SCRIPT_DIR.parents[LEVELS_UP]
    ENGINE_SRC_DIR = WAZUH_DIR / 'src' / 'engine'
    ENVIRONMENT_DIR = Path(environment_directory or (WAZUH_DIR / "environment"))

    update_conf(SCRIPT_DIR, ENVIRONMENT_DIR)
    set_mmdb(ENGINE_SRC_DIR, ENVIRONMENT_DIR)
    set_kvdb(ENVIRONMENT_DIR)

    os.environ['ENV_DIR'] = ENVIRONMENT_DIR.as_posix()
    os.environ['WAZUH_DIR'] = WAZUH_DIR.as_posix()
    os.environ['CONF_FILE'] = str(ENVIRONMENT_DIR / 'engine' / 'general.conf')

    from handler_engine_instance import up_down
    up_down_engine = up_down.UpDownEngine()
    up_down_engine.send_start_command()

    # Add the mmdb to the engine
    socket_path = str(ENVIRONMENT_DIR / "queue" / "sockets" / "engine-api")
    asn_path = str(ENVIRONMENT_DIR / "engine" / "etc" / "testdb-asn.mmdb")
    city_path = str(ENVIRONMENT_DIR / "engine" / "etc" / "testdb-city.mmdb")
    binary_path = str(ENGINE_SRC_DIR / "build" / "main")

    print("Adding mmdb to the engine")
    command = f'{binary_path} geo --client_timeout 100000 --api_socket {socket_path} add {asn_path} asn'
    print(command)
    subprocess.run(command,
                   check=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    command = f'{binary_path} geo --client_timeout 100000 --api_socket {socket_path} add {city_path} city'
    print(command)
    subprocess.run(command,
                   check=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    up_down_engine.send_stop_command()


if __name__ == "__main__":
    main()
