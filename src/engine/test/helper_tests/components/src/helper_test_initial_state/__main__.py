#!/usr/bin/env python3

import argparse
import os
import shutil
import subprocess
from pathlib import Path


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Update configuration and create dummy integrations."
    )
    parser.add_argument("-e", "--environment", required=True, help="Environment directory")
    parser.add_argument("-b", "--binary", help="Path to the binary file")
    parser.add_argument("-w", "--wazuh-dir", required=True, help="Path to the Wazuh installation directory")
    return parser.parse_args()


def update_conf(engine_src_dir: Path, environment_dir: Path):
    serv_conf_file_src = engine_src_dir / 'test' / 'helper_tests' / 'configuration_files' / 'general.conf'
    serv_conf_file_dest = environment_dir / 'engine' / 'general.conf'

    shutil.copy(serv_conf_file_src, serv_conf_file_dest)

    with open(serv_conf_file_dest, "r") as f:
        lines = f.readlines()

    with open(serv_conf_file_dest, "w") as f:
        for line in lines:
            updated_line = line.replace("github_workspace", environment_dir.as_posix())
            f.write(updated_line)


def set_mmdb(engine_src_dir: Path, environment_dir: Path):
    mmdb_asn_src = engine_src_dir / 'test' / 'helper_tests' / 'testdb-asn.mmdb'
    mmdb_asn_dest = environment_dir / 'engine' / 'etc' / 'testdb-asn.mmdb'

    shutil.copy(mmdb_asn_src, mmdb_asn_dest)

    mmdb_city_src = engine_src_dir / 'test' / 'helper_tests' / 'testdb-city.mmdb'
    mmdb_city_dest = environment_dir / 'engine' / 'etc' / 'testdb-city.mmdb'

    shutil.copy(mmdb_city_src, mmdb_city_dest)


def set_kvdb(environment_dir: Path):
    kvdb_path = environment_dir / "engine" / "etc" / "kvdb" / "test.json"

    os.makedirs(os.path.dirname(kvdb_path), exist_ok=True)
    with open(kvdb_path, 'w') as file:
        file.write('{"test": {"key": "value"}, "test_bitmask": {"33": "some_data"}}')


def main():
    args = parse_arguments()

    WAZUH_DIR = Path(args.wazuh_dir).resolve()
    ENGINE_SRC_DIR = WAZUH_DIR / 'src' / 'engine'
    ENVIRONMENT_DIR = Path(args.environment).resolve()

    update_conf(ENGINE_SRC_DIR, ENVIRONMENT_DIR)
    set_mmdb(ENGINE_SRC_DIR, ENVIRONMENT_DIR)
    set_kvdb(ENVIRONMENT_DIR)

    os.environ['ENV_DIR'] = ENVIRONMENT_DIR.as_posix()
    os.environ['WAZUH_DIR'] = WAZUH_DIR.as_posix()
    os.environ['CONF_FILE'] = str(ENVIRONMENT_DIR / 'engine' / 'general.conf')

    # TODO: If a binary path is added per parameter, it will be out of sync with the binary used by up_down_engine
    from handler_engine_instance import up_down
    up_down_engine = up_down.UpDownEngine()
    up_down_engine.send_start_command()

    socket_path = str(ENVIRONMENT_DIR / "queue" / "sockets" / "engine-api")
    asn_path = str(ENVIRONMENT_DIR / "engine" / "etc" / "testdb-asn.mmdb")
    city_path = str(ENVIRONMENT_DIR / "engine" / "etc" / "testdb-city.mmdb")
    binary_path = args.binary or str(ENGINE_SRC_DIR / "build" / "main")

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
