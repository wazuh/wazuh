#!/usr/bin/env python3

import argparse
import os
import shutil
import subprocess
from pathlib import Path


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Update configuration, create kvdbs and mmdbs"
    )
    parser.add_argument("-e", "--environment", required=True, help="Environment directory")
    parser.add_argument("-b", "--binary", required=True, help="Path to the binary file")
    parser.add_argument("--mmdb", required=True, help="Directory path where the as and geo databases are located")
    parser.add_argument("--conf", required=True, help="File path where the engine configuration file is")
    return parser.parse_args()


def update_conf(conf_dir: Path, environment_dir: Path):
    serv_conf_file_dest = environment_dir / 'engine' / 'general.conf'

    shutil.copy(conf_dir, serv_conf_file_dest)

    with open(serv_conf_file_dest, "r") as f:
        lines = f.readlines()

    with open(serv_conf_file_dest, "w") as f:
        for line in lines:
            updated_line = line.replace("github_workspace", environment_dir.as_posix())
            f.write(updated_line)


def set_mmdb(mmdb_dir: Path, environment_dir: Path):
    mmdb_asn_src = mmdb_dir / 'testdb-asn.mmdb'
    mmdb_asn_dest = environment_dir / 'engine' / 'etc' / 'testdb-asn.mmdb'

    shutil.copy(mmdb_asn_src, mmdb_asn_dest)

    mmdb_city_src = mmdb_dir / 'testdb-city.mmdb'
    mmdb_city_dest = environment_dir / 'engine' / 'etc' / 'testdb-city.mmdb'

    shutil.copy(mmdb_city_src, mmdb_city_dest)


def set_kvdb(environment_dir: Path):
    kvdb_path = environment_dir / "engine" / "etc" / "kvdb" / "test.json"

    os.makedirs(os.path.dirname(kvdb_path), exist_ok=True)
    with open(kvdb_path, 'w') as file:
        file.write('{"test": {"key": "value"}, "test_bitmask": {"33": "some_data"}}')


def main():
    args = parse_arguments()

    ENVIRONMENT_DIR = Path(args.environment).resolve()
    CONF_DIR = Path(args.conf).resolve()
    MMDB_DIR = Path(args.mmdb).resolve()
    BINARY_DIR = Path(args.binary).resolve()

    update_conf(CONF_DIR, ENVIRONMENT_DIR)
    set_mmdb(MMDB_DIR, ENVIRONMENT_DIR)
    set_kvdb(ENVIRONMENT_DIR)

    os.environ['ENV_DIR'] = ENVIRONMENT_DIR.as_posix()
    os.environ['BINARY_DIR'] = BINARY_DIR.as_posix()
    os.environ['CONF_FILE'] = (ENVIRONMENT_DIR / 'engine' / 'general.conf').as_posix()

    # TODO: If a binary path is added per parameter, it will be out of sync with the binary used by up_down_engine
    from handler_engine_instance import up_down
    up_down_engine = up_down.UpDownEngine()
    up_down_engine.send_start_command()

    socket_path = str(ENVIRONMENT_DIR / "queue" / "sockets" / "engine-api")
    asn_path = str(ENVIRONMENT_DIR / "engine" / "etc" / "testdb-asn.mmdb")
    city_path = str(ENVIRONMENT_DIR / "engine" / "etc" / "testdb-city.mmdb")

    print("Adding mmdb to the engine")
    command = f'{BINARY_DIR.as_posix()} geo --client_timeout 100000 --api_socket {socket_path} add {asn_path} asn'
    print(command)
    subprocess.run(command,
                   check=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    command = f'{BINARY_DIR.as_posix()} geo --client_timeout 100000 --api_socket {socket_path} add {city_path} city'
    print(command)
    subprocess.run(command,
                   check=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    up_down_engine.send_stop_command()


if __name__ == "__main__":
    main()
