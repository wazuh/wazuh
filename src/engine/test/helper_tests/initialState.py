#!/usr/bin/env python3

import argparse
import os
import shutil
import subprocess


def update_conf(script_dir, environment_dir):
    serv_conf_file_src = os.path.join(script_dir, "configuration_files/general.conf")
    serv_conf_file_dest = os.path.join(environment_dir, "engine", "general.conf")

    # Copy the configuration file
    shutil.copy(serv_conf_file_src, serv_conf_file_dest)

    # Update the path in the configuration file
    with open(serv_conf_file_dest, "r") as f:
        lines = f.readlines()

    # Update the file content
    with open(serv_conf_file_dest, "w") as f:
        for line in lines:
            # Replace the desired string
            updated_line = line.replace("github_workspace", environment_dir)
            f.write(updated_line)


def set_mmdb(engine_src_dir, environment_dir):
    mmdbAsn = os.path.join(engine_src_dir, 'test', 'helper_tests', 'testdb-asn.mmdb')
    shutil.copy(mmdbAsn, os.path.join(
        environment_dir, 'engine', 'etc', 'testdb-asn.mmdb'))

    mmdbCity = os.path.join(engine_src_dir, 'test', 'helper_tests', 'testdb-city.mmdb')
    shutil.copy(mmdbCity, os.path.join(
        environment_dir, 'engine', 'etc', 'testdb-city.mmdb'))


def main():
    parser = argparse.ArgumentParser(
        description="Update configuration and create dummy integrations."
    )
    parser.add_argument("-e", "--environment", help="Environment directory")

    args = parser.parse_args()

    environment_directory = args.environment
    if environment_directory is None:
        print(
            "environment_directory is optional. For default is wazuh directory. Usage: python script.py -e <environment_directory>"
        )

    SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
    WAZUH_DIR = os.path.realpath(os.path.join(SCRIPT_DIR, "../../../../"))
    ENGINE_SRC_DIR = os.path.join(WAZUH_DIR, 'src', 'engine')
    ENVIRONMENT_DIR = environment_directory or os.path.join(WAZUH_DIR, "environment")
    ENVIRONMENT_DIR = ENVIRONMENT_DIR.replace("//", "/")

    update_conf(SCRIPT_DIR, ENVIRONMENT_DIR)
    set_mmdb(ENGINE_SRC_DIR, ENVIRONMENT_DIR)

    os.environ['ENV_DIR'] = ENVIRONMENT_DIR
    os.environ['WAZUH_DIR'] = WAZUH_DIR
    os.environ['CONF_FILE'] = os.path.join(
        ENVIRONMENT_DIR, 'engine', 'general.conf')

    from handler_engine_instance import up_down
    up_down_engine = up_down.UpDownEngine()
    up_down_engine.send_start_command()

    # Add the mmdb to the engine
    print("Adding mmdb to the engine")
    command = f'{os.path.join(ENGINE_SRC_DIR, "build", "main")} geo --client_timeout 100000 --api_socket {os.path.join(ENVIRONMENT_DIR, "queue", "sockets", "engine-api")} add {os.path.join(ENVIRONMENT_DIR, "engine", "etc", "testdb-asn.mmdb")} asn'
    print(command)
    subprocess.run(command,
                   check=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    command = f'{os.path.join(ENGINE_SRC_DIR, "build", "main")} geo --client_timeout 100000 --api_socket {os.path.join(ENVIRONMENT_DIR, "queue", "sockets", "engine-api")} add {os.path.join(ENVIRONMENT_DIR, "engine", "etc", "testdb-city.mmdb")} city'
    print(command)
    subprocess.run(command,
                   check=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    up_down_engine.send_stop_command()


if __name__ == "__main__":
    main()
