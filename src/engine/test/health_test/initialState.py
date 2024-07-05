#!/usr/bin/env python3
import os
import subprocess
import time
import argparse
import shutil
import sys
import yaml
from pathlib import Path

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
WAZUH_DIR = os.path.realpath(os.path.join(SCRIPT_DIR, "../../../.."))
ENGINE_BIN = ""


def parse_args():
    parser = argparse.ArgumentParser(description='Script description.')
    parser.add_argument('-e', '--environment',
                        help='Specify environment directory', default='')
    parser.add_argument(
        '-b', '--binary', help='Specify the path to the engine binary', default='')
    return parser.parse_args()


def update_conf():
    serv_conf_file = os.path.join(
        ENGINE_SRC_DIR, 'test', 'health_test', 'configuration_files', 'general.conf')
    shutil.copy(serv_conf_file, os.path.join(ENVIRONMENT_DIR, 'engine'))
    with open(os.path.join(ENVIRONMENT_DIR, 'engine', 'general.conf'), 'r') as file:
        filedata = file.read()
    filedata = filedata.replace('github_workspace', ENVIRONMENT_DIR)
    with open(os.path.join(ENVIRONMENT_DIR, 'engine', 'general.conf'), 'w') as file:
        file.write(filedata)

    return serv_conf_file


def set_mmdb():
    mmdbAsn = os.path.join(ENGINE_SRC_DIR, 'test',
                           'health_test', 'testdb-asn.mmdb')
    shutil.copy(mmdbAsn, os.path.join(
        ENVIRONMENT_DIR, 'engine', 'etc', 'testdb-asn.mmdb'))

    mmdbCity = os.path.join(ENGINE_SRC_DIR, 'test',
                            'health_test', 'testdb-city.mmdb')
    shutil.copy(mmdbCity, os.path.join(
        ENVIRONMENT_DIR, 'engine', 'etc', 'testdb-city.mmdb'))


def load_integrations():
    subprocess.run(
        f'{ENGINE_BIN} catalog --api_socket {os.path.join(ENVIRONMENT_DIR, "queue", "sockets", "engine-api")} -n system create filter < {os.path.join(ENGINE_SRC_DIR, "ruleset", "filters", "allow-all.yml")}',
        check=True, shell=True)

    wazuh_core_dir = f"{ENGINE_SRC_DIR}/ruleset/wazuh-core"
    destination_dir = f"{ENVIRONMENT_DIR}/engine/wazuh-core"
    manifest = f"{ENVIRONMENT_DIR}/engine/wazuh-core/manifest.yml"

    # Check if the destination directory exists
    if not os.path.exists(destination_dir):
        shutil.copytree(wazuh_core_dir, destination_dir)
    else:
        print(
            f"The destination directory {destination_dir} already exists. Skipping the copy operation.")

    # Delete stage outputs of manifest
    if os.path.isfile(manifest):
        with open(manifest, 'r') as file:
            manifest_data = yaml.safe_load(file)

        if 'outputs' in manifest_data:
            del manifest_data['outputs']

            # Save updated content in manifest.yml
            with open(manifest, 'w') as file:
                yaml.dump(manifest_data, file, default_flow_style=False)

            print(
                f"The 'outputs' node has been removed from the {manifest} file.")
        else:
            print(f"The 'outputs' node does not exist in the {manifest} file.")
    else:
        print(f"The file {manifest} does not exist.")

    os.chdir(os.path.join(ENVIRONMENT_DIR, 'engine'))
    subprocess.run(["engine-integration", "add", "--api-sock",
                   f"{ENVIRONMENT_DIR}/queue/sockets/engine-api", "-n", "system", f"wazuh-core/"])

    os.chdir(os.path.join(ENGINE_SRC_DIR, 'ruleset'))
    integrations = ["syslog", "system", "windows", "apache-http",
                    "suricata", "wazuh-dashboard", "wazuh-indexer"]
    for integration in integrations:
        subprocess.run(["engine-integration", "add", "--api-sock",
                       f"{ENVIRONMENT_DIR}/queue/sockets/engine-api", "-n", "wazuh", f"integrations/{integration}/"])


def load_policies():
    subprocess.run(
        f'{ENGINE_BIN} policy --client_timeout 100000 --api_socket {os.path.join(ENVIRONMENT_DIR, "queue", "sockets", "engine-api")} add -p policy/wazuh/0 -f',
        check=True, shell=True)

    subprocess.run(
        f'{ENGINE_BIN} policy --client_timeout 100000 --api_socket {os.path.join(ENVIRONMENT_DIR, "queue", "sockets", "engine-api")} parent-set decoder/integrations/0',
        check=True, shell=True)

    subprocess.run(
        f'{ENGINE_BIN} policy --client_timeout 100000 --api_socket {os.path.join(ENVIRONMENT_DIR, "queue", "sockets", "engine-api")} parent-set -n wazuh decoder/integrations/0',
        check=True, shell=True)

    subprocess.run(
        f'{ENGINE_BIN} policy --client_timeout 100000 --api_socket {os.path.join(ENVIRONMENT_DIR, "queue", "sockets", "engine-api")} parent-set -n wazuh rule/enrichment/0',
        check=True, shell=True)

    subprocess.run(
        f'{ENGINE_BIN} policy --client_timeout 100000 --api_socket {os.path.join(ENVIRONMENT_DIR, "queue", "sockets", "engine-api")} asset-add -n system integration/wazuh-core/0',
        check=True, shell=True)

    assets = ['syslog/0', 'system/0', 'windows/0', 'apache-http/0',
              'suricata/0', 'wazuh-dashboard/0', 'wazuh-indexer/0']
    for asset in assets:
        subprocess.run(
            f'{ENGINE_BIN} policy --client_timeout 100000 --api_socket {os.path.join(ENVIRONMENT_DIR, "queue", "sockets", "engine-api")} asset-add -n wazuh integration/{asset}',
            check=True, shell=True)

    subprocess.run(
        f'{ENGINE_BIN} router --client_timeout 100000 --api_socket {os.path.join(ENVIRONMENT_DIR, "queue", "sockets", "engine-api")} add default filter/allow-all/0 255 policy/wazuh/0',
        check=True, shell=True)


def main():
    global ENGINE_SRC_DIR
    global ENVIRONMENT_DIR
    global ENGINE_BIN

    args = parse_args()

    if not args.environment:
        print(
            "environment is optional. For default is wazuh directory. Usage: {} -e <environment>".format(sys.argv[0]))

    ENGINE_SRC_DIR = os.path.join(WAZUH_DIR, 'src', 'engine')
    ENVIRONMENT_DIR = args.environment or WAZUH_DIR
    ENVIRONMENT_DIR = str(Path(ENVIRONMENT_DIR).resolve())
    ENGINE_BIN = args.binary or os.path.join(ENGINE_SRC_DIR, 'build', 'main')
    update_conf()
    set_mmdb()

    os.environ['ENV_DIR'] = ENVIRONMENT_DIR
    os.environ['WAZUH_DIR'] = WAZUH_DIR
    os.environ['CONF_FILE'] = os.path.join(ENVIRONMENT_DIR, 'engine', 'general.conf')
    os.environ['BINARY_DIR'] = ENGINE_BIN

    from handler_engine_instance import up_down
    up_down_engine = up_down.UpDownEngine()
    up_down_engine.send_start_command()

    # Add the mmdb to the engine
    print("Adding mmdb to the engine")
    command = f'{ENGINE_BIN} geo --client_timeout 100000 --api_socket {os.path.join(ENVIRONMENT_DIR, "queue", "sockets", "engine-api")} add {os.path.join(ENVIRONMENT_DIR, "engine", "etc", "testdb-asn.mmdb")} asn'
    print(command)
    subprocess.run(command,
                   check=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    command = f'{ENGINE_BIN} geo --client_timeout 100000 --api_socket {os.path.join(ENVIRONMENT_DIR, "queue", "sockets", "engine-api")} add {os.path.join(ENVIRONMENT_DIR, "engine", "etc", "testdb-city.mmdb")} city'
    print(command)
    subprocess.run(command,
                   check=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    load_integrations()
    load_policies()

    up_down_engine.send_stop_command()


if __name__ == "__main__":
    main()
