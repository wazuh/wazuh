#!/usr/bin/env python3

import os
import shutil
import argparse

def update_conf(script_dir, environment_dir):
    serv_conf_file_src = os.path.join(script_dir, 'configuration_files/general.conf')
    serv_conf_file_dest = os.path.join(environment_dir, 'engine', 'general.conf')

    # Copy the configuration file
    shutil.copy(serv_conf_file_src, serv_conf_file_dest)

    # Update the path in the configuration file
    with open(serv_conf_file_dest, 'r') as f:
        lines = f.readlines()

    # Update the file content
    with open(serv_conf_file_dest, 'w') as f:
        for line in lines:
            # Replace the desired string
            updated_line = line.replace('github_workspace', environment_dir)
            f.write(updated_line)

def create_empty_bk_conf(environment_dir):
    bk_path = environment_dir + "/engine/general-bk.conf"

    try:
        with open(bk_path, "w"):
            pass

    except Exception as e:
        print(f"Error to create the file: {e}")

def create_dummy_integration(environment_dir):
    wazuh_core_test = os.path.join(environment_dir, 'engine/wazuh-core-test')
    os.makedirs(os.path.join(wazuh_core_test, 'decoders'), exist_ok=True)
    os.makedirs(os.path.join(wazuh_core_test, 'filters'), exist_ok=True)

    with open(os.path.join(wazuh_core_test, 'decoders/test-message.yml'), 'w') as f:
        f.write("""\
name: decoder/test-message/0
check: $wazuh.queue == 49 # "1"
""")

    with open(os.path.join(wazuh_core_test, 'filters/allow-all.yml'), 'w') as f:
        f.write("name: filter/allow-all/0\n")

    with open(os.path.join(wazuh_core_test, 'manifest.yml'), 'w') as f:
        f.write("name: integration/wazuh-core-test/0\ndecoders:\n- decoder/test-message/0\n")

def create_other_dummy_integration(environment_dir):
    other_wazuh_core_test = os.path.join(environment_dir, 'engine/other-wazuh-core-test')
    os.makedirs(os.path.join(other_wazuh_core_test, 'decoders'), exist_ok=True)
    os.makedirs(os.path.join(other_wazuh_core_test, 'filters'), exist_ok=True)

    with open(os.path.join(other_wazuh_core_test, 'decoders/other-test-message.yml'), 'w') as f:
        f.write("""\
name: decoder/other-test-message/0
check: $wazuh.queue == 50 # "2"
""")

    with open(os.path.join(other_wazuh_core_test, 'filters/allow-all.yml'), 'w') as f:
        f.write("name: filter/allow-all/0\n")

    with open(os.path.join(other_wazuh_core_test, 'manifest.yml'), 'w') as f:
        f.write("name: integration/other-wazuh-core-test/0\ndecoders:\n- decoder/other-test-message/0\n")

def create_dummy_integration_with_parents(environment_dir):
    parent_wazuh_core_test = os.path.join(environment_dir, 'engine/parent-wazuh-core-test')
    os.makedirs(os.path.join(parent_wazuh_core_test, 'decoders'), exist_ok=True)
    os.makedirs(os.path.join(parent_wazuh_core_test, 'filters'), exist_ok=True)

    with open(os.path.join(parent_wazuh_core_test, 'decoders/parent-message.yml'), 'w') as f:
        f.write("""\
name: decoder/parent-message/0
check: $wazuh.queue == 49 # "1"
""")

    with open(os.path.join(parent_wazuh_core_test, 'decoders/test-message.yml'), 'w') as f:
        f.write("""\
name: decoder/test-message/0
parents:
  - decoder/parent-message/0
""")

def main():
    parser = argparse.ArgumentParser(description='Update configuration and create dummy integrations.')
    parser.add_argument('-e', '--environment', help='Environment directory')

    args = parser.parse_args()

    environment_directory = args.environment
    if environment_directory is None:
        print("environment_directory is optional. For default is wazuh directory. Usage: python script.py -e <environment_directory>")

    SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
    WAZUH_DIR = os.path.realpath(os.path.join(SCRIPT_DIR, '../../../'))
    ENVIRONMENT_DIR = environment_directory or os.path.join(WAZUH_DIR, 'environment')
    ENVIRONMENT_DIR = ENVIRONMENT_DIR.replace('//', '/')

    update_conf(SCRIPT_DIR, ENVIRONMENT_DIR)
    create_empty_bk_conf(ENVIRONMENT_DIR)
    create_dummy_integration(ENVIRONMENT_DIR)
    create_other_dummy_integration(ENVIRONMENT_DIR)
    create_dummy_integration_with_parents(ENVIRONMENT_DIR)

if __name__ == "__main__":
    main()
