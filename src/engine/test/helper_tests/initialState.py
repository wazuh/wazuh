#!/usr/bin/env python3

import argparse
import os
import shutil


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
    WAZUH_DIR = os.path.realpath(os.path.join(SCRIPT_DIR, "../../../"))
    ENVIRONMENT_DIR = environment_directory or os.path.join(WAZUH_DIR, "environment")
    ENVIRONMENT_DIR = ENVIRONMENT_DIR.replace("//", "/")

    update_conf(SCRIPT_DIR, ENVIRONMENT_DIR)


if __name__ == "__main__":
    main()
