#!/usr/bin/env python3
import os
import sys
import subprocess
import argparse

environment_directory = ""
input_file = ""
binary_path = ""
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
WAZUH_DIR = os.path.realpath(os.path.join(SCRIPT_DIR, '../../../..'))


def parse_arguments():
    global environment_directory
    global input_file

    parser = argparse.ArgumentParser(description='Run Behave tests for Wazuh.')
    parser.add_argument('-e', '--environment', help='Environment directory')
    parser.add_argument('-b', '--binary', help='Specify the path to the engine binary', default='')
    parser.add_argument('-i', '--input_file', help='Input file path')

    args = parser.parse_args()
    environment_directory = args.environment
    input_file = args.input_file
    binary_path = args.binary


def check_config_file():
    global environment_directory
    global WAZUH_DIR

    if not environment_directory:
        environment_directory = os.path.join(WAZUH_DIR, 'environment')

    serv_conf_file = os.path.join(environment_directory, 'engine', 'general.conf')

    if not os.path.isdir(environment_directory):
        print(f"Error: Environment directory {environment_directory} not found.")
        sys.exit(1)

    if not os.path.isfile(serv_conf_file):
        print(f"Error: Configuration file {serv_conf_file} not found.")
        sys.exit(1)

    return serv_conf_file


def run_test_health():
    global environment_directory
    global input_file

    engine_src_dir = os.path.join(WAZUH_DIR, "src", "engine")
    health_test_dir = os.path.join(engine_src_dir, "test", "health_test")

    if input_file is None:
        print("Warning: input_file is not specified. The health test will be run without it.")

    command = ["python3", os.path.join(health_test_dir, "health_test.py"), WAZUH_DIR, environment_directory]
    if input_file is not None:
        command.append(input_file)
    process = subprocess.run(command)
    return process.returncode


def main():
    global environment_directory
    global WAZUH_DIR
    global SCRIPT_DIR

    parse_arguments()
    serv_conf_file = check_config_file()

    engine_src_dir = os.path.join(WAZUH_DIR, 'src', 'engine')
    ENGINE_BIN = binary_path or os.path.join(engine_src_dir, 'build', 'main')

    os.environ['ENGINE_DIR'] = engine_src_dir
    os.environ['ENV_DIR'] = environment_directory
    os.environ['BINARY_DIR'] = ENGINE_BIN
    os.environ['CONF_FILE'] = serv_conf_file

    from handler_engine_instance import up_down
    up_down_engine = up_down.UpDownEngine()
    up_down_engine.send_start_command()

    exit_code = run_test_health()
    print(f"Exit code {exit_code}")

    up_down_engine.send_stop_command()

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
