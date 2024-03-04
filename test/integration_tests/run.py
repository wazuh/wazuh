import os
import sys
import subprocess
import argparse

environment_directory = ""

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
WAZUH_DIR = os.path.realpath(os.path.join(SCRIPT_DIR, '../../../..'))

def parse_arguments():
    global environment_directory

    parser = argparse.ArgumentParser(description='Run Behave tests for Wazuh.')
    parser.add_argument('-e', '--environment', help='Environment directory')

    args = parser.parse_args()
    environment_directory = args.environment

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

def run_behave_tests(integration_tests_dir):
    exit_code = 0

    for features_dir in [d for d, _, _ in os.walk(integration_tests_dir) if 'features' in d]:
        steps_dir = os.path.join(os.path.dirname(features_dir), 'steps')

        if os.path.isdir(steps_dir):
            print(f"Running Behave in {features_dir}")
            result = subprocess.run(['behave', features_dir, '--tags', '~exclude', '--format', 'progress2'])
            
            if result.returncode != 0:
                exit_code = 1

    print(f"Exit code {exit_code}")
    return exit_code

def main():
    global environment_directory
    global WAZUH_DIR
    global SCRIPT_DIR

    parse_arguments()
    serv_conf_file = check_config_file()

    engine_src_dir = os.path.join(WAZUH_DIR, 'src', 'engine')
    integration_tests_dir = os.path.join(engine_src_dir, 'test', 'integration_tests')

    os.environ['ENGINE_DIR'] = engine_src_dir
    os.environ['ENV_DIR'] = environment_directory
    os.environ['WAZUH_DIR'] = os.path.realpath(os.path.join(SCRIPT_DIR, '../../../..'))
    os.environ['CONF_FILE'] = serv_conf_file

    exit_code = run_behave_tests(integration_tests_dir)
    print(f"Exit code {exit_code}")

    sys.exit(exit_code)

if __name__ == "__main__":
    main()
