import sys
import subprocess
import json
import os
import re

def run_command(command):
    try:
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        return None

def execute_integration_test(github_working_dir, os_path, input_file_path):
    main_command = "cat"
    engine_test_conf = f"{github_working_dir}/environment/engine/etc/engine-test.conf"
    # Execute the command and get the output
    output = subprocess.check_output(f"{main_command} {input_file_path} | engine-test -c {engine_test_conf} run {os.path.basename(os_path)} -p policy/wazuh/1 --api-socket {github_working_dir}/environment/queue/sockets/engine-api -n wazuh system -j", shell=True, stderr=subprocess.STDOUT)

    # Split the output into individual JSON strings
    output_str = output.decode('utf-8')
    json_strings = output_str.strip().split('\n')

    parsed_results = []

    for json_string in json_strings:
        try:
            parsed_json = json.loads(json_string)
            parsed_results.append(parsed_json)
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON: {e}")

    return parsed_results

def compare_results(parsed_results, expected_json, input_file_name, mismatches):
    for event_json in parsed_results:
        if 'TestSessionID' in event_json:
            del event_json['TestSessionID']
        try:
            if event_json not in expected_json:
                mismatches.append(input_file_name)
                return
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON event: {e}")

def process_integration_tests(github_working_dir, allowed_integrations):
    integrations_directory = os.path.join(github_working_dir, "src/engine/ruleset/integrations")

    mismatches = []

    for os_dir in os.listdir(integrations_directory):
        os_path = os.path.join(integrations_directory, os_dir)

        if os.path.isdir(os_path) and os.path.basename(os_path) in allowed_integrations:
            test_directory = os.path.join(os_path, "test")
            if os.path.isdir(test_directory):
                for root, dirs, files in os.walk(test_directory):
                    for input_file in files:
                        match = re.search(r'_input\..*$', input_file)
                        if match:
                            print(input_file)
                            input_file_path = os.path.join(root, input_file)
                            new_extension = "_expected.json"
                            expected_file = re.sub(r'_input\..*$', new_extension, input_file)
                            expected_file_path = os.path.join(root, expected_file)

                            if os.path.isfile(expected_file_path):
                                expected_json = {}
                                with open(expected_file_path, 'r') as file:
                                    expected_json = json.load(file)

                                parsed_results = execute_integration_test(github_working_dir, os_path, input_file_path)
                                compare_results(parsed_results, expected_json, input_file, mismatches)
                                print(expected_file)
                            else:
                                print(f"Expected file '{expected_file}' corresponding to '{input_file}' in '{root}' was not found.")

    if mismatches:
        print("\nFiles with no expected result:")
        for mismatch in mismatches:
            print(mismatch)

    return 0 if not mismatches else 1

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(1)

    github_working_dir = sys.argv[1]
    # TODO: Add apache-access/error
    allowed_integrations = ["windows", "syslog", "suricata", "system"]

    error_code = process_integration_tests(github_working_dir, allowed_integrations)

    print("Process completed.")
    sys.exit(error_code)  # Set the error code at the end of the script
