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

def execute_integration_test(github_working_dir, env_dir, os_path, input_file_path, containing_folder, isOneExecution = False):
    main_command = "cat"
    integration = ""

    if not isOneExecution:
        integration = os.path.basename(os_path)
    else:
        integration = os.path.basename(os.path.dirname(os_path))
        if integration == "test":
            integration = os.path.basename(os.path.dirname(os.path.dirname(os_path)))

    engine_test_conf = f"{github_working_dir}/src/engine/ruleset/integrations/{integration}/test/engine-test.conf"

    if containing_folder != "test":
        integration += "-" + containing_folder

    # Execute the command and get the output
    try:
        # print the command
        print(f"\n{main_command} {input_file_path} | engine-test -c {engine_test_conf} run {integration} --api-socket {env_dir}/queue/sockets/engine-api -j")
        output = subprocess.check_output(f"{main_command} {input_file_path} | engine-test -c {engine_test_conf} run {integration} --api-socket {env_dir}/queue/sockets/engine-api -j", shell=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        print("Subprocess Error:")
        print(f"Standard  Output: {e.output.decode()}")
        sys.exit(1)

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

def replace_single_quotes(json_obj):
    if isinstance(json_obj, dict):
        new_dict = {}
        for key, value in json_obj.items():
            if isinstance(key, str):
                new_key = key.replace("'", "\"")
                new_dict[new_key] = replace_single_quotes(value)
            else:
                new_dict[key] = replace_single_quotes(value)
        return new_dict
    elif isinstance(json_obj, list):
        return [replace_single_quotes(item) for item in json_obj]
    else:
        return json_obj

def compare_results(parsed_results, expected_json, input_file_name, mismatches):
    if len(parsed_results) != len(expected_json):
        mismatches.append((input_file_name, 0))
        return

    for i, event_json in enumerate(parsed_results):
        if 'TestSessionID' in event_json:
            del event_json['TestSessionID']
        try:
            if event_json != expected_json[i]:
                print(json.dumps(replace_single_quotes(event_json)))
                mismatches.append((input_file_name, i))
                continue
        except json.JSONDecodeError as e:
            print(f"Error al decodificar el evento JSON: {e}")

def process_integration_tests(github_working_dir, env_dir, input_file_path=None):
    integrations_directory = os.path.join(github_working_dir, "src/engine/ruleset/integrations")

    mismatches = []

    if input_file_path:  # If an input file is given as an argument
        os_path = os.path.dirname(input_file_path)
        containing_folder = os.path.basename(os_path)

        expected_file = re.sub(r'_input\..*$', "_expected.json", os.path.basename(input_file_path))
        expected_file_path = os.path.join(os_path, expected_file)

        if os.path.isfile(expected_file_path):
            expected_json = {}
            with open(expected_file_path, 'r') as file:
                expected_json = json.load(file)

            parsed_results = execute_integration_test(github_working_dir, env_dir, os_path, input_file_path, containing_folder, True)
            compare_results(parsed_results, expected_json, input_file_path, mismatches)
            print(expected_file_path)
        else:
            print(f"Expected file '{expected_file}' corresponding to '{os.path.basename(input_file_path)}' in '{os_path}' was not found.")
            return 1
    else:  # Original behavior of looping through folders
        for os_dir in os.listdir(integrations_directory):
            os_path = os.path.join(integrations_directory, os_dir)

            test_directory = os.path.join(os_path, "test")
            if os.path.isdir(test_directory):
                for root, dirs, files in os.walk(test_directory):
                    for input_file in files:
                        match = re.search(r'_input\..*$', input_file)
                        if match:
                            containing_folder = os.path.basename(root)

                            input_file_path = os.path.join(root, input_file)
                            new_extension = "_expected.json"
                            expected_file = re.sub(r'_input\..*$', new_extension, input_file)
                            expected_file_path = os.path.join(root, expected_file)

                            if os.path.isfile(expected_file_path):
                                expected_json = {}
                                with open(expected_file_path, 'r') as file:
                                    expected_json = json.load(file)

                                parsed_results = execute_integration_test(github_working_dir, env_dir, os_path, input_file_path, containing_folder)
                                compare_results(parsed_results, expected_json, input_file, mismatches)
                                print(expected_file)
                            else:
                                print(f"Expected file '{expected_file}' corresponding to '{input_file}' in '{root}' was not found.")
                                return 1

    if mismatches:
        print("\nFiles with no expected result:")
        for mismatch in mismatches:
            print(f"File: {mismatch[0]}, Failed Index: {mismatch[1]}")

    return 0 if not mismatches else 1

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python script.py <github_working_dir> [env_dir] [input_file]")
        sys.exit(1)

    github_working_dir = sys.argv[1]
    env_dir = sys.argv[2]
    input_file_path = sys.argv[3] if len(sys.argv) == 4 else None

    error_code = process_integration_tests(github_working_dir, env_dir, input_file_path)

    print("Process completed.")

    sys.exit(error_code)
