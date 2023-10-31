import sys
import subprocess
import json
import os

def run_command(command):
    try:
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        return None

def check_or_create_session(github_working_dir, session_name):
    session_get = f"cd {github_working_dir}/src/engine/build && ./main test --api_socket {github_working_dir}/environment/queue/sockets/engine-api session get {session_name}"
    result = run_command(session_get)
    print(result)

    if result.returncode != 0:
        print(f"Session '{session_name}' does not exist. Creating it...")
        session_post = f"cd {github_working_dir}/src/engine/build && ./main test --client_timeout 100000 --api_socket {github_working_dir}/environment/queue/sockets/engine-api session create {session_name}"
        result = run_command(session_post)
        print(result)

        if result.returncode != 0:
            sys.exit(1)
        print(f"Session '{session_name}' created successfully.")
    else:
        print(f"Session '{session_name}' already exists.")

def execute_integration_test(github_working_dir, os_path, input_file_path):
    main_command = "cat"
    # Ejecutar el comando y obtener la salida
    output = subprocess.check_output(f"{main_command} {input_file_path} | engine-test run {os.path.basename(os_path)} --api-socket {github_working_dir}/environment/queue/sockets/engine-api -n wazuh system -j", shell=True, stderr=subprocess.STDOUT)

    # Dividir la salida en cadenas JSON individuales
    output_str = output.decode('utf-8')
    json_strings = output_str.strip().split('\n')

    parsed_results = []

    for json_string in json_strings:
        try:
            parsed_json = json.loads(json_string)
            parsed_results.append(parsed_json)
        except json.JSONDecodeError as e:
            print(f"Error al parsear JSON: {e}")

    return parsed_results

def compare_results(parsed_results, expected_json, input_file_name):
    for event_json in parsed_results:
        if 'TestSessionID' in event_json:
            del event_json['TestSessionID']
        try:
            if event_json not in expected_json:
                print(f"JSON events in '{input_file_name}' do not match the 'expected.json' file.")
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON event: {e}")

def process_integration_tests(github_working_dir, allowed_integrations, session_name):
    integrations_directory = os.path.join(github_working_dir, "src/engine/ruleset/integrations")

    for os_dir in os.listdir(integrations_directory):
        os_path = os.path.join(integrations_directory, os_dir)

        if os.path.isdir(os_path) and os.path.basename(os_path) in allowed_integrations:
            test_directory = os.path.join(os_path, "test")

            if os.path.isdir(test_directory):
                for input_file in os.listdir(test_directory):
                    if input_file.endswith("input.xml"):
                        input_file_path = os.path.join(test_directory, input_file)
                        expected_file = input_file.replace("input.xml", "expected.json")
                        expected_file_path = os.path.join(test_directory, expected_file)

                        if os.path.isfile(expected_file_path):
                            expected_json = {}
                            with open(expected_file_path, 'r') as file:
                                expected_json = json.load(file)

                            parsed_results = execute_integration_test(github_working_dir, os_path, input_file_path)
                            compare_results(parsed_results, expected_json, input_file)
                        else:
                            print(f"Expected file 'expected.json' corresponding to '{input_file}' in '{test_directory}' was not found.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(1)

    github_working_dir = sys.argv[1]
    allowed_integrations = ["windows"]
    session_name = "HealthTest"

    check_or_create_session(github_working_dir, session_name)
    process_integration_tests(github_working_dir, allowed_integrations, session_name)

print("Process completed.")
