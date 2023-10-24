import sys
import subprocess
import json
import os

def run_command(command):
    try:
        result = subprocess.run(
            command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
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
        session_post = f"cd {github_working_dir}/src/engine/build && ./main test --api_socket {github_working_dir}/environment/queue/sockets/engine-api session create {session_name}"
        result = run_command(session_post)
        print(result)
        if result.returncode != 0:
            sys.exit(1)
        print(f"Session '{session_name}' created successfully.")
    else:
        print(f"Session '{session_name}' already exists.")

def process_integration_tests(github_working_dir, allowed_integrations, session_name):
    main_command = "cat"
    integrations_directory = os.path.join(github_working_dir, "src/engine/ruleset/integrations")

    for os_dir in os.listdir(integrations_directory):
        os_path = os.path.join(integrations_directory, os_dir)

        if os.path.isdir(os_path) and os.path.basename(os_path) in allowed_integrations:
            test_directory = os.path.join(os_path, "test")

            if os.path.isdir(test_directory):
                for input_file in os.listdir(test_directory):
                    if input_file.endswith("input.txt"):
                        input_file_path = os.path.join(test_directory, input_file)
                        expected_file = input_file.replace("input.txt", "expected.json")
                        expected_file_path = os.path.join(test_directory, expected_file)

                        if os.path.isfile(expected_file_path):
                            output = subprocess.check_output(f"{main_command} {input_file_path} | engine-test run {os.path.basename(os_path)} --api-socket {github_working_dir}/environment/queue/sockets/engine-api -n wazuh system -j", shell=True, stderr=subprocess.STDOUT)
                            output = output.decode('utf-8').strip().split("\n")
                            first_brace_position = output.find('{')
                            if first_brace_position != -1:
                                output = output[first_brace_position:]

                            event_json = output.decode('utf-8').strip().split("\n")

                            with open(expected_file_path, 'r') as file:
                                expected_json = json.load(file)

                            for event_json in json_events:
                                try:
                                    event = json.loads(event_json)
                                    if event not in expected_json:
                                        print("JSON events do not match the 'expected.json' file.")
                                except json.JSONDecodeError as e:
                                    print(f"Error decoding JSON event: {e}")
                        else:
                            print(f"Expected file 'expected.json' corresponding to '{input_file}' in '{test_directory}' was not found.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(1)

    github_working_dir = sys.argv[1]
    allowed_integrations = ["windows", "syslog", "suricata", "apache-http", "system"]
    session_name = "HealthTest"

    #check_or_create_session(github_working_dir, session_name)
    process_integration_tests(github_working_dir, allowed_integrations, session_name)

print("Process completed.")
