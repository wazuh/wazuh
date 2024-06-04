#!/usr/bin/env python3

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional, Tuple

import yaml
from api_communication.client import APIClient
from api_communication.proto import catalog_pb2 as api_catalog
from api_communication.proto import engine_pb2 as api_engine
from api_communication.proto import policy_pb2 as api_policy
from api_communication.proto import tester_pb2 as api_tester
from google.protobuf.json_format import MessageToJson, ParseDict

environment_directory = ""
input_file = ""
only_failure = None
only_success = None


SCRIPT_DIR = Path(__file__).resolve().parent
WAZUH_DIR = SCRIPT_DIR.joinpath("../../../..").resolve()
POLICY_NAME = "policy/wazuh/0"
ASSET_NAME = "decoder/test/0"
SESSION_NAME = "test"
NAMESPACE = "user"


def parse_arguments():
    """
    Parses command-line arguments for configuring the environment and selecting test cases to display.

    The supported command-line arguments are:
        -e, --environment: Environment directory.
        -i, --input_file: Absolute or relative path to the helper function description file.
        --failure_cases: Show only the test cases that failed.
        --success_cases: Show only the test cases that succeeded.

    This function does not return any value.
    """
    global environment_directory
    global input_file
    global only_success
    global only_failure

    parser = argparse.ArgumentParser(
        description="Run Helpers test for Engine.")
    parser.add_argument("-e", "--environment", help="Environment directory")
    parser.add_argument(
        "-i",
        "--input_file",
        help="Absolute or relative path where the description of the helper function is located",
    )
    parser.add_argument(
        "--failure_cases",
        help="Shows only the failure test cases that occurred",
        action="store_true",
    )
    parser.add_argument(
        "--success_cases",
        help="Shows only the success test cases that occurred",
        action="store_true",
    )

    args = parser.parse_args()
    input_file = args.input_file
    only_success = args.success_cases
    only_failure = args.failure_cases
    environment_directory = args.environment


def check_config_file():
    """
    Checks the existence and validity of the environment directory and configuration file.

    If the environment directory is not specified, it defaults to a subdirectory within WAZUH_DIR.
    It checks for the existence of the environment directory and a specific configuration file.

    Returns:
        str: The path to the configuration file if all checks pass.

    Exits:
        The program exits with an error message if the environment directory or configuration file is not found.
    """
    global environment_directory
    global WAZUH_DIR

    if not environment_directory:
        environment_directory = os.path.join(WAZUH_DIR, "environment")

    serv_conf_file = os.path.join(
        environment_directory, "engine", "general.conf")

    if not os.path.isdir(environment_directory):
        print(
            f"Error: Environment directory {environment_directory} not found.")
        sys.exit(1)

    if not os.path.isfile(serv_conf_file):
        print(f"Error: Configuration file {serv_conf_file} not found.")
        sys.exit(1)

    return serv_conf_file


def load_yaml(file_path: str):
    """
    Loads data from a YAML file.

    Args:
        file_path (str): The path to the YAML file.

    Returns:
        dict: The parsed YAML data.

    """
    with open(file_path, "r") as stream:
        try:
            return yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)
            sys.exit(1)


def string_to_resource_type(string_value):
    """
    Converts a string value to a corresponding ResourceType enumeration value.

    Args:
        string_value (str): The string representation of the resource type.

    Returns:
        api_catalog.ResourceType: The corresponding ResourceType value.
        If the string value is invalid, returns api_catalog.ResourceType.UNKNOWN.
    """
    try:
        return api_catalog.ResourceType.Value(string_value)
    except ValueError:
        return api_catalog.ResourceType.UNKNOWN


def string_to_resource_format(string_value):
    """
    Converts a string value to a corresponding ResourceFormat enumeration value.

    Args:
        string_value (str): The string representation of the resource format.

    Returns:
        api_catalog.ResourceFormat: The corresponding ResourceFormat value.
        If the string value is invalid, returns api_catalog.ResourceFormat.json.
    """
    try:
        return api_catalog.ResourceFormat.Value(string_value)
    except ValueError:
        return api_catalog.ResourceFormat.json


class Evaluator:
    """
    A class to evaluate and record the results of various test cases.

    Attributes:
        successful (list): A list to store the successful test cases.
        failure (list): A list to store the failed test cases.
        id (int): The ID of the current test case.
        asset (str): The asset definition related to the test case.
        helper_name (str): The name of the helper being tested.
        helper_type (str): The type of helper being tested.
        description (str): The description of the test case.
        should_pass (bool): Indicates if the test case is expected to pass.
        expected (str): The expected result of the test case.
        input (list): The input data for the test case.
    """

    successful = []
    failure = []
    id = 0
    asset = ""
    helper_name = ""
    helper_type = ""
    description = ""
    should_pass = False
    expected = ""
    input = []

    def set_id(self, id: int):
        """
        Sets the ID of the current test case.

        Args:
            id (int): The ID of the test case.
        """
        self.id = id

    def set_helper_name(self, helper_name: str):
        """
        Sets the name of the helper being tested.

        Args:
            helper_name (str): The name of the helper.
        """
        self.helper_name = helper_name

    def set_description(self, description: str):
        """
        Sets the description of the test case.

        Args:
            description (str): The description of the test case.
        """
        self.description = description

    def set_asset_definition(self, asset: str):
        """
        Sets the asset definition related to the test case.

        Args:
            asset (str): The asset definition.
        """
        self.asset = asset

    def set_should_pass(self, should_pass: bool):
        """
        Sets whether the test case is expected to pass.

        Args:
            should_pass (bool): True if the test case is expected to pass, False otherwise.
        """
        self.should_pass = should_pass

    def set_expected(self, expected: str):
        """
        Sets the expected result of the test case.

        Args:
            expected (str): The expected result.
        """
        self.expected = expected

    def set_helper_type(self, helper_type: str):
        """
        Sets the type of helper being tested.

        Args:
            helper_type (str): The type of helper.
        """
        self.helper_type = helper_type

    def set_input(self, input: list):
        """
        Sets the input data for the test case.

        Args:
            input (list): The input data.
        """
        self.input = input

    def create_failure_test(self, response):
        """
        Creates a record for a failed test case.

        Args:
            response: The response received from the API call.
        """
        failure_test = {
            "helper": self.helper_name,
            "id": self.id,
            "description": {
                "message": f"{self.description}: {self.expected}",
                "asset": self.asset,
                "response": json.loads(MessageToJson(response)),
                "should_pass": self.should_pass,
                "expected": self.expected,
            },
        }

        self.failure.append(failure_test)

    def create_success_test(self):
        """
        Creates a record for a successful test case.
        """
        success_test = {
            "helper": self.helper_name,
            "id": self.id,
        }

        self.successful.append(success_test)

    def check_response(self, response: dict):
        """
        Checks the response from the API call to determine if the test case passed or failed.

        Args:
            response (dict): The response received from the API call.
        """
        if (self.should_pass and response.status == api_engine.OK) or (
            not self.should_pass and response.status == api_engine.ERROR
        ):
            self.create_success_test()
        else:
            self.create_failure_test(response)

    def handle_map_event_with_field_mapping(self, response, output: dict, field_mapping: str):
        """
        Handles the mapping event with field mapping.

        Args:
            response: The response received from the API call.
            output (dict): The output from the API call.
            field_mapping (str): The field mapping to be checked in the output.
        """
        if self.expected:
            if self.should_pass:
                if output[field_mapping] == self.expected:
                    self.create_success_test()
                else:
                    self.create_failure_test(response)
            else:
                if output[field_mapping] != self.expected:
                    self.create_success_test()
                else:
                    self.create_failure_test(response)
        else:
            self.create_success_test()

    def handle_transform_event_with_field_mapping(self, response, output: dict, field_mapping: str):
        """
        Handles the transform event with field mapping.

        Args:
            response: The response received from the API call.
            output (dict): The output from the API call.
            field_mapping (str): The field mapping to be checked in the output.
        """
        if self.expected:
            if output[field_mapping] == self.expected:
                self.create_success_test()
            else:
                self.create_failure_test(response)
        else:
            self.create_success_test()

    def tester_run_map(self, api_client: APIClient, field_mapping: str):
        """
        Runs the map test case.

        Args:
            api_client: The API client to use for the request.
            field_mapping (str): The field mapping to be checked in the output.
        """
        request = build_run_post_request(self.input, api_tester.NONE)
        error, response = send_recv(api_client, request, api_tester.RunPost_Response())
        output = extract_output_from_response(response)

        if (self.should_pass and field_mapping in output) or (
            not self.should_pass and field_mapping not in output
        ) or (not self.should_pass and field_mapping in output):
            if field_mapping in output:
                self.handle_map_event_with_field_mapping(response, output, field_mapping)
            else:
                self.create_success_test()
        else:
            if self.expected is not None:
                self.create_failure_test(response)
            else:
                self.create_success_test()

    def tester_run_filter(self, api_client: APIClient, field_mapping: str):
        """
        Runs the filter test case.

        Args:
            api_client: The API client to use for the request.
            field_mapping (str): The field mapping to be checked in the output.
        """
        request = build_run_post_request(self.input, api_tester.NONE)
        error, response = send_recv(api_client, request, api_tester.RunPost_Response())
        output = extract_output_from_response(response)

        if (self.should_pass and field_mapping in output) or (
            not self.should_pass and field_mapping not in output
        ) or (self.should_pass and field_mapping not in output):
            self.create_success_test()
        else:
            self.create_failure_test(response)

    def tester_run_transform(self, api_client: APIClient, field_mapping: str):
        """
        Runs the transform test case.

        Args:
            api_client: The API client to use for the request.
            field_mapping (str): The field mapping to be checked in the output.
        """
        request = build_run_post_request(self.input, api_tester.ALL)
        error, response = send_recv(api_client, request, api_tester.RunPost_Response())
        output = extract_output_from_response(response)
        result = extract_transformation_result_from_response(response, self.helper_name)

        if (self.should_pass and result == "Success") or (
            not self.should_pass and result != "Success"
        ):
            if field_mapping in output:
                self.handle_transform_event_with_field_mapping(response, output, field_mapping)
            else:
                self.create_success_test()
        else:
            self.create_failure_test(response)


def run_command(command: str):
    result = subprocess.run(
        command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    assert result.returncode == 0, f"{result.stderr}"


def send_recv(api_client: APIClient, request, expected_response_type) -> Tuple[Optional[str], dict]:
    """
    Sends a request to the API and receives a response, handling errors and parsing the response.

    Args:
        api_client: The API client handling the communication.
        request: The request to be sent.
        expected_response_type: The expected response type for parsing.

    Returns:
        Tuple[Optional[str], dict]: A tuple containing an error message (if any) and the parsed response.
    """
    try:
        error, response = api_client.send_recv(request)
        assert error is None, f"{error}"
        parse_response = ParseDict(response, expected_response_type)
        if parse_response.status == api_engine.ERROR:
            return parse_response.error, parse_response
        else:
            return None, parse_response
    except Exception as e:
        assert False, f"Error parsing response: {str(e)}"


def create_asset_for_runtime(api_client: APIClient, result_evaluator: Evaluator):
    """
    Creates an asset at runtime and verifies the creation status.

    Args:
        api_client: The API client used to send requests.
        asset (dict): The asset details required to create the asset.
        id (str): The identifier for the test case.
        helper_name (str): The name of the helper function.
        description (str): A description of the test case.
        failed_tests (list): A list to append details of failed test cases.

    Returns:
        bool: True if the asset creation is successful, False otherwise.
    """
    request = build_asset_request(result_evaluator.asset)
    error, response = send_recv(
        api_client, request, api_engine.GenericStatus_Response()
    )

    if response.status == api_engine.OK:
        return True

    result_evaluator.failure.append(
        {
            "helper": result_evaluator.helper_name,
            "id": result_evaluator.id,
            "description": {
                "message": result_evaluator.description,
                "asset": result_evaluator.asset,
                "response": response,
                "expected": True,
            },
        }
    )
    return False


def create_policy(api_client: APIClient):
    """
    Creates a policy using the provided API client.

    Args:
        api_client: The API client used to send requests.
    """
    request = api_policy.StorePost_Request()
    request.policy = POLICY_NAME
    error, response = send_recv(
        api_client, request, api_engine.GenericStatus_Response()
    )


def add_asset_to_policy(api_client: APIClient, asset: dict):
    """
    Adds an asset to a policy using the provided API client.

    Args:
        api_client: The API client used to send requests.
        asset (dict): The asset details required to add the asset to the policy.
    """
    request = api_policy.AssetPost_Request()
    request.policy = POLICY_NAME
    request.asset = asset["name"]
    request.namespace = NAMESPACE
    error, response = send_recv(
        api_client, request, api_engine.GenericStatus_Response()
    )

    assert response.status == api_engine.OK, f"{error}, Asset: {asset}"


def create_session(api_client: APIClient):
    """
    Creates a session using the provided API client.

    Args:
        api_client: The API client used to send requests.
    """
    request = api_tester.SessionPost_Request()
    request.session.name = SESSION_NAME
    request.session.policy = POLICY_NAME
    error, response = send_recv(
        api_client, request, api_engine.GenericStatus_Response()
    )

    assert response.status == api_engine.OK, f"{error}"


def delete_session(api_client: APIClient):
    """
    Deletes a session using the provided API client.

    Args:
        api_client: The API client used to send requests.
    """
    request = api_tester.SessionDelete_Request()
    request.name = SESSION_NAME
    error, response = send_recv(
        api_client, request, api_engine.GenericStatus_Response()
    )


def generate_report(successful_tests: list, failed_tests: list):
    """
    Generates a test report based on successful and failed test cases.

    Args:
        successful_tests (list): A list of dictionaries containing details of successful test cases.
        failed_tests (list): A list of dictionaries containing details of failed test cases.
    """

    global only_success
    global only_failure

    report = "## Test Report\n\n"
    report += "### General Summary\n\n"
    report += (
        f"- Total test cases executed: {len(successful_tests) + len(failed_tests)}\n"
    )
    report += f"- Successful test cases: {len(successful_tests)}\n"
    report += f"- Failed test cases: {len(failed_tests)}\n\n"

    if only_success:
        if successful_tests:
            report += "#### Successful Test Cases\n\n"
            for i, success_test in enumerate(successful_tests, start=1):
                report += f"{i}. **Test Case {i}**\n"
                report += f"   - Helper: {success_test['helper']}\n"
                report += f"   - Id: {success_test['id']}\n"

    if only_failure:
        if failed_tests:
            report += "#### Failed Test Cases\n\n"
            for i, failed_test in enumerate(failed_tests, start=1):
                report += f"{i}. **Test Case {i}**\n"
                report += f"   - Helper: {failed_test['helper']}\n"
                report += f"   - Id: {failed_test['id']}\n"
                report += f"   - Description: {failed_test['description']}\n"

    print(report)


def build_asset_request(asset):
    """
    Builds a request to post an asset.

    Args:
        asset (dict): The asset details required to build the request.

    Returns:
        request: The built request object for posting the asset.
    """
    request = api_catalog.ResourcePost_Request()
    request.type = string_to_resource_type("decoder")
    request.format = string_to_resource_format("json")
    request.content = json.dumps(asset)
    request.namespaceid = NAMESPACE
    return request


def build_run_post_request(input_data, level: api_tester.TraceLevel):
    """
    Builds a request to run a post operation with the given input data and debug level.

    Args:
        input_data (dict): The input data for the run post request.
        level (api_tester.TraceLevel): The debug level for the request (NONE, ASSET_ONLY, ALL).

    Returns:
        request: The built request object for running the post operation.
    """
    debug_level_to_int = {api_tester.NONE: 0, api_tester.ASSET_ONLY: 1, api_tester.ALL: 2}
    request = api_tester.RunPost_Request()
    request.name = SESSION_NAME
    request.trace_level = debug_level_to_int[level]
    request.message = json.dumps(input_data)
    request.queue = "1"
    request.location = "any"
    request.namespaces.extend([NAMESPACE])
    return request


def extract_output_from_response(response):
    """
    Extracts the event output from the response object.

    Args:
        response (object): The response object returned from the API call.

    Returns:
        dict: The event output extracted from the response.
    """
    response = json.loads(MessageToJson(response))
    return response["result"]["output"]


def extract_transformation_result_from_response(response, helper_name):
    """
    Extracts the transformation result from the response object.

    Args:
        response (object): The response object returned from the API call.

    Returns:
        str: The transformation result extracted from the response.
    """
    response = json.loads(MessageToJson(response))
    traces = response["result"]["assetTraces"][0]["traces"]

    # Find the trace that contains "helper_name"
    target_trace = next((trace for trace in traces if helper_name in trace), None)

    if target_trace:
        regex = r"->\s*(Success|Failure)"
        match = re.search(regex, target_trace)
        if match:
            return match.group(1)

    return None


def create_asset_for_buildtime(api_client: APIClient, result_evaluator: Evaluator):
    """
    Creates an asset for build-time testing and handles the response.

    Args:
        api_client (APIClient): The API client used to make requests.
    """
    request = build_asset_request(result_evaluator.asset)
    error, response = send_recv(api_client, request, api_engine.GenericStatus_Response())
    result_evaluator.check_response(response)


def process_files_in_directory(directory, api_client: APIClient, socket_path: str, result_evaluator: Evaluator):
    """
    Process all files in the given directory.

    Args:
        directory (Path): The directory to process.
        api_client (APIClient): The API client used to make requests.
        socket_path (str): The path to the socket.
        successful_tests (list): A list to store successful test cases.
        failure_tests (list): A list to store failed test cases.
    """
    for element in directory.iterdir():
        if element.is_dir():
            for file in element.iterdir():
                process_file(file, api_client, socket_path, result_evaluator)


def execute_single_run_test(api_client, run_test: dict, result_evaluator: Evaluator):
    """
    Execute single run test.

    Args:
        api_client (APIClient): The API client used to make requests.
        run_test (dict): The configuration for the run test.
        result_evaluator: Object that handles the result of each test by deciding whether it was successful or not
    """

    result_evaluator.set_id(run_test["id"])
    result_evaluator.set_should_pass(run_test["should_pass"])
    result_evaluator.set_expected(run_test.get("expected"))
    result_evaluator.set_description(run_test["description"])
    result_evaluator.set_input([])

    create_asset_for_runtime(
        api_client,
        result_evaluator
    )
    create_policy(api_client)
    add_asset_to_policy(api_client, run_test["assets_definition"])
    create_session(api_client)

    if result_evaluator.helper_type == "map":
        result_evaluator.tester_run_map(api_client, "helper")
    elif result_evaluator.helper_type == "filter":
        result_evaluator.tester_run_filter(api_client, "verification_field")
    elif result_evaluator.helper_type == "transformation":
        result_evaluator.tester_run_transform(api_client, "target_field")
    else:
        print(f"Helper type '{result_evaluator.helper_type}' not is valid")
        sys.exit(1)


def execute_multiple_run_tests(api_client: APIClient, run_test: dict, result_evaluator: Evaluator):
    """
    Execute multiple run tests.

    Args:
        api_client (APIClient): The API client used to make requests.
        run_test (dict): The configuration for the run test.
        result_evaluator: Object that handles the result of each test by deciding whether it was successful or not
    """
    for j, test_case in enumerate(run_test["test_cases"]):

        result_evaluator.set_id(test_case.get("id"))
        result_evaluator.set_should_pass(test_case.get("should_pass", None))
        result_evaluator.set_expected(test_case.get("expected", None))
        result_evaluator.set_description(run_test["description"])
        result_evaluator.set_input(test_case.get("input", []))

        if j == 0:
            if not create_asset_for_runtime(api_client, result_evaluator):
                continue
            create_policy(api_client)
            add_asset_to_policy(api_client, run_test["assets_definition"])
            create_session(api_client)

        if result_evaluator.helper_type == "map":
            result_evaluator.tester_run_map(api_client, "helper")
        elif result_evaluator.helper_type == "filter":
            result_evaluator.tester_run_filter(api_client, "verification_field")
        elif result_evaluator.helper_type == "transformation":
            result_evaluator.tester_run_transform(api_client, "target_field")
        else:
            print(f"Helper type '{result_evaluator.helper_type}' not is valid")
            sys.exit(1)


def process_file(file: str, api_client: APIClient, socket_path: str, result_evaluator: Evaluator):
    """
    Process a YAML file containing test configurations.

    Args:
        file (str): The YAML file to process.
        api_client (APIClient): The API client used to make requests.
        socket_path (str): The path to the socket.
        successful_tests (list): A list to store successful test cases.
        failure_tests (list): A list to store failed test cases.
    """
    file_content = load_yaml(file)
    result_evaluator.set_helper_name(file.stem)

    for build_test in file_content.get("build_test", []):
        # Evaluator set
        result_evaluator.set_id(build_test["id"])
        result_evaluator.set_asset_definition(build_test["assets_definition"])
        result_evaluator.set_should_pass(build_test["should_pass"])
        result_evaluator.set_description(build_test["description"])

        # Tear Down
        run_command(f"engine-clear -f --api-sock {socket_path}")

        # Try create asset
        create_asset_for_buildtime(api_client, result_evaluator)

    for run_test in file_content.get("run_test", []):
        # Evaluator set
        result_evaluator.set_helper_type(file_content["helper_type"])
        result_evaluator.set_asset_definition(run_test["assets_definition"])

        # Tear Down
        run_command(f"engine-clear -f --api-sock {socket_path}")
        delete_session(api_client)

        if "test_cases" not in run_test:
            execute_single_run_test(
                api_client,
                run_test,
                result_evaluator
            )
        else:
            execute_multiple_run_tests(
                api_client,
                run_test,
                result_evaluator
            )


def run_test_cases_generator():
    """
    Generates test cases by iterating over Python files in subdirectories.

    If any script returns a non-zero exit code, the function exits with status code 1.
    """
    # Get the current directory
    current_dir = Path(__file__).resolve().parent

    # Iterate over all items in the current directory
    for item in current_dir.iterdir():
        # Check if the item is a directory
        if item.is_dir():
            # Get the list of files in the directory
            files = item.iterdir()
            # Look for files with .py extension and execute them
            for file in files:
                if file.suffix == ".py":
                    print(f"Running {file}")
                    # Execute the Python script
                    if input_file:
                        result = subprocess.run(
                            ["python3", str(file), "--input_file", input_file]
                        )
                    else:
                        result = subprocess.run(["python3", str(file)])

                    if result.returncode == 1:
                        sys.exit(1)


def run_test_cases_executor(api_client: APIClient, socket_path: str):
    """
    Execute test cases found in YAML files in the current directory.

    Args:
        api_client (APIClient): The API client used to make requests.
        socket_path (str): The path to the socket.
    """
    # Get the current directory
    current_dir = Path(__file__).resolve().parent

    result_evaluator = Evaluator()

    for item in current_dir.iterdir():
        if item.is_dir():
            process_files_in_directory(item, api_client, socket_path, result_evaluator)

    generate_report(result_evaluator.successful, result_evaluator.failure)

    if len(result_evaluator.failure) != 0:
        sys.exit(1)


def main():
    global environment_directory
    global WAZUH_DIR
    global SCRIPT_DIR

    parse_arguments()
    serv_conf_file = check_config_file()

    os.environ["ENV_DIR"] = environment_directory
    os.environ["WAZUH_DIR"] = str(SCRIPT_DIR.joinpath("../../../..").resolve())
    os.environ["CONF_FILE"] = serv_conf_file
    socket_path = environment_directory + "/queue/sockets/engine-api"
    api_client = APIClient(socket_path)

    # Generate test cases
    run_test_cases_generator()

    from handler_engine_instance import up_down

    up_down_engine = up_down.UpDownEngine()
    up_down_engine.send_start_command()

    run_test_cases_executor(api_client, socket_path)

    up_down_engine.send_stop_command()


if __name__ == "__main__":
    main()
