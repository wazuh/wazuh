#!/usr/bin/env python3

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional

import yaml
from google.protobuf.message import Message
from api_communication.client import APIClient
from api_communication.proto import catalog_pb2 as api_catalog
from api_communication.proto import kvdb_pb2 as api_kvdb
from api_communication.proto import engine_pb2 as api_engine
from api_communication.proto import policy_pb2 as api_policy
from api_communication.proto import tester_pb2 as api_tester
from google.protobuf.json_format import MessageToJson, ParseDict

POLICY_NAME = "policy/wazuh/0"
ASSET_NAME = "decoder/test/0"
SESSION_NAME = "test"
NAMESPACE = "user"


class Config:
    """
    A class to store the configuration of the test runner.
    """
    environment_directory: str = ""
    wazuh_dir: str = ""
    input_file_path: str = ""
    folder_path: str = ""
    binary_path: str = ""
    only_failure: bool = False
    only_success: bool = False


config = Config()


def parse_arguments():
    """
    Parses command-line arguments for configuring the environment and selecting test cases to display.
    """
    parser = argparse.ArgumentParser(description="Runs the generated test cases and validates their results")
    parser.add_argument("-e", "--environment", required=True, help="Environment directory")
    parser.add_argument("-b", "--binary", required=True, help="Path to the binary file")

    parser.add_argument("--input_file_path", help="Absolute or relative path where the test cases were generated")
    parser.add_argument("--folder_path", help="Absolute or relative path where the test cases were generated")
    parser.add_argument("--failure_cases", help="Shows only the failure test cases that occurred", action="store_true")
    parser.add_argument("--success_cases", help="Shows only the success test cases that occurred", action="store_true")

    args = parser.parse_args()

    if args.input_file_path and args.folder_path:
        args.error("Only one of --input_file_path or --folder_path can be specified.")

    config.environment_directory = args.environment
    config.binary_path = args.binary

    config.input_file_path = args.input_file_path
    config.folder_path = args.folder_path
    config.only_success = args.success_cases
    config.only_failure = args.failure_cases


def check_config_file() -> str:
    """
    Checks the existence and validity of the environment directory and configuration file.

    If the environment directory or configuration file is not found, the script exits with an error message.
    Returns:
        str: The path to the configuration file if all checks pass.
    """
    env_dir = Path(config.environment_directory)
    serv_conf_file = env_dir / "engine" / "general.conf"

    if not env_dir.is_dir():
        sys.exit(f"Error: Environment directory {env_dir} not found.")
    if not serv_conf_file.is_file():
        sys.exit(f"Error: Configuration file {serv_conf_file} not found.")

    return str(serv_conf_file)


def load_yaml(file_path: str) -> dict:
    """
    Loads data from a YAML file.

    Args:
        file_path (str): The path to the YAML file.

    Returns:
        dict: The data loaded from the YAML file.
    """
    with open(file_path, "r") as stream:
        try:
            return yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            sys.exit(f"Error loading YAML file: {exc}")


class Evaluator:
    """
    A class to evaluate and record the results of various test cases.

    Attributes:
        successful (list): A list of successful test cases.
        failure (list): A list of failed test cases.
        id (int): The ID of the test case.
        asset (str): The asset definition.
        helper_name (str): The name of the helper function.
        helper_type (str): The type of the helper function.
        description (str): The description of the test case.
        should_pass (bool): Whether the test case should pass.
        expected (str): The expected result of the test case.
        input (list): The input data for the test case.
    """

    def __init__(self):
        self.successful = []
        self.failure = []
        self.id = 0
        self.asset = ""
        self.helper_name = ""
        self.helper_type = ""
        self.description = ""
        self.field_mapping = ""
        self.should_pass = False
        self.skipped = False
        self.expected = ""
        self.input = []

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

    def set_skipped(self, skipped: bool):
        """
        Sets whether the test case is skipped.

        Args:
            skipped (bool): True whether the test should be skipped, False otherwise.
        """
        self.skipped = skipped

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
        if json.loads(MessageToJson(response)).get("result"):
            json_response = json.loads(MessageToJson(response))["result"]["output"].get(self.field_mapping)
        else:
            json_response = None
        failure_test = {
            "helper": self.helper_name,
            "id": self.id,
            "description": json.dumps({
                "message": f"{self.description}",
                "asset": self.asset,
                "all_response": json.loads(MessageToJson(response)),
                "should_pass": self.should_pass,
                "expected": self.expected,
                "response": json_response
            }),
        }

        self.failure.append(failure_test)

    def create_success_test(self):
        """
        Creates a log entry for a successful test case.
        """
        success_test = {
            "helper": self.helper_name,
            "id": self.id,
        }
        self.successful.append(success_test)

    def check_response(self, response: dict) -> None:
        """
        Checks the response of an API request and creates a log entry based on the result.
        """
        if not self.skipped:
            if (self.should_pass and response.status == api_engine.OK) or (
                not self.should_pass and response.status == api_engine.ERROR
            ):
                self.create_success_test()
            else:
                self.create_failure_test(response)
        else:
            self.create_success_test()

    def handle_map_event_with_field_mapping(self, response, output: dict, field_mapping: str):
        """
        Handles the event of a map test case with a field mapping.

        Args:
            response (dict): The response from the API request.
            output (dict): The output data from the response.
            field_mapping (str): The field mapping to check.
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
        self.field_mapping = field_mapping
        request = build_run_post_request(self.input, api_tester.ALL)
        response = send_recv(api_client, request, api_tester.RunPost_Response())
        output = extract_output_from_response(response)

        if not self.skipped:
            if (self.should_pass and field_mapping in output) or (not self.should_pass and field_mapping not in output):
                if field_mapping in output:
                    self.handle_map_event_with_field_mapping(response, output, field_mapping)
                else:
                    self.create_success_test()
            else:
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
        self.field_mapping = field_mapping
        request = build_run_post_request(self.input, api_tester.ALL)
        response = send_recv(api_client, request, api_tester.RunPost_Response())
        output = extract_output_from_response(response)

        if not self.skipped:
            if (self.should_pass and field_mapping in output) or (not self.should_pass and field_mapping not in output):
                self.create_success_test()
            else:
                self.create_failure_test(response)
        else:
            self.create_success_test()

    def tester_run_transform(self, api_client: APIClient, field_mapping: str):
        """
        Runs the transform test case.

        Args:
            api_client: The API client to use for the request.
            field_mapping (str): The field mapping to be checked in the output.
        """
        self.field_mapping = field_mapping
        request = build_run_post_request(self.input, api_tester.ALL)
        response = send_recv(api_client, request, api_tester.RunPost_Response())
        output = extract_output_from_response(response)
        result = extract_transformation_result_from_response(response, self.helper_name)

        if not self.skipped:
            if (self.should_pass and result == "Success") or (not self.should_pass and result != "Success"):
                if field_mapping in output:
                    self.handle_transform_event_with_field_mapping(response, output, field_mapping)
                else:
                    self.create_success_test()
            else:
                self.create_failure_test(response)
        else:
            self.create_success_test()


def run_command(command: str):
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert result.returncode == 0, f"{result.stderr}"


def send_recv(api_client: APIClient, request: Message, expected_response_type: Message) -> Message:
    """
    Sends a request to the API and receives a response, handling errors and parsing the response.

    Args:
        api_client: The API client handling the communication.
        request: The request to be sent.
        expected_response_type: The expected response type for parsing.

    Returns:
        Message: Object that contains the parsed response.
    """
    try:
        error, response = api_client.send_recv(request)
        assert error is None, f"{error}"
        parse_response: Message = ParseDict(response, expected_response_type)
        return parse_response
    except Exception as e:
        sys.exit(f"Error parsing response: {str(e)}")


def create_asset_for_runtime(api_client: APIClient, result_evaluator: Evaluator) -> bool:
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
    response = send_recv(api_client, request, api_engine.GenericStatus_Response())
    if response.status == api_engine.OK:
        return True
    if result_evaluator.skipped:
        result_evaluator.create_success_test()
    else:
        if result_evaluator.should_pass:
            result_evaluator.create_failure_test(response)
        else:
            result_evaluator.create_success_test()
    return False


def create_policy(api_client: APIClient):
    """
    Creates a policy using the provided API client.

    Args:
        api_client: The API client used to send requests.
    """
    request = api_policy.StorePost_Request()
    request.policy = POLICY_NAME
    send_recv(api_client, request, api_engine.GenericStatus_Response())


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
    response = send_recv(api_client, request, api_policy.AssetPost_Response())
    assert response.status == api_engine.OK, f"{response.error}, Asset: {asset}"
    assert len(response.warning) == 0, f"{response.warning}"


def create_session(api_client: APIClient):
    request = api_tester.SessionPost_Request()
    request.session.name = SESSION_NAME
    request.session.policy = POLICY_NAME
    response = send_recv(api_client, request, api_engine.GenericStatus_Response())
    assert response.status == api_engine.OK, f"{response.error}"


def delete_session(api_client: APIClient):
    request = api_tester.SessionDelete_Request()
    request.name = SESSION_NAME
    send_recv(api_client, request, api_engine.GenericStatus_Response())


def delete_policy(api_client: APIClient):
    request = api_policy.StoreDelete_Request()
    request.policy = POLICY_NAME
    send_recv(api_client, request, api_engine.GenericStatus_Response())


def delete_asset(api_client: APIClient):
    request = api_catalog.ResourceDelete_Request()
    request.name = ASSET_NAME
    request.namespaceid = NAMESPACE
    send_recv(api_client, request, api_engine.GenericStatus_Response())


def create_kvdb(api_client: APIClient, kvdb_path: str):
    request = api_kvdb.managerPost_Request()
    request.name = "testing"
    request.path = kvdb_path
    send_recv(api_client, request, api_engine.GenericStatus_Response())


def delete_kvdb(api_client: APIClient):
    request = api_kvdb.managerDelete_Request()
    request.name = "testing"
    send_recv(api_client, request, api_engine.GenericStatus_Response())


def generate_report(successful_tests: list, failed_tests: list) -> str:
    """
    Generates a report of the test results.

    Args:
        successful_tests (list): A list of successful test cases.
        failed_tests (list): A list of failed test cases.
    """
    report = "## Test Report\n\n"
    report += "### General Summary\n\n"
    report += f"- Total test cases executed: {len(successful_tests) + len(failed_tests)}\n"
    report += f"- Successful test cases: {len(successful_tests)}\n"
    report += f"- Failed test cases: {len(failed_tests)}\n\n"

    if config.only_success:
        if successful_tests:
            report += "#### Successful Test Cases\n\n"
            for i, success_test in enumerate(successful_tests, start=1):
                report += f"{i}. **Test Case {i}**\n"
                report += f"   - Helper: {success_test['helper']}\n"
                report += f"   - Id: {success_test['id']}\n"

    if config.only_failure:
        if failed_tests:
            report += "#### Failed Test Cases\n\n"
            for i, failed_test in enumerate(failed_tests, start=1):
                report += f"{i}. **Test Case {i}**\n"
                report += f"   - Helper: {failed_test['helper']}\n"
                report += f"   - Id: {failed_test['id']}\n"
                report += f"   - Description: {failed_test['description']}\n"
    return report


def build_asset_request(asset: dict) -> api_catalog.ResourcePost_Request:
    """
    Builds a request to post an asset.

    Args:
        asset (dict): The asset details required to build the request.

    Returns:
        request: The built request object for posting the asset.
    """
    request = api_catalog.ResourcePost_Request()
    request.type = api_catalog.ResourceType.Value("decoder")
    request.format = api_catalog.ResourceFormat.Value("json")
    request.content = json.dumps(asset)
    request.namespaceid = NAMESPACE
    return request


def build_run_post_request(input_data: dict, level: api_tester.TraceLevel) -> api_tester.RunPost_Request:
    """
    Builds a request to run a post operation with the given input data and debug level.

    Args:
        input_data (dict): The input data for the run post request.
        level (api_tester.TraceLevel): The debug level for the request (NONE, ASSET_ONLY, ALL).

    Returns:
        request: The built request object for running the post operation.
    """
    request = api_tester.RunPost_Request()
    request.name = SESSION_NAME
    request.trace_level = level
    request.message = json.dumps(input_data)
    request.queue = "1"
    request.location = "any"
    request.namespaces.extend([NAMESPACE])
    return request


def extract_output_from_response(response: dict) -> dict:
    """
    Extracts the event output from the response object.

    Args:
        response (object): The response object returned from the API call.

    Returns:
        dict: The event output extracted from the response.
    """
    response = json.loads(MessageToJson(response))
    return response["result"]["output"]


def get_target_trace(traces: list, helper_name: str, count=1) -> Optional[str]:
    """
    Obtains the target trace containing the specified helper name from a list of traces.

    Args:
        traces (list): The list of trace strings to search through.
        helper_name (str): The helper name to look for within each trace.
        count (int, optional): The number of times to call next on the filtered iterator. Default is 1.

    Returns:
        str or None: The target trace containing the helper name if found, otherwise None.
    """
    iterator = (trace for trace in traces if helper_name in trace)
    target_trace = None
    for _ in range(count):
        target_trace = next(iterator, None)
        if target_trace is None:
            break
    return target_trace


def extract_transformation_result_from_response(response: dict, helper_name: str) -> Optional[str]:
    """
    Extracts the transformation result from the response object.

    Args:
        response (object): The response object returned from the API call.

    Returns:
        str: The transformation result extracted from the response.
    """
    response = json.loads(MessageToJson(response))
    # Take the first asset trace as the asset is unique
    # TODO check name of the asset
    traces = response["result"]["assetTraces"][0]["traces"]
    if helper_name != "parse_json":
        target_trace = get_target_trace(traces, helper_name)
    else:
        # Ignore the first parse_json of the event.original
        target_trace = get_target_trace(traces, helper_name, count=2)

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
    response = send_recv(api_client, request, api_engine.GenericStatus_Response())
    result_evaluator.check_response(response)


def execute_single_run_test(api_client: APIClient, run_test: dict, result_evaluator: Evaluator):
    """
    Execute single run test.

    Args:
        api_client (APIClient): The API client used to make requests.
        run_test (dict): The configuration for the run test.
        result_evaluator: Object that handles the result of each test by deciding whether it was successful or not
    """

    result_evaluator.set_id(run_test["id"])
    result_evaluator.set_should_pass(run_test.get("should_pass", None))
    result_evaluator.set_expected(run_test.get("expected"))
    result_evaluator.set_skipped(run_test.get("skipped", False))
    result_evaluator.set_description(run_test["description"])
    result_evaluator.set_input([])

    if create_asset_for_runtime(api_client, result_evaluator):
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
            sys.exit(f"Helper type '{result_evaluator.helper_type}' not is valid")


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
        result_evaluator.set_skipped(test_case.get("skipped"))
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
            sys.exit(f"Helper type '{result_evaluator.helper_type}' not is valid")


def process_file(file: Path, api_client: APIClient, result_evaluator: Evaluator, kvdb_path: str):
    """
    Process a YAML file containing test configurations.

    Args:
        file (str): The YAML file to process.
        api_client (APIClient): The API client used to make requests.
        successful_tests (list): A list to store successful test cases.
        failure_tests (list): A list to store failed test cases.
    """
    file_content = load_yaml(file)
    result_evaluator.set_helper_name(file.stem)

    for build_test in file_content.get("build_test", []):
        result_evaluator.set_id(build_test["id"])
        result_evaluator.set_asset_definition(build_test["assets_definition"])
        result_evaluator.set_should_pass(build_test["should_pass"])
        result_evaluator.set_description(build_test["description"])
        result_evaluator.set_skipped(build_test.get("skipped", False))

        # Tear Down
        delete_asset(api_client)
        delete_kvdb(api_client)

        # Setup
        create_kvdb(api_client, kvdb_path)
        create_asset_for_buildtime(api_client, result_evaluator)

    for run_test in file_content.get("run_test", []):
        result_evaluator.set_helper_type(file_content["helper_type"])
        result_evaluator.set_asset_definition(run_test["assets_definition"])

        # Tear Down
        delete_asset(api_client)
        delete_policy(api_client)
        delete_session(api_client)
        delete_kvdb(api_client)

        # Setup
        create_kvdb(api_client, kvdb_path)

        if "test_cases" not in run_test:
            execute_single_run_test(api_client, run_test, result_evaluator)
        else:
            execute_multiple_run_tests(api_client, run_test, result_evaluator)


def run_test_cases_executor(api_client: APIClient, kvdb_path: str):
    """
    Execute test cases found in Python files in specific directories.

    Args:
        api_client (APIClient): The API client used to make requests.
        kvdb_path (str): The path to the key-value database.
    """
    result_evaluator = Evaluator()
    if config.input_file_path:
        process_file(Path(config.input_file_path), api_client, result_evaluator, kvdb_path)
    elif config.folder_path:
        for file in Path(config.folder_path).iterdir():
            if file.is_file() and (file.suffix in ['.yml', '.yaml']):
                process_file(file, api_client, result_evaluator, kvdb_path)
    else:
        sys.exit("It is necessary to indicate a file or directory that contains a configuration yaml")

    report = generate_report(result_evaluator.successful, result_evaluator.failure)

    if len(result_evaluator.failure) != 0:
        sys.exit(report)
    print(report)


def main():
    parse_arguments()

    serv_conf_file = check_config_file()
    ENVIRONMENT_DIR = Path(config.environment_directory)
    kvdb_path = ENVIRONMENT_DIR / "engine" / "etc" / "kvdb" / "test.json"
    socket_path = str(ENVIRONMENT_DIR / "queue" / "sockets" / "engine-api")

    os.environ['ENV_DIR'] = ENVIRONMENT_DIR.as_posix()
    os.environ['BINARY_DIR'] = config.binary_path
    os.environ['CONF_FILE'] = serv_conf_file

    api_client = APIClient(socket_path)

    from handler_engine_instance import up_down
    print("Starting up_down engine")
    up_down_engine = up_down.UpDownEngine()
    up_down_engine.send_start_command()

    print("running test cases")
    run_test_cases_executor(api_client, str(kvdb_path))

    up_down_engine.send_stop_command()


if __name__ == "__main__":
    main()
