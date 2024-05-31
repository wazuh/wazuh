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

SCRIPT_DIR = Path(__file__).resolve().parent
WAZUH_DIR = SCRIPT_DIR.joinpath("../../../..").resolve()
POLICY_NAME = "policy/wazuh/0"
ASSET_NAME = "decoder/test/0"
SESSION_NAME = "test"
NAMESPACE = "user"
only_failure = None
only_success = None


def send_recv(api_client, request, expected_response_type) -> Tuple[Optional[str], dict]:
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


def load_yaml(file_path):
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


def run_command(command):
    result = subprocess.run(
        command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    assert result.returncode == 0, f"{result.stderr}"


def create_asset_for_runtime(api_client, asset, id, helper_name, description, failed_tests):
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
    request = build_asset_request(asset)
    error, response = send_recv(
        api_client, request, api_engine.GenericStatus_Response()
    )

    if response.status == api_engine.OK:
        return True

    failed_tests.append(
        {
            "helper": helper_name,
            "id": id,
            "description": {
                "message": description,
                "asset": asset,
                "response": response,
                "expected": True,
            },
        }
    )
    return False


def create_policy(api_client):
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


def add_asset_to_policy(api_client, asset):
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


def create_session(api_client):
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


def delete_session(api_client):
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


def generate_report(successful_tests, failed_tests):
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


def build_run_post_request(input_data, level):
    """
    Builds a request to run a post operation with the given input data and debug level.

    Args:
        input_data (dict): The input data for the run post request.
        level (str): The debug level for the request ("NONE", "ASSET_ONLY", "ALL").

    Returns:
        request: The built request object for running the post operation.
    """
    debug_level_to_int = {"NONE": 0, "ASSET_ONLY": 1, "ALL": 2}
    request = api_tester.RunPost_Request()
    request.name = SESSION_NAME
    request.trace_level = debug_level_to_int[level]
    request.message = json.dumps(input_data)
    request.queue = "1"
    request.location = "any"
    request.namespaces.extend([NAMESPACE])
    return request


def handle_response(
    id,
    expected,
    response,
    helper_name,
    description,
    asset,
    successful_tests,
    failure_tests,
):
    """
    Handles the response from an API call and categorizes it as either successful or failed.

    Args:
        id (str): The ID of the test case.
        expected (bool): Indicates whether the response status is expected to be successful or not.
        response (object): The response object returned from the API call.
        helper_name (str): The name of the helper function being tested.
        description (str): Description of the test case.
        asset (dict): The asset associated with the test case.
        successful_tests (list): A list to store successful test cases.
        failure_tests (list): A list to store failed test cases.
    """
    if (expected and response.status == api_engine.OK) or (
        not expected and response.status == api_engine.ERROR
    ):
        successful_tests.append({"helper": helper_name, "id": id})
    else:
        failure_tests.append(
            {
                "helper": helper_name,
                "id": id,
                "description": {
                    "message": description,
                    "asset": asset,
                    "response": response,
                    "expected": expected,
                },
            }
        )


def extract_event_from_response(response):
    """
    Extracts the event output from the response object.

    Args:
        response (object): The response object returned from the API call.

    Returns:
        dict: The event output extracted from the response.
    """
    response = json.loads(MessageToJson(response))
    return response["result"]["output"]


def extract_transformation_result_from_response(response):
    """
    Extracts the transformation result from the response object.

    Args:
        response (object): The response object returned from the API call.

    Returns:
        str: The transformation result extracted from the response.
    """
    response = json.loads(MessageToJson(response))
    regex = r"->\s*(Success|Failure)"
    match = re.search(regex, response["result"]
                      ["assetTraces"][0]["traces"][-1])
    if match:
        return match.group(1)
    return response["result"]["assetTraces"][0]["traces"][-1]


def handle_test_result(
    id,
    should_pass,
    expected,
    event,
    result,
    helper_name,
    description,
    asset,
    response,
    successful_tests,
    failure_tests,
    field_mapping=None,
    helper_type=None,
):
    """
    Handles the test result based on the helper type and other parameters.

    Args:
        id (str): The ID of the test case.
        should_pass (bool): Indicates whether the test is expected to pass.
        expected (any): The expected result of the test.
        event (dict): The event data to be tested.
        result (str): The result of the transformation.
        helper_name (str): The name of the helper function being tested.
        description (str): Description of the test case.
        asset (dict): The asset associated with the test case.
        response (object): The response object returned from the API call.
        successful_tests (list): A list to store successful test cases.
        failure_tests (list): A list to store failed test cases.
        field_mapping (str, optional): The field to be checked in the event.
        helper_type (str, optional): The type of helper function (e.g., "map", "filter", "transformation").
    """
    if should_pass is None:
        successful_tests.append({"helper": helper_name, "id": id})
        return

    if helper_type == "map":
        handle_map_test(
            should_pass,
            expected,
            event,
            helper_name,
            id,
            description,
            asset,
            response,
            successful_tests,
            failure_tests,
            field_mapping,
        )
    elif helper_type == "filter":
        handle_filter_test(
            should_pass,
            event,
            helper_name,
            id,
            description,
            asset,
            response,
            successful_tests,
            failure_tests,
            field_mapping,
        )
    elif helper_type == "transformation":
        handle_transformation_test(
            should_pass,
            expected,
            result,
            event,
            helper_name,
            id,
            description,
            asset,
            response,
            successful_tests,
            failure_tests,
            field_mapping,
        )
    else:
        # Handle other cases if necessary
        pass


def handle_map_test(
    should_pass,
    expected,
    event,
    helper_name,
    id,
    description,
    asset,
    response,
    successful_tests,
    failure_tests,
    field_mapping,
):
    """
    Handles the test result for "map" helper type.

    Args:
        should_pass (bool): Indicates whether the test is expected to pass.
        expected (any): The expected result of the test.
        event (dict): The event data to be tested.
        helper_name (str): The name of the helper function being tested.
        id (str): The ID of the test case.
        description (str): Description of the test case.
        asset (dict): The asset associated with the test case.
        response (object): The response object returned from the API call.
        successful_tests (list): A list to store successful test cases.
        failure_tests (list): A list to store failed test cases.
        field_mapping (str): The field to be checked in the event.
    """
    if (should_pass and field_mapping in event) or (
        not should_pass and field_mapping not in event
    ):
        if field_mapping in event:
            handle_map_event_with_field_mapping(
                should_pass,
                expected,
                event,
                field_mapping,
                helper_name,
                id,
                description,
                asset,
                response,
                successful_tests,
                failure_tests,
            )
        else:
            successful_tests.append({"helper": helper_name, "id": id})
    elif not should_pass and field_mapping in event:
        if expected:
            if event[field_mapping] != expected:
                successful_tests.append({"helper": helper_name, "id": id})
            else:
                failure_tests.append(
                    create_failure_test(
                        helper_name,
                        id,
                        description,
                        asset,
                        response,
                        should_pass,
                        expected,
                    )
                )
        else:
            failure_tests.append(
                create_failure_test(
                    helper_name,
                    id,
                    description,
                    asset,
                    response,
                    should_pass,
                    "expected is required",
                )
            )
    else:
        if expected is None:
            successful_tests.append({"helper": helper_name, "id": id})
        else:
            failure_tests.append(
                create_failure_test(
                    helper_name, id, description, asset, response, should_pass, expected
                )
            )


def handle_map_event_with_field_mapping(
    should_pass,
    expected,
    event,
    field_mapping,
    helper_name,
    id,
    description,
    asset,
    response,
    successful_tests,
    failure_tests,
):
    """
    Handles the test result for an event with field mapping.

    Args:
        should_pass (bool): Indicates whether the test is expected to pass.
        expected (any): The expected result of the test.
        event (dict): The event data to be tested.
        field_mapping (str): The field to be checked in the event.
        helper_name (str): The name of the helper function being tested.
        id (str): The ID of the test case.
        description (str): Description of the test case.
        asset (dict): The asset associated with the test case.
        response (object): The response object returned from the API call.
        successful_tests (list): A list to store successful test cases.
        failure_tests (list): A list to store failed test cases.
    """
    if expected:
        if event[field_mapping] == expected:
            successful_tests.append({"helper": helper_name, "id": id})
        else:
            failure_tests.append(
                create_failure_test(
                    helper_name, id, description, asset, response, should_pass, expected
                )
            )
    else:
        successful_tests.append({"helper": helper_name, "id": id})


def handle_filter_test(
    should_pass,
    event,
    helper_name,
    id,
    description,
    asset,
    response,
    successful_tests,
    failure_tests,
    field_mapping,
):
    """
    Handles the test result for "filter" helper type.

    Args:
        should_pass (bool): Indicates whether the test is expected to pass.
        event (dict): The event data to be tested.
        helper_name (str): The name of the helper function being tested.
        id (str): The ID of the test case.
        description (str): Description of the test case.
        asset (dict): The asset associated with the test case.
        response (object): The response object returned from the API call.
        successful_tests (list): A list to store successful test cases.
        failure_tests (list): A list to store failed test cases.
        field_mapping (str): The field to be checked in the event.
    """
    if (should_pass and field_mapping in event) or (
        not should_pass and field_mapping not in event
    ):
        successful_tests.append({"helper": helper_name, "id": id})
    else:
        failure_tests.append(
            create_failure_test(
                helper_name, id, description, asset, response, should_pass
            )
        )


def handle_transformation_test(
    should_pass,
    expected,
    result,
    event,
    helper_name,
    id,
    description,
    asset,
    response,
    successful_tests,
    failure_tests,
    field_mapping,
):
    """
    Handles the test result for "transformation" helper type.

    Args:
        should_pass (bool): Indicates whether the test is expected to pass.
        expected (any): The expected result of the test.
        result (str): The result of the transformation.
        event (dict): The event data to be tested.
        helper_name (str): The name of the helper function being tested.
        id (str): The ID of the test case.
        description (str): Description of the test case.
        asset (dict): The asset associated with the test case.
        response (object): The response object returned from the API call.
        successful_tests (list): A list to store successful test cases.
        failure_tests (list): A list to store failed test cases.
        field_mapping (str): The field to be checked in the event.
    """
    if (should_pass and result == "Success") or (
        not should_pass and result != "Success"
    ):
        if field_mapping in event:
            handle_map_event_with_field_mapping(
                should_pass,
                expected,
                event,
                field_mapping,
                helper_name,
                id,
                description,
                asset,
                response,
                successful_tests,
                failure_tests,
            )
        else:
            successful_tests.append({"helper": helper_name, "id": id})
    else:
        failure_tests.append(
            create_failure_test(
                helper_name, id, description, asset, response, should_pass, expected
            )
        )


def create_failure_test(helper_name, id, description, asset, response, should_pass, expected=None):
    """
    Creates a failure test case dictionary.

    Args:
        helper_name (str): The name of the helper function being tested.
        id (str): The ID of the test case.
        description (str): A description of the test case.
        asset (dict): The asset associated with the test case.
        response (object): The response object returned from the API call.
        should_pass (bool): Indicates whether the test is expected to pass.
        expected (any, optional): The expected result of the test.

    Returns:
        dict: A dictionary representing the failure test case.
    """
    failure_test = {
        "helper": helper_name,
        "id": id,
        "description": {
            "message": f"{description}: {expected}",
            "asset": asset,
            "response": response,
            "should_pass": should_pass,
            "expected": expected,
        },
    }
    return failure_test


def create_asset_for_buildtime(
    api_client,
    id,
    asset,
    helper_name,
    description,
    expected,
    successful_tests,
    failure_test,
    ignore=False,
):
    """
    Creates an asset for build-time testing and handles the response.

    Args:
        api_client (object): The API client used to make requests.
        id (str): The ID of the test case.
        asset (dict): The asset to be created.
        helper_name (str): The name of the helper function being tested.
        description (str): A description of the test case.
        expected (any): The expected result of the test.
        successful_tests (list): A list to store successful test cases.
        failure_test (list): A list to store failed test cases.
        ignore (bool, optional): If True, ignores handling the response.
    """
    request = build_asset_request(asset)
    error, response = send_recv(
        api_client, request, api_engine.GenericStatus_Response()
    )
    if not ignore:
        handle_response(
            id,
            expected,
            response,
            helper_name,
            description,
            asset,
            successful_tests,
            failure_test,
        )


def tester_run_map(
    api_client,
    id,
    input_data,
    level,
    field_mapping,
    should_pass,
    expected,
    helper_name,
    description,
    asset,
    successful_tests,
    failure_tests,
):
    """
    Runs a map test case and handles the result.

    Args:
        api_client (object): The API client used to make requests.
        id (str): The ID of the test case.
        input_data (dict): The input data for the test case.
        level (str): The debug level.
        field_mapping (str): The field to be checked in the event.
        should_pass (bool): Indicates whether the test is expected to pass.
        expected (any): The expected result of the test.
        helper_name (str): The name of the helper function being tested.
        description (str): A description of the test case.
        asset (dict): The asset associated with the test case.
        successful_tests (list): A list to store successful test cases.
        failure_tests (list): A list to store failed test cases.
    """
    request = build_run_post_request(input_data, level)
    error, response = send_recv(
        api_client, request, api_tester.RunPost_Response())
    event = extract_event_from_response(response)

    handle_test_result(
        id,
        should_pass,
        expected,
        event,
        None,
        helper_name,
        description,
        asset,
        response,
        successful_tests,
        failure_tests,
        field_mapping,
        helper_type="map",
    )


def tester_run_filter(
    api_client,
    id,
    input_data,
    level,
    field_mapping,
    should_pass,
    expected,
    helper_name,
    description,
    asset,
    successful_tests,
    failure_tests,
):
    """
    Runs a filter test case and handles the result.

    Args:
        api_client (object): The API client used to make requests.
        id (str): The ID of the test case.
        input_data (dict): The input data for the test case.
        level (str): The debug level.
        field_mapping (str): The field to be checked in the event.
        should_pass (bool): Indicates whether the test is expected to pass.
        expected (any): The expected result of the test.
        helper_name (str): The name of the helper function being tested.
        description (str): A description of the test case.
        asset (dict): The asset associated with the test case.
        successful_tests (list): A list to store successful test cases.
        failure_tests (list): A list to store failed test cases.
    """
    request = build_run_post_request(input_data, level)
    error, response = send_recv(
        api_client, request, api_tester.RunPost_Response())
    event = extract_event_from_response(response)

    handle_test_result(
        id,
        should_pass,
        expected,
        event,
        None,
        helper_name,
        description,
        asset,
        response,
        successful_tests,
        failure_tests,
        field_mapping,
        helper_type="filter",
    )


def tester_run_transformation(
    api_client,
    id,
    input_data,
    level,
    should_pass,
    expected,
    helper_name,
    description,
    asset,
    field_mapping,
    successful_tests,
    failure_test,
):
    """
    Runs a transformation test case and handles the result.

    Args:
        api_client (object): The API client used to make requests.
        id (str): The ID of the test case.
        input_data (dict): The input data for the test case.
        level (str): The debug level.
        should_pass (bool): Indicates whether the test is expected to pass.
        expected (any): The expected result of the test.
        helper_name (str): The name of the helper function being tested.
        description (str): A description of the test case.
        asset (dict): The asset associated with the test case.
        field_mapping (str): The field to be checked in the event.
        successful_tests (list): A list to store successful test cases.
        failure_test (list): A list to store failed test cases.
    """
    request = build_run_post_request(input_data, level)
    error, response = send_recv(
        api_client, request, api_tester.RunPost_Response())
    event = extract_event_from_response(response)
    result = extract_transformation_result_from_response(response)

    handle_test_result(
        id,
        should_pass,
        expected,
        event,
        result,
        helper_name,
        description,
        asset,
        response,
        successful_tests,
        failure_test,
        field_mapping=field_mapping,
        helper_type="transformation",
    )


def process_files_in_directory(directory, api_client, socket_path, successful_tests, failure_tests):
    """
    Process all files in the given directory.

    Args:
        directory (Path): The directory to process.
        api_client (object): The API client used to make requests.
        socket_path (str): The path to the socket.
        successful_tests (list): A list to store successful test cases.
        failure_tests (list): A list to store failed test cases.
    """
    for element in directory.iterdir():
        if element.is_dir():
            for file in element.iterdir():
                process_file(
                    file, api_client, socket_path, successful_tests, failure_tests
                )


def run_test(
    api_client,
    socket_path,
    helper_type,
    run_tests,
    helper_name,
    successful_tests,
    failure_tests,
):
    """
    Run buildtime, runtime and unit tests.

    Args:
        api_client (object): The API client used to make requests.
        socket_path (str): The path to the socket.
        helper_type (str): The type of helper.
        run_tests (list): List of tests to run.
        helper_name (str): The name of the helper.
        successful_tests (list): A list to store successful test cases.
        failure_tests (list): A list to store failed test cases.
    """
    for _, run_test in enumerate(run_tests):
        run_command(f"engine-clear -f --api-sock {socket_path}")
        delete_session(api_client)
        if "test_cases" not in run_test:
            execute_single_run_test(
                api_client,
                run_test,
                helper_type,
                helper_name,
                successful_tests,
                failure_tests,
            )
        else:
            execute_multiple_run_tests(
                api_client,
                run_test,
                helper_type,
                helper_name,
                successful_tests,
                failure_tests,
            )


def execute_single_run_test(api_client, run_test, helper_type, helper_name, successful_tests, failure_tests):
    create_asset_for_buildtime(
        api_client,
        run_test["id"],
        run_test["assets_definition"],
        helper_name,
        run_test["description"],
        run_test["should_pass"],
        successful_tests,
        failure_tests,
        True,
    )
    """
    Execute a single run test.

    Args:
        api_client (object): The API client used to make requests.
        run_test (dict): The configuration for the run test.
        helper_type (str): The type of helper.
        helper_name (str): The name of the helper.
        successful_tests (list): A list to store successful test cases.
        failure_tests (list): A list to store failed test cases.
    """
    create_policy(api_client)
    add_asset_to_policy(api_client, run_test["assets_definition"])
    create_session(api_client)

    if helper_type == "map":
        tester_run_map(
            api_client,
            run_test["id"],
            [],
            "NONE",
            "helper",
            run_test["should_pass"],
            run_test["expected"],
            helper_name,
            run_test["description"],
            run_test["assets_definition"],
            successful_tests,
            failure_tests,
        )
    elif helper_type == "filter":
        tester_run_filter(
            api_client,
            run_test["id"],
            [],
            "NONE",
            "verification_field",
            run_test["should_pass"],
            run_test.get("expected", None),
            helper_name,
            run_test["description"],
            run_test["assets_definition"],
            successful_tests,
            failure_tests,
        )
    else:
        tester_run_transformation(
            api_client,
            run_test["id"],
            [],
            "ALL",
            run_test["should_pass"],
            run_test.get("expected", None),
            helper_name,
            run_test["description"],
            run_test["assets_definition"],
            "target_field",
            successful_tests,
            failure_tests,
        )


def execute_multiple_run_tests(api_client, run_test, helper_type, helper_name, successful_tests, failure_tests):
    """
    Execute multiple run tests.

    Args:
        api_client (object): The API client used to make requests.
        run_test (dict): The configuration for the run test.
        helper_type (str): The type of helper.
        helper_name (str): The name of the helper.
        successful_tests (list): A list to store successful test cases.
        failure_tests (list): A list to store failed test cases.
    """
    for j, test_case in enumerate(run_test["test_cases"]):
        if j == 0:
            if not create_asset_for_runtime(
                api_client,
                run_test["assets_definition"],
                test_case.get("id"),
                helper_name,
                run_test["description"],
                failure_tests,
            ):
                break
            create_policy(api_client)
            add_asset_to_policy(api_client, run_test["assets_definition"])
            create_session(api_client)

        if helper_type == "map":
            tester_run_map(
                api_client,
                test_case.get("id"),
                test_case.get("input", []),
                "NONE",
                "helper",
                test_case.get("should_pass", None),
                test_case.get("expected", None),
                helper_name,
                run_test["description"],
                run_test["assets_definition"],
                successful_tests,
                failure_tests,
            )
        elif helper_type == "filter":
            tester_run_filter(
                api_client,
                test_case.get("id"),
                test_case.get("input", []),
                "NONE",
                "verification_field",
                test_case.get("should_pass", None),
                test_case.get("expected", None),
                helper_name,
                run_test["description"],
                run_test["assets_definition"],
                successful_tests,
                failure_tests,
            )
        else:
            tester_run_transformation(
                api_client,
                test_case.get("id"),
                test_case.get("input", []),
                "ALL",
                test_case.get("should_pass", None),
                test_case.get("expected", None),
                helper_name,
                run_test["description"],
                run_test["assets_definition"],
                "target_field",
                successful_tests,
                failure_tests,
            )


def process_file(file, api_client, socket_path, successful_tests, failure_tests):
    """
    Process a YAML file containing test configurations.

    Args:
        file (Path): The YAML file to process.
        api_client (object): The API client used to make requests.
        socket_path (str): The path to the socket.
        successful_tests (list): A list to store successful test cases.
        failure_tests (list): A list to store failed test cases.
    """
    helper_name = file.stem
    file_content = load_yaml(file)

    for build_test in file_content["build_test"]:
        run_command(f"engine-clear -f --api-sock {socket_path}")
        create_asset_for_buildtime(
            api_client,
            build_test["id"],
            build_test["assets_definition"],
            helper_name,
            build_test["description"],
            build_test["should_pass"],
            successful_tests,
            failure_tests,
        )

    run_tests = file_content.get("run_test", [])
    helper_type = file_content.get("helper_type", "")
    run_test(
        api_client,
        socket_path,
        helper_type,
        run_tests,
        helper_name,
        successful_tests,
        failure_tests,
    )


def run_test_cases_executor(api_client, socket_path):
    """
    Execute test cases found in YAML files in the current directory.

    Args:
        api_client (object): The API client used to make requests.
        socket_path (str): The path to the socket.
    """
    # Get the current directory
    current_dir = Path(__file__).resolve().parent

    successful_tests = []
    failure_tests = []

    for item in current_dir.iterdir():
        if item.is_dir():
            process_files_in_directory(item, api_client, socket_path, successful_tests, failure_tests)

    generate_report(successful_tests, failure_tests)

    if len(failure_tests) != 0:
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
