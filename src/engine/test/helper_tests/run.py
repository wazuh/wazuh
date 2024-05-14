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

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
WAZUH_DIR = os.path.realpath(os.path.join(SCRIPT_DIR, "../../../.."))
POLICY_NAME = "policy/wazuh/0"
ASSET_NAME = "decoder/test/0"
SESSION_NAME = "test"
NAMESPACE = "user"
only_failure = None
only_success = None


def send_recv(
    api_client, request, expected_response_type
) -> Tuple[Optional[str], dict]:
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
    global environment_directory
    global input_file
    global only_success
    global only_failure

    parser = argparse.ArgumentParser(description="Run Helpers test for Engine.")
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
    global environment_directory
    global WAZUH_DIR

    if not environment_directory:
        environment_directory = os.path.join(WAZUH_DIR, "environment")

    serv_conf_file = os.path.join(environment_directory, "engine", "general.conf")

    if not os.path.isdir(environment_directory):
        print(f"Error: Environment directory {environment_directory} not found.")
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
    try:
        return api_catalog.ResourceType.Value(string_value)
    except ValueError:
        return api_catalog.ResourceType.UNKNOWN


def string_to_resource_format(string_value):
    try:
        return api_catalog.ResourceFormat.Value(string_value)
    except ValueError:
        return api_catalog.ResourceFormat.json


def run_test_cases_generator():
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
                        subprocess.run(
                            ["python3", str(file), "--input_file", input_file]
                        )
                    else:
                        subprocess.run(["python3", str(file)])


def run_command(command):
    result = subprocess.run(
        command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    assert result.returncode == 0, f"{result.stderr}"


def create_asset_for_runtime(
    api_client, asset, id, helper_name, description, failed_tests
):
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
    request = api_policy.StorePost_Request()
    request.policy = POLICY_NAME
    error, response = send_recv(
        api_client, request, api_engine.GenericStatus_Response()
    )


def add_asset_to_policy(api_client, asset_name):
    request = api_policy.AssetPost_Request()
    request.policy = POLICY_NAME
    request.asset = asset_name
    request.namespace = NAMESPACE
    error, response = send_recv(
        api_client, request, api_engine.GenericStatus_Response()
    )

    assert response.status == api_engine.OK, f"{error}"


def create_session(api_client):
    request = api_tester.SessionPost_Request()
    request.session.name = SESSION_NAME
    request.session.policy = POLICY_NAME
    error, response = send_recv(
        api_client, request, api_engine.GenericStatus_Response()
    )

    assert response.status == api_engine.OK, f"{error}"


def delete_session(api_client):
    request = api_tester.SessionDelete_Request()
    request.name = SESSION_NAME
    error, response = send_recv(
        api_client, request, api_engine.GenericStatus_Response()
    )


def generate_report(successful_tests, failed_tests):
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
    request = api_catalog.ResourcePost_Request()
    request.type = string_to_resource_type("decoder")
    request.format = string_to_resource_format("json")
    request.content = json.dumps(asset)
    request.namespaceid = NAMESPACE
    return request


def update_asset_request(asset):
    request = api_catalog.ResourcePut_Request()
    request.name = ASSET_NAME
    request.format = string_to_resource_format("json")
    request.content = json.dumps(asset)
    request.namespaceid = NAMESPACE
    return request


def build_run_post_request(input_data, level):
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
    # print({"asset": asset, "response": response})
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
    response = json.loads(MessageToJson(response))
    return response["result"]["output"]


def extract_transformation_result_from_response(response):
    response = json.loads(MessageToJson(response))
    regex = r"->\s*(Success|Failure)"
    match = re.search(regex, response["result"]["assetTraces"][0]["traces"][-1])
    return match.group(1)


def handle_test_result(
    id,
    expected,
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
    if expected != None:
        if helper_type == "map_filter":
            if (expected and field_mapping in result) or (
                not expected and field_mapping not in result
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
        elif helper_type == "transformation":
            if (expected and result == "Success") or (
                not expected and result != "Success"
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
        else:
            # Handle other cases if necessary
            pass
    else:
        successful_tests.append({"helper": helper_name, "id": id})


def create_asset_for_buildtime(
    api_client,
    id,
    asset,
    helper_name,
    description,
    expected,
    successful_tests,
    failure_test,
):
    request = build_asset_request(asset)
    error, response = send_recv(
        api_client, request, api_engine.GenericStatus_Response()
    )
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


def update_asset(
    api_client,
    id,
    asset,
    helper_name,
    description,
    expected,
    successful_tests,
    failure_test,
):
    request = update_asset_request(asset)
    error, response = send_recv(
        api_client, request, api_engine.GenericStatus_Response()
    )
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


def tester_run_map_filter(
    api_client,
    id,
    input_data,
    level,
    field_mapping,
    expected,
    helper_name,
    description,
    asset,
    successful_tests,
    failure_tests,
):
    request = build_run_post_request(input_data, level)
    error, response = send_recv(api_client, request, api_tester.RunPost_Response())
    event = extract_event_from_response(response)

    handle_test_result(
        id,
        expected,
        event,
        helper_name,
        description,
        asset,
        response,
        successful_tests,
        failure_tests,
        field_mapping,
        helper_type="map_filter",
    )


def tester_run_transformation(
    api_client,
    id,
    input_data,
    level,
    expected,
    helper_name,
    description,
    asset,
    successful_tests,
    failure_test,
):
    request = build_run_post_request(input_data, level)
    error, response = send_recv(api_client, request, api_tester.RunPost_Response())
    result = extract_transformation_result_from_response(response)

    handle_test_result(
        id,
        expected,
        result,
        helper_name,
        description,
        asset,
        response,
        successful_tests,
        failure_test,
        helper_type="transformation",
    )


def run_test_cases_executor(api_client, socket_path):
    # Get the current directory
    current_dir = Path(__file__).resolve().parent

    successful_tests = []
    failure_tests = []

    # Iterate over all items in the current directory
    for item in current_dir.iterdir():
        # Check if the item is a directory
        if item.is_dir():
            # Get the list of files in the directory
            elements = item.iterdir()
            for element in elements:
                if element.is_dir():
                    files = element.iterdir()
                    for file in files:
                        helper_name = file.stem
                        for i, build_tests in enumerate(load_yaml(file)["build_test"]):
                            if i == 0:
                                create_asset_for_buildtime(
                                    api_client,
                                    build_tests["id"],
                                    build_tests["assets_definition"],
                                    helper_name,
                                    build_tests["description"],
                                    build_tests["should_pass"],
                                    successful_tests,
                                    failure_tests,
                                )
                            else:
                                update_asset(
                                    api_client,
                                    build_tests["id"],
                                    build_tests["assets_definition"],
                                    helper_name,
                                    build_tests["description"],
                                    build_tests["should_pass"],
                                    successful_tests,
                                    failure_tests,
                                )
                        for _, run_tests in enumerate(load_yaml(file)["run_test"]):
                            run_command(f"engine-clear -f --api-sock {socket_path}")
                            delete_session(api_client)
                            helper_type = load_yaml(file)["helper_type"]

                            for j, test_case in enumerate(run_tests["test_cases"]):
                                if j == 0:
                                    if not create_asset_for_runtime(
                                        api_client,
                                        run_tests["assets_definition"],
                                        test_case.get("id"),
                                        helper_name,
                                        run_tests["description"],
                                        failure_tests,
                                    ):
                                        break
                                    create_policy(api_client)
                                    add_asset_to_policy(
                                        api_client,
                                        run_tests["assets_definition"]["name"],
                                    )
                                    create_session(api_client)
                                if helper_type == "map" or helper_type == "filter":
                                    tester_run_map_filter(
                                        api_client,
                                        test_case.get("id"),
                                        test_case.get("input", []),
                                        "NONE",
                                        "helper",
                                        test_case.get("should_pass", None),
                                        helper_name,
                                        run_tests["description"],
                                        run_tests["assets_definition"],
                                        successful_tests,
                                        failure_tests,
                                    )

                                elif helper_type == "transformation":
                                    tester_run_transformation(
                                        api_client,
                                        test_case.get("id"),
                                        test_case.get("input", []),
                                        "ALL",
                                        test_case.get("should_pass", None),
                                        helper_name,
                                        run_tests["description"],
                                        run_tests["assets_definition"],
                                        successful_tests,
                                        failure_tests,
                                    )
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
    os.environ["WAZUH_DIR"] = os.path.realpath(os.path.join(SCRIPT_DIR, "../../../.."))
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
