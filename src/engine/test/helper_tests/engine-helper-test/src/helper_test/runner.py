#!/usr/bin/env python3

import json
import re
import subprocess
import sys
import yaml
from pathlib import Path
from typing import Optional

from google.protobuf.json_format import MessageToJson, ParseDict
from google.protobuf.message import Message

from api_communication.client import APIClient
from api_communication.proto import crud_pb2 as api_crud
from api_communication.proto import engine_pb2 as api_engine
from api_communication.proto import tester_pb2 as api_tester
from engine_handler.handler import EngineHandler

# ===================================================================
#  Constants
# ===================================================================

# Namespace / policy used for helpers tests
POLICY_NS = "testing"
POLICY_NAME = POLICY_NS  # kept for compatibility

# Helpers decoder
ASSET_NAME = "decoder/test/0"

# Tester session name
SESSION_NAME = "test"

# Namespace used in RunPost (namespaces list)
NAMESPACE = POLICY_NS

QUEUE = 1
LOCATION = "[agent-id] (agent-ex) any->SomeModule"

# Fixed UUIDs (valid v4) for decoder and its integration
HELPERS_DECODER_UUID = "7a2d5a4b-4e6b-4dcb-8e4a-5c6e0c7a9f11"
HELPERS_INTEG_UUID   = "e9d1a9c3-8f2b-4a6a-9f4b-2c6d5e7f2b10"

# KVDB resource UUID in CM
KVDB_RESOURCE_UUID = "3c7d9b5e-2f4a-4b6a-9c1d-8e7a2b4c5d10"


# ===================================================================
#  CLI
# ===================================================================

def configure(subparsers):
    """
    Configure the 'run' subcommand for executing helper tests.
    """
    parser = subparsers.add_parser(
        "run",
        help="Runs the generated test cases and validates their results",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--input-file",
        help="Absolute or relative path to the test case file",
    )
    group.add_argument(
        "--input-dir",
        help="Absolute or relative path to the directory containing test case files",
    )
    parser.add_argument(
        "--show-failure",
        help="Shows only the failure test cases that occurred",
        action="store_true",
    )

    parser.set_defaults(func=run)


def load_yaml(file_path: str) -> dict:
    """
    Load a YAML file and return its contents as a Python dict.
    """
    with open(file_path, "r") as stream:
        try:
            return yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            raise Exception(f"Error loading YAML file: {exc}")


# ===================================================================
#  Evaluator
# ===================================================================

class Evaluator:
    """
    Helper class that collects and evaluates test case results.
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
        self.id = id

    def set_helper_name(self, helper_name: str):
        self.helper_name = helper_name

    def set_description(self, description: str):
        self.description = description

    def set_asset_definition(self, asset: str):
        self.asset = asset

    def set_should_pass(self, should_pass: bool):
        self.should_pass = should_pass

    def set_skipped(self, skipped: bool):
        self.skipped = skipped

    def set_expected(self, expected: str):
        self.expected = expected

    def set_helper_type(self, helper_type: str):
        self.helper_type = helper_type

    def set_input(self, input: list):
        self.input = input

    def create_failure_test(self, response):
        """
        Register a failed test case with extended context.
        """
        if json.loads(MessageToJson(response)).get("result"):
            output = json.loads(MessageToJson(response))["result"]["output"]
            json_response = json.loads(output).get(self.field_mapping)
        else:
            json_response = None

        failure_test = {
            "helper": self.helper_name,
            "id": self.id,
            "description": json.dumps(
                {
                    "message": f"{self.description}",
                    "asset": self.asset,
                    "all_response": json.loads(MessageToJson(response)),
                    "should_pass": self.should_pass,
                    "expected": self.expected,
                    "response": json_response,
                }
            ),
        }

        self.failure.append(failure_test)

    def create_success_test(self):
        """
        Register a successful test case (minimal data).
        """
        success_test = {
            "helper": self.helper_name,
            "id": self.id,
        }
        self.successful.append(success_test)

    def check_response(self, response: dict) -> None:
        """
        Check a GenericStatus-like response and classify as success/failure
        according to should_pass and skipped.
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
        Validate a map helper test case that expects a specific field mapping.
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
        Validate a transform helper test case that expects a specific field mapping.
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
        Execute a tester run for a map helper and evaluate the result.
        """
        self.field_mapping = field_mapping
        request = build_run_post_request(self.input, api_tester.ALL)
        response, raw_output = send_recv(api_client, request, api_tester.RunPost_Response())
        output = raw_output

        if not self.skipped:
            if (self.should_pass and field_mapping in output) or (
                not self.should_pass and field_mapping not in output
            ):
                if field_mapping in output:
                    self.handle_map_event_with_field_mapping(
                        response, output, field_mapping
                    )
                else:
                    self.create_success_test()
            else:
                self.create_failure_test(response)
        else:
            self.create_success_test()

    def tester_run_filter(self, api_client: APIClient, field_mapping: str):
        """
        Execute a tester run for a filter helper and evaluate based on presence/absence
        of the given field.
        """
        self.field_mapping = field_mapping
        request = build_run_post_request(self.input, api_tester.ALL)
        response, raw_output = send_recv(api_client, request, api_tester.RunPost_Response())
        output = raw_output

        if not self.skipped:
            if (self.should_pass and field_mapping in output) or (
                not self.should_pass and field_mapping not in output
            ):
                self.create_success_test()
            else:
                self.create_failure_test(response)
        else:
            self.create_success_test()

    def tester_run_transform(self, api_client: APIClient, field_mapping: str):
        """
        Execute a tester run for a transform helper and validate:
          - transformation trace (Success/Failure)
          - optional expected value in field_mapping
        """
        self.field_mapping = field_mapping
        request = build_run_post_request(self.input, api_tester.ALL)
        response, raw_output = send_recv(api_client, request, api_tester.RunPost_Response())
        output = raw_output
        result = extract_transformation_result_from_response(
            response, self.helper_name
        )

        if not self.skipped:
            if (self.should_pass and result == "Success") or (
                not self.should_pass and result != "Success"
            ):
                if field_mapping in output:
                    self.handle_transform_event_with_field_mapping(
                        response, output, field_mapping
                    )
                else:
                    self.create_success_test()
            else:
                self.create_failure_test(response)
        else:
            self.create_success_test()


# ===================================================================
#  Generic helpers
# ===================================================================

def run_command(command: str):
    result = subprocess.run(
        command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    assert result.returncode == 0, f"{result.stderr}"


def send_recv(api_client: APIClient, request: Message, expected_response_type: Message):
    """
    Send a request through APIClient and parse the response into expected_response_type.
    Raises on transport or parsing errors.
    
    Returns:
      - For RunPost_Response: tuple (Message, dict) where dict is raw_output with preserved types
      - For other types: Message
    """
    try:
        error, response = api_client.send_recv(request)
        assert error is None, f"{error}"
        parse_response: Message = ParseDict(response, expected_response_type)
        
        # Preserve raw output with correct integer types for RunPost_Response
        if isinstance(parse_response, api_tester.RunPost_Response):
            raw_output = response.get('result', {}).get('output', {})
            return parse_response, raw_output
        
        return parse_response
    except Exception as e:
        raise Exception(f"Error parsing response: {e}")


# ===================================================================
#  CM / Policy / Tester helpers
# ===================================================================

def list_namespaces(api_client: APIClient):
    """
    Return the list of existing namespace spaces via namespaceGet.
    """
    req = api_crud.namespaceGet_Request()
    resp = send_recv(api_client, req, api_crud.namespaceGet_Response())
    return list(resp.spaces)


def create_namespace(api_client: APIClient):
    """
    Ensure POLICY_NS exists. If it already exists, do nothing.
    """
    spaces = list_namespaces(api_client)
    if POLICY_NS in spaces:
        return

    req = api_crud.namespacePost_Request()
    req.space = POLICY_NS
    response = send_recv(api_client, req, api_engine.GenericStatus_Response())
    assert response.status == api_engine.OK, f"{response.error}"


def delete_namespace(api_client: APIClient):
    """
    Delete POLICY_NS. This is kept for potential full teardown,
    but is not used in normal per-file setup anymore.
    """
    req = api_crud.namespaceDelete_Request()
    req.space = POLICY_NS
    response = send_recv(api_client, req, api_engine.GenericStatus_Response())
    assert response.status == api_engine.OK, f"{response.error}"


def build_asset_request(asset: dict) -> api_crud.resourcePost_Request:
    """
    Build a resourcePost request for a decoder in engine-cm.

    We enforce:
      - name = ASSET_NAME
      - id   = HELPERS_DECODER_UUID
    so that the integration can reference the decoder by UUID.
    """
    asset = dict(asset)  # copy to avoid mutating original

    asset["name"] = ASSET_NAME
    asset["id"] = HELPERS_DECODER_UUID
    asset["enabled"] = True

    yml = yaml.safe_dump(asset, sort_keys=False)

    req = api_crud.resourcePost_Request()
    req.space = POLICY_NS
    req.type = "decoder"
    req.ymlContent = yml
    return req


def create_asset_for_runtime(api_client: APIClient, result_evaluator: Evaluator) -> bool:
    """
    Create a decoder in runtime (in POLICY_NS) and evaluate the result
    according to should_pass and skipped.
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


def create_asset_for_buildtime(api_client: APIClient, result_evaluator: Evaluator):
    """
    Create a decoder for build-time tests in POLICY_NS and classify
    the result using Evaluator.check_response.
    """
    request = build_asset_request(result_evaluator.asset)
    response = send_recv(api_client, request, api_engine.GenericStatus_Response())
    result_evaluator.check_response(response)


def delete_asset(api_client: APIClient):
    """
    Delete the helpers decoder (if present) in POLICY_NS by UUID.
    No error if it doesn't exist.
    """
    req = api_crud.resourceDelete_Request()
    req.space = POLICY_NS
    req.uuid = HELPERS_DECODER_UUID
    api_client.send_recv(req)


def delete_integration(api_client: APIClient):
    """
    Delete the helpers integration (if present) in POLICY_NS by UUID.
    No error if it doesn't exist.
    """
    req = api_crud.resourceDelete_Request()
    req.space = POLICY_NS
    req.uuid = HELPERS_INTEG_UUID
    api_client.send_recv(req)


def create_helpers_integration(api_client: APIClient):
    """
    Create/update the helpers integration that references the helpers decoder
    and associates the KVDB resource.
    The policy will be built solely from integrations.
    """
    integration_yaml = f"""\
id: {HELPERS_INTEG_UUID}
title: helpers-test
enabled: true
category: other
default_parent: {HELPERS_DECODER_UUID}
decoders:
  - "{HELPERS_DECODER_UUID}"
kvdbs:
  - "{KVDB_RESOURCE_UUID}"
"""
    req = api_crud.resourcePost_Request()
    req.space = POLICY_NS
    req.type = "integration"
    req.ymlContent = integration_yaml
    response = send_recv(api_client, req, api_engine.GenericStatus_Response())
    assert response.status == api_engine.OK, f"{response.error}"


def create_policy(api_client: APIClient):
    """
    Create/update the policy in engine-cm, in namespace POLICY_NS.

    The policy is defined solely in terms of integrations:
      - default_parent and root_decoder point to the helpers decoder (ASSET_NAME),
      - the integrations list contains HELPERS_INTEG_UUID.
    """
    policy_yaml = f"""\
type: policy
title: Helpers Testing Policy
default_parent: {HELPERS_DECODER_UUID}
root_decoder: {HELPERS_DECODER_UUID}
integrations:
  - "{HELPERS_INTEG_UUID}"
"""
    req = api_crud.policyPost_Request()
    req.space = POLICY_NS
    req.ymlContent = policy_yaml
    response = send_recv(api_client, req, api_engine.GenericStatus_Response())
    assert response.status == api_engine.OK, f"{response.error}"


def delete_policy(api_client: APIClient):
    """
    Delete the policy in namespace POLICY_NS (if it exists).
    """
    req = api_crud.policyDelete_Request()
    req.space = POLICY_NS
    api_client.send_recv(req)


def create_session(api_client: APIClient):
    """
    Create a tester session pointing to namespaceId = POLICY_NS.
    """
    request = api_tester.SessionPost_Request()
    request.session.name = SESSION_NAME
    request.session.namespaceId = POLICY_NS
    response = send_recv(api_client, request, api_engine.GenericStatus_Response())
    assert response.status == api_engine.OK, f"{response.error}"


def delete_session(api_client: APIClient):
    """
    Delete the tester session SESSION_NAME (best-effort).
    """
    request = api_tester.SessionDelete_Request()
    request.name = SESSION_NAME
    api_client.send_recv(request)


def create_kvdb_resource(api_client: APIClient):
    """
    Create or update a KVDB resource in POLICY_NS using valid JSON content.
    """

    kvdb_json = {
        "id": KVDB_RESOURCE_UUID,
        "date": "2025-10-06T13:32:19Z",
        "title": "windows_kerberos_status_code_to_code_name",
        "author": "Wazuh Inc.",
        "content": {

            "0x0": "KDC_ERR_NONE",
            "0x1": "KDC_ERR_NAME_EXP",
            "0x2": "KDC_ERR_SERVICE_EXP",
            "0x3": "KDC_ERR_BAD_PVNO",
            "0x4": "KDC_ERR_C_OLD_MAST_KVNO",
            "0x5": "KDC_ERR_S_OLD_MAST_KVNO",
            "0x6": "KDC_ERR_C_PRINCIPAL_UNKNOWN",


            "bitmask_test_values": [0, 1, 2, 3, 4, 16, 17, 18, 19, 20, 24, 28, 29, 30, 31],


            "access_mask": {
                "0": "Create Child",
                "1": "Delete Child",
                "2": "List Contents",
                "3": "SELF",
                "4": "Read Property",
                "5": "Write Property",
                "6": "Delete Tree",
                "7": "List Object",
                "8": "Control Access",
                "16": "DELETE",
                "17": "READ_CONTROL",
                "18": "WRITE_DAC",
                "19": "WRITE_OWNER",
                "20": "SYNCHRONIZE",
                "24": "ADS_RIGHT_ACCESS_SYSTEM_SECURITY",
                "31": "ADS_RIGHT_GENERIC_READ",
                "30": "ADS_RIGHT_GENERIC_WRITE",
                "29": "ADS_RIGHT_GENERIC_EXECUTE",
                "28": "ADS_RIGHT_GENERIC_ALL"
            },
        },
        "enabled": True,
    }

    req = api_crud.resourcePost_Request()
    req.space = POLICY_NS
    req.type = "kvdb"
    # api_crud.resourcePost_Request expects YAML/JSON as string in ymlContent
    req.ymlContent = json.dumps(kvdb_json, separators=(",", ":"))

    response = send_recv(api_client, req, api_engine.GenericStatus_Response())
    assert response.status == api_engine.OK, f"{response.error}"


def delete_kvdb_resource(api_client: APIClient):
    """
    Delete the KVDB resource by UUID in POLICY_NS (best-effort).
    """
    req = api_crud.resourceDelete_Request()
    req.space = POLICY_NS
    req.uuid = KVDB_RESOURCE_UUID
    api_client.send_recv(req)


# ===================================================================
#  Report generation
# ===================================================================

def generate_report(successful_tests: list, failed_tests: list, show_failure: bool) -> str:
    """
    Build a human-readable report of all executed tests.
    """
    report = "## Test Report\n\n"
    report += "### General Summary\n\n"
    report += f"- Total test cases executed: {len(successful_tests) + len(failed_tests)}\n"
    report += f"- Successful test cases: {len(successful_tests)}\n"
    report += f"- Failed test cases: {len(failed_tests)}\n\n"

    if successful_tests and not show_failure:
        report += "#### Successful Test Cases\n\n"
        for i, success_test in enumerate(successful_tests, start=1):
            report += f"{i}. **Test Case {i}**\n"
            report += f"   - Helper: {success_test['helper']}\n"
            report += f"   - Id: {success_test['id']}\n"

    if failed_tests:
        report += "#### Failed Test Cases\n\n"
        for i, failed_test in enumerate(failed_tests, start=1):
            report += f"{i}. **Test Case {i}**\n"
            report += f"   - Helper: {failed_test['helper']}\n"
            report += f"   - Id: {failed_test['id']}\n"
            report += f"   - Description: {failed_test['description']}\n"
    return report


# ===================================================================
#  Tester Run helpers
# ===================================================================

def build_run_post_request(input_data: dict, level: api_tester.TraceLevel) -> api_tester.RunPost_Request:
    """
    Build a tester RunPost request using the global SESSION_NAME and
    the helpers location/queue constants.
    """
    request = api_tester.RunPost_Request()
    request.name = SESSION_NAME
    request.trace_level = level
    request.event = f"{QUEUE}:{LOCATION}:{json.dumps(input_data, separators=(',', ':'))}"
    return request


def extract_output_from_response(response: dict) -> dict:
    """
    Extract the 'output' field (JSON string) from the RunPost response
    and parse it as a Python dict.
    """
    response = json.loads(MessageToJson(response))
    return json.loads(response["result"]["output"])


def get_target_trace(traces: list, helper_name: str, count=1) -> Optional[str]:
    """
    Return the nth trace (count) that contains helper_name, or None if not found.
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
    Parse the RunPost response and extract the 'Success'/'Failure' result
    from the asset trace for the given helper_name.
    """
    response = json.loads(MessageToJson(response))
    # Take the first asset trace as the asset is unique
    traces = response["result"]["assetTraces"][0]["traces"]
    if helper_name != "parse_json":
        target_trace = get_target_trace(traces, helper_name)
    else:
        # Ignore the first parse_json trace (event.original)
        target_trace = get_target_trace(traces, helper_name, count=2)

    if target_trace:
        regex = r"->\s*(Success|Failure)"
        match = re.search(regex, target_trace)
        if match:
            return match.group(1)
    return None


# ===================================================================
#  Test execution
# ===================================================================

def execute_single_run_test(api_client: APIClient, run_test: dict, result_evaluator: Evaluator):
    """
    Execute a single run_test block (no test_cases array).
    """
    result_evaluator.set_id(run_test["id"])
    result_evaluator.set_should_pass(run_test.get("should_pass", None))
    result_evaluator.set_expected(run_test.get("expected"))
    result_evaluator.set_skipped(run_test.get("skipped", False))
    result_evaluator.set_description(run_test["description"])
    result_evaluator.set_input([])

    # Create runtime decoder
    if create_asset_for_runtime(api_client, result_evaluator):
        # Integration that references the decoder and KVDB
        create_helpers_integration(api_client)
        # Policy based only on integrations
        create_policy(api_client)
        # Tester session bound to the namespace/policy
        create_session(api_client)

        if result_evaluator.helper_type == "map":
            result_evaluator.tester_run_map(api_client, "helper")
        elif result_evaluator.helper_type == "filter":
            result_evaluator.tester_run_filter(api_client, "verification_field")
        elif result_evaluator.helper_type == "transformation":
            result_evaluator.tester_run_transform(api_client, "target_field")
        else:
            raise Exception(
                f"Helper type '{result_evaluator.helper_type}' is not valid"
            )


def execute_multiple_run_tests(api_client: APIClient, run_test: dict, result_evaluator: Evaluator):
    """
    Execute a run_test block that contains a test_cases array.
    The first test_case sets up decoder + integration + policy + session.
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
                break
            create_helpers_integration(api_client)
            create_policy(api_client)
            create_session(api_client)

        if result_evaluator.helper_type == "map":
            result_evaluator.tester_run_map(api_client, "helper")
        elif result_evaluator.helper_type == "filter":
            result_evaluator.tester_run_filter(api_client, "verification_field")
        elif result_evaluator.helper_type == "transformation":
            result_evaluator.tester_run_transform(api_client, "target_field")
        else:
            raise Exception(
                f"Helper type '{result_evaluator.helper_type}' is not valid"
            )


def process_file(file: Path, api_client: APIClient, result_evaluator: Evaluator, kvdb_path: str):
    """
    Process a single YAML test file:
      - ensure namespace exists,
      - run build_test then run_test sections.
    kvdb_path is currently unused (KVDB is injected as a CM resource).
    """
    file_content = load_yaml(file)
    result_evaluator.set_helper_name(file.stem)

    # Ensure namespace exists (do not recreate if it is already there)
    create_namespace(api_client)

    # Build-time tests
    for build_test in file_content.get("build_test", []):
        result_evaluator.set_id(build_test["id"])
        result_evaluator.set_asset_definition(build_test["assets_definition"])
        result_evaluator.set_should_pass(build_test["should_pass"])
        result_evaluator.set_description(build_test["description"])
        result_evaluator.set_skipped(build_test.get("skipped", False))

        # Tear down
        delete_session(api_client)
        delete_policy(api_client)
        delete_asset(api_client)
        delete_integration(api_client)
        delete_kvdb_resource(api_client)

        # Setup
        create_kvdb_resource(api_client)
        create_asset_for_buildtime(api_client, result_evaluator)

    # Run-time tests
    for run_test in file_content.get("run_test", []):
        result_evaluator.set_helper_type(file_content["helper_type"])
        result_evaluator.set_asset_definition(run_test["assets_definition"])

        # Tear down
        delete_session(api_client)
        delete_policy(api_client)
        delete_asset(api_client)
        delete_integration(api_client)
        delete_kvdb_resource(api_client)

        # Setup
        create_kvdb_resource(api_client)

        if "test_cases" not in run_test:
            execute_single_run_test(api_client, run_test, result_evaluator)
        else:
            execute_multiple_run_tests(api_client, run_test, result_evaluator)


def run_test_cases_executor(input_path: Path, api_client: APIClient, kvdb_path: str) -> Evaluator:
    """
    Execute all test files under input_path (or the single file if input_path is a file).
    """
    print("Running test cases...")
    result_evaluator = Evaluator()

    if input_path.is_file():
        print(f"Processing file: {input_path}")
        process_file(input_path, api_client, result_evaluator, kvdb_path)
    else:
        for file in input_path.rglob("*.yml"):
            print(f"Processing file: {file}")
            process_file(file, api_client, result_evaluator, kvdb_path)
    print("Test cases executed.")

    return result_evaluator


# ===================================================================
#  Main runner
# ===================================================================

def runner(input_path: Path, env_dir: Path, show_failure: bool):
    """
    Validate paths, start an engine instance, run all tests, print report,
    and stop the engine.
    """
    engine_handler = Optional[EngineHandler]
    success = True

    print("Validating parameters...")
    bin_path = (env_dir / "wazuh-engine").resolve()
    if not bin_path.is_file():
        raise FileNotFoundError(f"Binary file not found: {bin_path}")

    config_path = (env_dir / "config.env").resolve()
    if not config_path.is_file():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    kvdb_path = env_dir / "tmp" / "kvdb_test.json"
    if not kvdb_path.is_file():
        raise FileNotFoundError(f"KVDB file not found: {kvdb_path}")

    if not input_path.exists():
        raise FileNotFoundError(f"Input path not found: {input_path}")

    if input_path.is_dir() and not list(input_path.rglob("*.yml")):
        raise FileNotFoundError(
            f"No YAML files found in directory: {input_path}"
        )
    print("Parameters validated.")

    try:
        print("Starting Engine instance...")
        engine_handler = EngineHandler(
            bin_path.as_posix(), config_path.as_posix()
        )
        engine_handler.start()
        print("Engine started.")

        result = run_test_cases_executor(
            input_path, engine_handler.api_client, kvdb_path.as_posix()
        )

        if len(result.failure) != 0:
            success = False

        print("Generating report...")
        report = generate_report(result.successful, result.failure, show_failure)
        print(report)

        print("Stopping Engine instance...")
        engine_handler.stop()
        print("Engine stopped.")

    except Exception:
        if engine_handler:
            print("Stopping Engine instance...")
            engine_handler.stop()
            print("Engine stopped.")
        raise

    if not success:
        raise Exception("Some test cases failed.")


def run(args):
    """
    Entrypoint for the CLI subcommand configured by configure().
    """
    input_file = Path(args.get("input_file")).resolve() if args.get("input_file") else None
    input_dir = Path(args.get("input_dir")).resolve() if args.get("input_dir") else None
    env_dir = Path(args.get("environment")).resolve()
    show_failure = args.get("show_failure")

    try:
        runner(input_file or input_dir, env_dir, show_failure)
    except Exception as e:
        print(e)
        sys.exit(1)

    sys.exit(0)
