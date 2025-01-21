import json
import os
import subprocess
from typing import Optional, Tuple
from behave import given, when, then
from google.protobuf.json_format import MessageToJson
from pathlib import Path

from api_communication.client import APIClient
from google.protobuf.json_format import ParseDict
from api_communication.proto import tester_pb2 as api_tester
from api_communication.proto import policy_pb2 as api_policy
from api_communication.proto import engine_pb2 as api_engine
from api_communication.proto import catalog_pb2 as api_catalog
from api_utils.commands import engine_clear

ENGINE_DIR = os.environ.get("ENGINE_DIR", "")
ENV_DIR = os.environ.get("ENV_DIR", "")
SOCKET_PATH = ENV_DIR + "/queue/sockets/engine-api.socket"
RULESET_DIR = ENV_DIR + "/engine"

api_client = APIClient(SOCKET_PATH)


def run_command(command):
    result = subprocess.run(
        command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert result.returncode == 0, f"{result.stderr}"


def send_recv(request, expected_response_type) -> Tuple[Optional[str], dict]:
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


def add_integration(integration_name: str):
    namespace = "system"
    integration_path = Path(RULESET_DIR).resolve() / integration_name
    assert integration_path.is_dir(
    ), f"Integration {integration_name} not found"
    asset_types = {
        "decoders": api_catalog.decoder,
        "rules": api_catalog.rule,
        "outputs": api_catalog.output,
        "filters": api_catalog.filter
    }

    for directory, asset_type in asset_types.items():
        path = integration_path / directory
        if path.is_dir():
            for asset_file in path.rglob("*.yml"):
                request = api_catalog.ResourcePost_Request()
                request.namespaceid = namespace
                request.content = asset_file.read_text()
                request.format = api_catalog.yaml
                request.type = asset_type

                error, response = api_client.send_recv(request)
                assert error is None, f"{error}"
                parsed_response = ParseDict(
                    response, api_engine.GenericStatus_Response())
                assert parsed_response.status == api_engine.OK, f"{parsed_response}"

    # Add manifest
    manifest_file = integration_path / "manifest.yml"
    assert manifest_file.is_file(
    ), f"Manifest file not found for integration {integration_name}"
    request = api_catalog.ResourcePost_Request()
    request.namespaceid = namespace
    request.content = manifest_file.read_text()
    request.format = api_catalog.yaml
    request.type = api_catalog.integration

    error, response = api_client.send_recv(request)
    assert error is None, f"{error}"
    parsed_response = ParseDict(response, api_engine.GenericStatus_Response())
    assert parsed_response.status == api_engine.OK, f"{parsed_response}"


def create_policy(policy_name: str):
    request = api_policy.StorePost_Request()
    request.policy = policy_name
    error, response = send_recv(request, api_engine.GenericStatus_Response())
    assert error is None, f"{error}"


def delete_policy(policy_name: str):
    request = api_policy.StoreDelete_Request()
    request.policy = policy_name
    error, response = send_recv(request, api_engine.GenericStatus_Response())


def add_integration_to_policy(integration_name: str, policy_name: str):
    request = api_policy.AssetPost_Request()
    request.policy = policy_name
    request.asset = f"integration/{integration_name}/0"
    request.namespace = "system"
    error, response = send_recv(request, api_policy.AssetPost_Response())
    assert error is None, f"{error}"


def policy_tear_down(policy_name: str, integration_name: str):
    engine_clear(api_client)


def create_session(session_name: str, policy_name: str) -> api_engine.GenericStatus_Response:
    request = api_tester.SessionPost_Request()
    request.session.name = session_name
    request.session.policy = policy_name
    error, response = send_recv(request, api_engine.GenericStatus_Response())
    return response


def get_session(context, session_name: str):
    request = api_tester.SessionGet_Request()
    request.name = session_name
    error, context.result = send_recv(
        request, api_tester.SessionGet_Response())
    assert error is None, f"{error}"


def session_tear_down():
    # Check if there are sessions to delete
    request = api_tester.TableGet_Request()
    error, response = send_recv(request, api_tester.TableGet_Response())
    assert error is None, f"{error}"
    if len(response.sessions) == 0:
        return

    # Delete all sessions
    for session in response.sessions:
        request = api_tester.SessionDelete_Request()
        request.name = session.name
        error, response = send_recv(
            request, api_engine.GenericStatus_Response())


@given('I have a policy "{policy_name}" that has an integration called "{integration_name}" loaded')
def step_impl(context, policy_name: str, integration_name: str):
    # TearDown
    policy_tear_down(policy_name, integration_name)

    # Setup
    add_integration(integration_name)
    create_policy(policy_name)
    add_integration_to_policy(integration_name, policy_name)


@given('I create a "{session_name}" session that points to policy "{policy_name}"')
def step_impl(context, session_name: str, policy_name: str):
    # TearDown
    session_tear_down()

    # Setup
    create_session(session_name, policy_name)


@when('I send a request to the tester to add a new session called "{session_name}" with the data from policy:"{policy_name}"')
def step_impl(context, session_name: str, policy_name: str):
    context.result = create_session(session_name, policy_name)


@when('I send a request to the tester to add {sessions} sessions called "{session_name}" with policy "{policy_name}"')
def step_impl(context, sessions: str, session_name: str, policy_name: str):
    for i in range(int(sessions)):
        create_session(session_name + str(i), policy_name)


@when('I send a request to the tester to delete the session "{session_name}"')
def step_impl(context, session_name: str):
    request = api_tester.SessionDelete_Request()
    request.name = session_name
    error, context.result = send_recv(
        request, api_engine.GenericStatus_Response())


@when('I send a request to the tester to get the session "{session_name}"')
def step_impl(context, session_name: str):
    get_session(context, session_name)


@when('I send a request to the policy "{policy_name}" to add an integration called "{integration_name}"')
def step_impl(context, policy_name: str, integration_name: str):
    add_integration(integration_name)
    add_integration_to_policy(integration_name, policy_name)


@when('I send a request to delete the policy "{policy_name}"')
def step_impl(context, policy_name: str):
    delete_policy(policy_name)


@when('I send a request to send the event "{message}" from "{session_name}" session with "{debug_level}" debug "{namespace}" namespace, agent.name "{queue_char}" and "{asset_trace}" asset trace')
def step_impl(context, message: str, session_name: str, debug_level: str, queue_char: str, namespace: str, asset_trace: str):
    debug_level_to_int = {
        "NONE": 0,
        "ASSET_ONLY": 1,
        "ALL": 2
    }

    json_event : dict = {
        "event": {
            "original": {
                "message": message
            }
        }
    }
    header_json_event : dict = {
        "agent": {
            "name": "header-agent",
            "id": queue_char
        }
    }
    subheader_json_event : dict = {
        "collector": "file",
        "module": "logcollector"
    }
    str_json_event = json.dumps(json_event, separators=(",", ":"))
    str_header_json_event = json.dumps(header_json_event, separators=(",", ":"))
    str_subheader_json_event = json.dumps(subheader_json_event, separators=(",", ":"))

    request = api_tester.RunPost_Request()
    request.name = session_name
    request.trace_level = debug_level_to_int[debug_level]
    request.ndjson_event = str_header_json_event + "\n" + str_subheader_json_event + "\n" + str_json_event
    request.namespaces.extend([namespace])
    request.asset_trace.extend([asset_trace])
    error, context.result = send_recv(request, api_tester.RunPost_Response())
    assert error is None, f"{error}"


@then('I should receive a {status} response indicating that "{message}"')
def step_impl(context, status: str, message: str):
    if status == "failture":
        assert context.result.status == api_engine.ERROR, f"{context.result}"
        assert context.result.error == message, f"{context.result}"


@then('I should receive a {status} response')
def step_impl(context, status: str):
    if status == "success":
        assert context.result.status == api_engine.OK, f"{context.result}"


@then('I should receive a size list of {size}')
def step_impl(context, size: str):
    request = api_tester.TableGet_Request()
    error, response = send_recv(request, api_tester.TableGet_Response())
    assert error is None, f"{error}"
    assert len(response.sessions) == int(size), f"{response.sessions}"


@then('I should receive a session with name "{session_name}"')
def step_impl(context, session_name: str):
    assert context.result.session.name == session_name, f"{context.result}"


@then('I should receive a session with sync "{policy_sync}"')
def step_impl(context, policy_sync: str):
    policy_sync_to_string = {
        0: "SYNC_UNKNOWN",
        1: "UPDATED",
        2: "OUTDATED",
        3: "ERROR"
    }
    assert policy_sync_to_string[
        context.result.session.policy_sync] == policy_sync, f"{context.result.session.policy_sync}"


@then('I send a request to the tester to reload the "{session_name}" session and the sync change to "{policy_sync}" again')
def step_impl(context, session_name: str, policy_sync: str):
    request = api_tester.SessionReload_Request()
    request.name = session_name
    error, response = send_recv(request, api_engine.GenericStatus_Response())
    assert error is None, f"{error}"

    get_session(context, session_name)

    policy_sync_to_string = {
        0: "SYNC_UNKNOWN",
        1: "UPDATED",
        2: "OUTDATED",
        3: "ERROR"
    }
    assert policy_sync_to_string[
        context.result.session.policy_sync] == policy_sync, f"{context.result.session.policy_sync}"


@then('I send a request to the tester to reload the "{session_name}"')
def step_impl(context, session_name: str):
    request = api_tester.SessionReload_Request()
    request.name = session_name
    error, context.result = send_recv(
        request, api_engine.GenericStatus_Response())


@then('I should receive an error response')
def step_impl(context):
    assert context.result.status == api_engine.ERROR, f"{context.result}"


@then('I should receive the next output: "{response}"')
def step_impl(context, response: str):
    # Load expected and actual JSON responses
    expected_response = json.loads(response)
    actual_response = json.loads(MessageToJson(context.result.result))

    # Normalize and compare JSON strings
    normalized_expected = json.dumps(
        expected_response, sort_keys=True, separators=(",", ":"))
    normalized_actual = json.dumps(
        actual_response, sort_keys=True, separators=(",", ":"))

    assert normalized_actual == normalized_expected, f"Responses do not match: {normalized_actual} != {normalized_expected}"
