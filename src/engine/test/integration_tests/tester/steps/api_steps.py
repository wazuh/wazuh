from api_communication.client import APIClient
from google.protobuf.json_format import ParseDict
from api_communication.proto import tester_pb2 as api_tester
from api_communication.proto import kvdb_pb2 as api_kvdb
from api_communication.proto import policy_pb2 as api_policy
from api_communication.proto import engine_pb2 as api_engine

from behave import given, when, then
from google.protobuf.json_format import MessageToJson
import json
import os
import subprocess
from typing import Optional, Tuple

ENGINE_DIR = os.environ.get("ENGINE_DIR", "")
ENV_DIR = os.environ.get("ENV_DIR", "")
SOCKET_PATH = ENV_DIR + "/queue/sockets/engine-api"
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
    command = f"engine-integration add -a {SOCKET_PATH} -n system {RULESET_DIR}/{integration_name}/"
    run_command(command)

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
    # Remove policy "policy_name"
    delete_policy(policy_name)

    # Delete all assets and kvdbs
    command = f"engine-clear -f --api-sock {SOCKET_PATH}"
    run_command(command)

def create_session(session_name: str, policy_name: str) -> api_engine.GenericStatus_Response:
    request = api_tester.SessionPost_Request()
    request.session.name = session_name
    request.session.policy = policy_name
    error, response = send_recv(request, api_engine.GenericStatus_Response())
    return response

def get_session(context, session_name: str):
    request = api_tester.SessionGet_Request()
    request.name = session_name
    error, context.result = send_recv(request, api_tester.SessionGet_Response())
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
        error, response = send_recv(request, api_engine.GenericStatus_Response())

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
    error, context.result = send_recv(request, api_engine.GenericStatus_Response())

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

@when('I send a request to send the event "{message}" from "{session_name}" session with "{debug_level}" debug "{namespace}" namespace, queue "{queue_char}" and "{asset_trace}" asset trace')
def step_impl(context, message: str, session_name: str, debug_level: str, queue_char: str, namespace: str, asset_trace: str):
    debug_level_to_int = {
        "NONE": 0,
        "ASSET_ONLY": 1,
        "ALL": 2
    }
    request = api_tester.RunPost_Request()
    request.name = session_name
    request.trace_level = debug_level_to_int[debug_level]
    request.message = message
    request.queue = queue_char
    request.location = "any"
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
    assert len(response.sessions)  == int(size), f"{response.sessions}"

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
    assert policy_sync_to_string[context.result.session.policy_sync] == policy_sync, f"{context.result.session.policy_sync}"

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
    assert policy_sync_to_string[context.result.session.policy_sync] == policy_sync, f"{context.result.session.policy_sync}"

@then('I send a request to the tester to reload the "{session_name}"')
def step_impl(context, session_name: str):
    request = api_tester.SessionReload_Request()
    request.name = session_name
    error, context.result = send_recv(request, api_engine.GenericStatus_Response())

@then('I should receive an error response')
def step_impl(context):
    assert context.result.status == api_engine.ERROR, f"{context.result}"

@then('I should receive the next output: "{response}"')
def step_impl(context, response: str):
    # Load expected and actual JSON responses
    expected_response = json.loads(response)
    actual_response = json.loads(MessageToJson(context.result.result))

    # Normalize and compare JSON strings
    normalized_expected = json.dumps(expected_response, sort_keys=True, separators=(",", ":"))
    normalized_actual = json.dumps(actual_response, sort_keys=True, separators=(",", ":"))

    assert normalized_actual == normalized_expected, f"Responses do not match: {normalized_actual} != {normalized_expected}"
