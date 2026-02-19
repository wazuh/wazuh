import json
import os
import subprocess
from typing import Optional, Tuple

from behave import given, when, then
from google.protobuf.json_format import MessageToJson, ParseDict

from api_communication.client import APIClient
from api_communication.proto import tester_pb2 as api_tester
from api_communication.proto import engine_pb2 as api_engine
from api_communication.proto import crud_pb2 as api_crud

# ===================================================================
#  Environment / API client
# ===================================================================

ENV_DIR = os.environ.get("ENV_DIR", "")
SOCKET_PATH = ENV_DIR + "/queue/sockets/engine-api.socket"

api_client = APIClient(SOCKET_PATH)

# ===================================================================
#  Constants shared with init.py
# ===================================================================

POLICY_NS = "testing"

DECODER_TEST_UUID = "2faeea8b-672b-4b42-8f91-657d7810d636"
DECODER_OTHER_UUID = "594ea807-a037-408d-95b8-9a124ea333df"

INTEG_WAZUH_CORE_UUID = "9b1a1ef2-1a70-4a8b-a89b-38b34174c2d1"
INTEG_OTHER_WAZUH_CORE_UUID = "a15bbd77-8cb0-488f-94cd-4783d689a72f"


# ===================================================================
#  Generic helpers
# ===================================================================

def run_command(command):
    result = subprocess.run(
        command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    assert result.returncode == 0, f"{result.stderr}"


def send_recv(request, expected_response_type) -> Tuple[Optional[str], object, dict]:
    """
    Generic helper for engine-api:
      - Returns (error_string, parsed_response, raw_output_dict)
      - error_string is None if status != ERROR
      - If status == ERROR, error_string = parsed_response.error
      - raw_output_dict preserves integer types from the original response (only for RunPost_Response)
    """
    error, response = api_client.send_recv(request)
    print(f"Request: {request}")
    print(f"Error: {error}")
    print(f"Response: {response}")
    assert error is None, f"{error}"

    parsed = ParseDict(response, expected_response_type)
    status = getattr(parsed, "status", None)
    if status == api_engine.ERROR:
        return parsed.error, parsed, {}

    # Preserve raw output with correct integer types for RunPost_Response
    raw_output = {}
    if isinstance(parsed, api_tester.RunPost_Response):
        raw_output = response.get('result', {}).get('output', {})

    return None, parsed, raw_output


# ===================================================================
#  CMCRUD helpers (policy only)
# ===================================================================

def build_policy_yaml(default_parent: str, root_decoder: str, integration_uuids):
    """
    Policy YAML according to the model:

      {
        "type": "policy",
        "title": "Development 0.0.1",
        "default_parent": "...",
        "root_decoder": "...",
        "integrations": [ ... ]
      }
    """
    integrations_block = "\n".join(f'  - "{u}"' for u in integration_uuids)
    return f"""\
type: policy
title: Development 0.0.1
hash: "tester-test-hash"
index_unclassified_events: true
default_parent: {default_parent}
root_decoder: {root_decoder}
integrations:
{integrations_block}
"""


def cm_policy_upsert(space: str, yml: str):
    req = api_crud.policyPost_Request()
    req.space = space
    req.ymlContent = yml
    err, resp, _ = send_recv(req, api_engine.GenericStatus_Response())
    assert err is None, f"Error upserting policy in '{space}': {err}"
    assert resp.status == api_engine.OK, f"{resp}"


def cm_policy_delete(space: str):
    req = api_crud.policyDelete_Request()
    req.space = space
    err, resp, _ = send_recv(req, api_engine.GenericStatus_Response())
    assert err is None, f"Error deleting policy '{space}': {err}"
    assert resp.status == api_engine.OK, f"{resp}"


def add_integration_to_policy(integration_name: str, policy_name: str):
    """
    "Add integration" is done as a policy upsert, leaving
    both integrations in the document.
    It is used in the scenario where sync becomes OUTDATED.
    """
    assert policy_name == POLICY_NS, "This step is intended for policy 'testing'"

    # We always leave the policy with both integrations
    integ_list = [INTEG_WAZUH_CORE_UUID, INTEG_OTHER_WAZUH_CORE_UUID]
    policy_yaml = build_policy_yaml(
        default_parent=DECODER_TEST_UUID,
        root_decoder=DECODER_TEST_UUID,
        integration_uuids=integ_list,
    )
    cm_policy_upsert(POLICY_NS, policy_yaml)


def delete_policy(policy_name: str):
    assert policy_name == POLICY_NS, "This step is intended for policy 'testing'"
    cm_policy_delete(POLICY_NS)


# ===================================================================
#  Tester helpers (sessions)
# ===================================================================

def create_session(session_name: str, policy_name: str) -> api_engine.GenericStatus_Response:
    """
    In the new tester, the session references the namespace/policy
    via namespaceId.
    """
    request = api_tester.SessionPost_Request()
    request.session.name = session_name
    request.session.namespaceId = policy_name
    _, response, _ = send_recv(request, api_engine.GenericStatus_Response())
    return response


def get_session(context, session_name: str):
    request = api_tester.SessionGet_Request()
    request.name = session_name
    error, context.result, _ = send_recv(request, api_tester.SessionGet_Response())
    assert error is None, f"{error}"


def session_tear_down():
    # Check if there are sessions to delete
    request = api_tester.TableGet_Request()
    error, response, _ = send_recv(request, api_tester.TableGet_Response())
    assert error is None, f"{error}"
    if len(response.sessions) == 0:
        return

    # Delete all sessions
    for session in response.sessions:
        req = api_tester.SessionDelete_Request()
        req.name = session.name
        _, _, _ = send_recv(req, api_engine.GenericStatus_Response())


# ===================================================================
#  GIVEN steps
# ===================================================================

@given('I have a policy "{policy_name}" that has an integration called "{integration_name}" loaded')
def step_impl(context, policy_name: str, integration_name: str):
    """
    - policy_name must be 'testing' (namespace/policy in CM)
    - integration_name: 'wazuh-core-test' or 'other-wazuh-core-test'
    Here we DO NOT create decoders or integrations (that is done by init.py),
    we only upsert the policy in CM with the corresponding integration.
    """
    assert policy_name == POLICY_NS, (
        f"Tester steps currently only support policy '{POLICY_NS}', got '{policy_name}'"
    )

    # Session cleanup so each scenario starts clean
    session_tear_down()

    if integration_name == "wazuh-core-test":
        integ_list = [INTEG_WAZUH_CORE_UUID]
        default_parent = DECODER_TEST_UUID
        root_decoder = DECODER_TEST_UUID
    elif integration_name == "other-wazuh-core-test":
        integ_list = [INTEG_OTHER_WAZUH_CORE_UUID]
        default_parent = DECODER_OTHER_UUID
        root_decoder = DECODER_OTHER_UUID
    else:
        raise AssertionError(f"Unsupported integration name: {integration_name}")

    policy_yaml = build_policy_yaml(
        default_parent=default_parent,
        root_decoder=root_decoder,
        integration_uuids=integ_list,
    )
    cm_policy_upsert(POLICY_NS, policy_yaml)


@given('I create a "{session_name}" session that points to policy "{policy_name}"')
def step_impl(context, session_name: str, policy_name: str):
    # Session cleanup
    session_tear_down()

    # Create the session pointing to namespaceId == policy_name
    response = create_session(session_name, policy_name)
    assert response.status == api_engine.OK, f"{response}"


# ===================================================================
#  WHEN steps
# ===================================================================

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
    error, context.result, _ = send_recv(request, api_engine.GenericStatus_Response())


@when('I send a request to the tester to get the session "{session_name}"')
def step_impl(context, session_name: str):
    get_session(context, session_name)


@when('I send a request to the policy "{policy_name}" to add an integration called "{integration_name}"')
def step_impl(context, policy_name: str, integration_name: str):
    # Update the policy in CM so that it has both integrations
    add_integration_to_policy(integration_name, policy_name)


@when('I send a request to delete the policy "{policy_name}"')
def step_impl(context, policy_name: str):
    delete_policy(policy_name)


@when('I send a request to send the event "{message}" from "{session_name}" session with "{debug_level}" debug, agent.id "{agent_id}" and "{asset_trace}" asset trace')
def step_impl(context, message: str, session_name: str, debug_level: str, agent_id: str, asset_trace: str):
    debug_level_to_int = {
        "NONE": 0,
        "ASSET_ONLY": 1,
        "ALL": 2
    }

    request = api_tester.RunPost_Request()
    request.name = session_name
    request.trace_level = debug_level_to_int[debug_level]
    LOCATION = f"[{agent_id}] (agent-ex) any->SomeModule"
    QUEUE = 1
    request.event = f"{QUEUE}:{LOCATION}:{message}"
    if not asset_trace == "ALL":
        request.asset_trace.extend([asset_trace])
    error, context.result, context.raw_output = send_recv(request, api_tester.RunPost_Response())
    assert error is None, f"{error}"


# ===================================================================
#  THEN steps
# ===================================================================

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
    error, response, _ = send_recv(request, api_tester.TableGet_Response())
    assert error is None, f"{error}"
    assert len(response.sessions) == int(size), f"{response.sessions}"


@then('I should receive a session with name "{session_name}"')
def step_impl(context, session_name: str):
    assert context.result.session.name == session_name, f"{context.result}"


@then('I should receive a session with sync "{policy_sync}"')
def step_impl(context, policy_sync: str):
    return


@then('I send a request to the tester to reload the "{session_name}" session and the sync change to "{policy_sync}" again')
def step_impl(context, session_name: str, policy_sync: str):
    request = api_tester.SessionReload_Request()
    request.name = session_name
    error, response, _ = send_recv(request, api_engine.GenericStatus_Response())
    assert error is None, f"{error}"

    get_session(context, session_name)


@then('I send a request to the tester to reload the "{session_name}"')
def step_impl(context, session_name: str):
    request = api_tester.SessionReload_Request()
    request.name = session_name
    error, context.result, _ = send_recv(
        request, api_engine.GenericStatus_Response()
    )


@then('I should receive an error response')
def step_impl(context):
    assert context.result.status == api_engine.ERROR, f"{context.result}"


@then('I should receive the next output: "{response}"')
def step_impl(context, response: str):
    """
    Compare the expected and actual JSON, ensuring:
      - the full wrapper is validated (e.g., assetTraces + output)
      - the output field uses raw dict to preserve integer types
    """
    # 1. Parse the expected wrapper
    expected_wrapper = json.loads(response)

    # 2. Build actual wrapper manually to preserve types
    from google.protobuf.json_format import MessageToDict
    actual_wrapper = {
        'output': context.raw_output  # Use raw dict instead of Struct
    }
    # Only include assetTraces if they exist
    if context.result.result.asset_traces:
        actual_wrapper['assetTraces'] = [MessageToDict(trace) for trace in context.result.result.asset_traces]

    # 3. Extract outputs
    expected_output = expected_wrapper.get('output', {})
    actual_output = actual_wrapper.get('output', {})

    # 4. Remove manager_name from both outputs
    expected_output.get('agent', {}).pop('manager_name', None)
    actual_output.get('agent', {}).pop('manager_name', None)

    # 5. Re-serialize with sorted keys
    def normalize(obj): return json.dumps(obj, sort_keys=True, separators=(",", ":"))
    expected_wrapper['output'] = normalize(expected_output)
    actual_wrapper['output'] = normalize(actual_output)

    # 6. Compare
    norm_expected = normalize(expected_wrapper)
    norm_actual = normalize(actual_wrapper)

    assert norm_actual == norm_expected, f"Responses do not match: {norm_actual} != {norm_expected}"
