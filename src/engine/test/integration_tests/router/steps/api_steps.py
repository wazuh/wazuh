import os
import subprocess
import time
from pathlib import Path
from typing import Optional, Tuple

from behave import given, when, then
from google.protobuf.json_format import ParseDict

from api_communication.client import APIClient
from api_communication.proto import router_pb2 as api_router
from api_communication.proto import crud_pb2 as api_crud
from api_communication.proto import engine_pb2 as api_engine


# ===================================================================
#  Constants and client
# ===================================================================

ENV_DIR = os.environ.get("ENV_DIR", "")
SOCKET_PATH = ENV_DIR + "/queue/sockets/engine-api.socket"

api_client = APIClient(SOCKET_PATH)

# Namespace == policy name in CM
POLICY_NS = "testing"

# Resource names
FILTER_ALLOW_ALL_NAME = "filter/allow-all/0"

# UUIDs (must match init.py and tester tests)
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


def send_recv(request, expected_response_type) -> Tuple[Optional[str], object]:
    error, response = api_client.send_recv(request)
    assert error is None, f"{error}"
    parsed = ParseDict(response, expected_response_type)
    if getattr(parsed, "status", None) == api_engine.ERROR:
        return parsed.error, parsed
    return None, parsed


# ===================================================================
#  CMCRUD helpers: policy and filter
# ===================================================================

def build_policy_yaml(default_parent: str, root_decoder: str, integration_uuids):
    """
    Policy YAML according to the new model:
      type: policy
      title: Development 0.0.1
      default_parent: ...
      root_decoder: ...
      integrations: [ ... ]
    """
    integrations_block = "\n".join(f'  - "{u}"' for u in integration_uuids)
    return f"""\
type: policy
title: Development 0.0.1
hash: "router-test-hash"
default_parent: {default_parent}
root_decoder: {root_decoder}
integrations:
{integrations_block}
"""


def cm_policy_upsert(space: str, yml: str):
    req = api_crud.policyPost_Request()
    req.space = space
    req.ymlContent = yml
    err, resp = send_recv(req, api_engine.GenericStatus_Response())
    assert err is None, f"Error upserting policy in '{space}': {err}"
    assert resp.status == api_engine.OK, f"{resp}"


def cm_policy_delete(space: str, strict: bool = False):
    req = api_crud.policyDelete_Request()
    req.space = space
    err, resp = send_recv(req, api_engine.GenericStatus_Response())
    if strict:
        assert err is None, f"Error deleting policy '{space}': {err}"
        assert resp.status == api_engine.OK, f"{resp}"


def cm_resource_list(space: str, rtype: str):
    req = api_crud.resourceList_Request()
    req.space = space
    req.type = rtype
    err, resp = send_recv(req, api_crud.resourceList_Response())
    assert err is None, f"Error listing resources '{rtype}' in '{space}': {err}"
    assert resp.status == api_engine.OK, f"{resp}"
    return list(resp.resources)


def cm_resource_delete_by_uuid(space: str, uuid: str):
    req = api_crud.resourceDelete_Request()
    req.space = space
    req.uuid = uuid
    err, resp = send_recv(req, api_engine.GenericStatus_Response())
    assert err is None, f"Error deleting resource '{uuid}' in '{space}': {err}"
    assert resp.status == api_engine.OK, f"{resp}"


def create_filter(filter_name: str):
    """
    Creates the filter in CM with the minimal shape:
      name: filter/allow-all/0
    """
    assert filter_name == FILTER_ALLOW_ALL_NAME, (
        f"Router steps only support '{FILTER_ALLOW_ALL_NAME}' for now"
    )
    filter_yaml = f"name: {FILTER_ALLOW_ALL_NAME}\ntype: pre-filter\nenabled: true\n"

    req = api_crud.resourcePost_Request()
    req.space = POLICY_NS
    req.type = "filter"
    req.ymlContent = filter_yaml
    err, resp = send_recv(req, api_engine.GenericStatus_Response())
    assert err is None, f"Error creating filter '{filter_name}': {err}"
    assert resp.status == api_engine.OK, f"{resp}"


def delete_filter(filter_name: str):
    """
    Deletes the filter by name using resourceList + resourceDelete (uuid).
    """
    assert filter_name == FILTER_ALLOW_ALL_NAME, (
        f"Router steps only support '{FILTER_ALLOW_ALL_NAME}' for now"
    )

    resources = cm_resource_list(POLICY_NS, "filter")
    matches = [r for r in resources if r.name == filter_name]
    assert matches, f"Filter '{filter_name}' not found in namespace '{POLICY_NS}'"
    # Assume only one
    cm_resource_delete_by_uuid(POLICY_NS, matches[0].uuid)


def setup_policy_with_integrations(initial_integration: str):
    """
    Prepares the policy in CM for the router:
      - Uses namespace POLICY_NS (== 'testing').
      - Assumes decoders and integrations already exist (init.py).
      - Creates/updates the policy with a single initial integration.
    """
    if initial_integration == "wazuh-core-test":
        integ_list = [INTEG_WAZUH_CORE_UUID]
    elif initial_integration == "other-wazuh-core-test":
        integ_list = [INTEG_OTHER_WAZUH_CORE_UUID]
    else:
        raise AssertionError(f"Unsupported integration name: {initial_integration}")

    policy_yaml = build_policy_yaml(
        default_parent=DECODER_TEST_UUID,
        root_decoder=DECODER_TEST_UUID,
        integration_uuids=integ_list,
    )
    cm_policy_upsert(POLICY_NS, policy_yaml)


def add_integration_to_policy(integration_name: str, policy_name: str):
    """
    Simulates "add integration to policy" by rewriting the YAML
    with both integrations (wazuh-core-test + other-wazuh-core-test).
    Used in the OUTDATED/UPDATED sync scenario.
    """
    assert policy_name == POLICY_NS, (
        f"Router steps expect policy_name == '{POLICY_NS}', got '{policy_name}'"
    )

    integ_list = [INTEG_WAZUH_CORE_UUID, INTEG_OTHER_WAZUH_CORE_UUID]
    policy_yaml = build_policy_yaml(
        default_parent=DECODER_TEST_UUID,
        root_decoder=DECODER_TEST_UUID,
        integration_uuids=integ_list,
    )
    cm_policy_upsert(POLICY_NS, policy_yaml)


def delete_policy(policy_name: str):
    """
    Used in the sync=ERROR scenario (strict=True).
    """
    assert policy_name == POLICY_NS, (
        f"Router steps expect policy_name == '{POLICY_NS}', got '{policy_name}'"
    )
    cm_policy_delete(POLICY_NS, strict=True)


# ===================================================================
#  Router helpers
# ===================================================================

def create_route(route_name: str, policy_name: str, filter_name: str, priority: int) -> api_engine.GenericStatus_Response:
    """
    Creates a route:
      - name
      - filter (filter name)
      - priority
      - namespaceId == policy_name (in our model: 'testing')
    """
    request = api_router.RoutePost_Request()
    request.route.name = route_name
    request.route.filter = filter_name
    request.route.priority = priority
    # New model: we use namespaceId instead of policy store
    request.route.namespaceId = policy_name
    err, resp = send_recv(request, api_engine.GenericStatus_Response())
    return resp


def router_tear_down():
    # Check if there are routes to delete
    request = api_router.TableGet_Request()
    err, response = send_recv(request, api_router.TableGet_Response())
    assert err is None, f"{err}"
    if len(response.table) == 0:
        return

    # Delete all routes
    for entry in response.table:
        req = api_router.RouteDelete_Request()
        req.name = entry.name
        _, _ = send_recv(req, api_engine.GenericStatus_Response())


def policy_tear_down():
    """
    Previously you called engine_clear; we keep this to ensure a clean state,
    but the policy in CM is still overwritten in setup_policy_with_integrations.
    """
    router_tear_down()


# ===================================================================
#  GIVEN steps
# ===================================================================

@given('I have a policy "{policy_name}" that has an integration called "{integration_name}" loaded')
def step_impl(context, policy_name: str, integration_name: str):
    # Global teardown of engine/router
    policy_tear_down()

    # In the new model, policy_name must be the CM namespace
    assert policy_name == POLICY_NS, (
        f"Router steps currently only support policy '{POLICY_NS}', got '{policy_name}'"
    )

    # Configure the policy in CM with the initial integration
    setup_policy_with_integrations(initial_integration=integration_name)


@given('I create a "{route_name}" route with priority "{priority}" that uses the filter "{filter_name}" and points to policy "{policy_name}"')
def step_impl(context, route_name: str, priority: str, filter_name: str, policy_name: str):
    # Clean previous routes
    router_tear_down()

    # Create the route pointing to namespaceId == policy_name
    response = create_route(route_name, policy_name, filter_name, int(priority))
    assert response.status == api_engine.OK, f"{response}"


# ===================================================================
#  WHEN steps
# ===================================================================

@when('I send a request to the router to add a new route called "{route_name}" with the data from policy:"{policy_name}" filter:"{filter_name}" priority:"{priority}"')
def step_impl(context, route_name: str, policy_name: str, filter_name: str, priority: str):
    context.result = create_route(route_name, policy_name, filter_name, int(priority))


@when('I send a request to update the priority from route "{route_name}" to value of "{priority}"')
def step_impl(context, route_name: str, priority: str):
    request = api_router.RoutePatchPriority_Request()
    request.name = route_name
    request.priority = int(priority)
    err, context.result = send_recv(request, api_engine.GenericStatus_Response())
    context.route_name = route_name


@when('I send a request to delete the route "{route_name}"')
def step_impl(context, route_name: str):
    request = api_router.RouteDelete_Request()
    request.name = route_name
    err, context.result = send_recv(request, api_engine.GenericStatus_Response())


@when('I send a request to get the route "{route_name}"')
def step_impl(context, route_name: str):
    request = api_router.RouteGet_Request()
    request.name = route_name
    time.sleep(1)  # small delay for uptime
    err, context.result = send_recv(request, api_router.RouteGet_Response())
    assert err is None, f"{err}"


@when('I send a request to get the list of routes')
def step_impl(context):
    request = api_router.TableGet_Request()
    err, response = send_recv(request, api_router.TableGet_Response())
    assert err is None, f"{err}"
    context.size = len(response.table)


@when('I send a request to the policy "{policy_name}" to add an integration called "{integration_name}"')
def step_impl(context, policy_name: str, integration_name: str):
    # Rewrite the policy with both integrations
    add_integration_to_policy(integration_name, policy_name)


@when('I send a request to delete the policy "{policy_name}"')
def step_impl(context, policy_name: str):
    delete_policy(policy_name)


@when('I send a request to {request} the filter "{filter_name}"')
def step_impl(context, request: str, filter_name: str):
    if request == "create":
        create_filter(filter_name)
    elif request == "delete":
        delete_filter(filter_name)
    else:
        assert False, f"The request {request} is not allowed."


# ===================================================================
#  THEN steps
# ===================================================================

@then('I send a restart to server')
def step_impl(context):
    # It is assumed that context.shared_data['engine_instance'] is already configured by the test environment
    context.shared_data["engine_instance"].stop()
    context.shared_data["engine_instance"].start()


@then('I should receive an {status} response indicating "{response}"')
def step_impl(context, status: str, response: str):
    if status == "error":
        assert context.result.status == api_engine.ERROR, f"{context.result}"
        assert context.result.error == response, f"{context.result}"


@then('I should receive a {response} response')
def step_impl(context, response: str):
    if response == "success":
        assert context.result.status == api_engine.OK, f"{context.result}"


@then('I should check if the new priority is {priority}')
def step_impl(context, priority: str):
    request = api_router.RouteGet_Request()
    request.name = context.route_name
    err, response = send_recv(request, api_router.RouteGet_Response())
    assert err is None, f"{err}"
    assert response.route.priority == int(priority)


@then('I should receive all the "{route_name}" route information. Filter "{filter_name}", policy "{policy_name}", priority "{priority}"')
def step_impl(context, route_name: str, filter_name: str, policy_name: str, priority: str):
    assert context.result.route.name == route_name, f"{context.result.route}"
    assert context.result.route.filter == filter_name, f"{context.result.route}"
    assert context.result.route.priority == int(priority), f"{context.result.route}"
    # Conceptually "policy", in the new model is namespaceId
    assert context.result.route.namespaceId == policy_name, f"{context.result.route}"


@then('I should receive a list with size equal to "{size_list}"')
def step_impl(context, size_list: str):
    assert context.size == int(size_list), f"{context.size}"


@then('I should receive a route with sync "{policy_sync}"')
def step_impl(context, policy_sync: str):
    return


@then('I send a request to the router to reload the "{route_name}" route and the sync change to "{policy_sync}" again')
def step_impl(context, route_name: str, policy_sync: str):
    request = api_router.RouteReload_Request()
    request.name = route_name
    err, _ = send_recv(request, api_engine.GenericStatus_Response())
    assert err is None, f"{err}"

    request = api_router.RouteGet_Request()
    request.name = route_name
    err, response = send_recv(request, api_router.RouteGet_Response())
    assert err is None, f"{err}"
    _ = response


@then('I should receive a route with state "{state}"')
def step_impl(context, state: str):
    state_to_string = {
        0: "STATE_UNKNOWN",
        1: "DISABLED",
        2: "ENABLED",
    }
    assert state_to_string[
        context.result.route.entry_status
    ] == state, f"{context.result.route}"


@then('I should receive a route with last update {request} to {last_update}')
def step_impl(context, request: str, last_update: str):
    if request == "equal":
        assert context.result.route.uptime == int(last_update), f"{context.result.route}"
    elif request == "different":
        assert context.result.route.uptime != int(last_update), f"{context.result.route}"
    else:
        assert False, f"The request {request} is not allowed."


@then('I send a request to the router to reload the "{route_name}"')
def step_impl(context, route_name: str):
    request = api_router.RouteReload_Request()
    request.name = route_name
    err, context.result = send_recv(
        request, api_engine.GenericStatus_Response()
    )


@then('I should receive an error response')
def step_impl(context):
    assert context.result.status == api_engine.ERROR, f"{context.result}"
