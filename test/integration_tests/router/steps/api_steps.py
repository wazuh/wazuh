import os
import subprocess
from pathlib import Path
from behave import given, when, then
from typing import Optional, Tuple
from google.protobuf.json_format import ParseDict

from api_communication.client import APIClient
from api_communication.proto import router_pb2 as api_router
from api_communication.proto import catalog_pb2 as api_catalog
from api_communication.proto import kvdb_pb2 as api_kvdb
from api_communication.proto import policy_pb2 as api_policy
from api_communication.proto import engine_pb2 as api_engine
from api_utils.commands import engine_clear
import time

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


def create_filter(filter_name: str):
    request = api_catalog.ResourcePost_Request()
    request.type = "filter"
    request.format = "yaml"
    # Load content from file
    with open(f"{RULESET_DIR}/wazuh-core-test/filters/allow-all.yml", "r") as f:
        request.content = f.read()
    request.namespaceid = "system"
    error, response = send_recv(request, api_engine.GenericStatus_Response())
    assert error is None, f"{error}"


def delete_filter(filter_name: str):
    request = api_catalog.ResourceDelete_Request()
    request.name = filter_name
    request.namespaceid = "system"
    error, response = send_recv(request, api_engine.GenericStatus_Response())
    assert error is None, f"{error}"


def create_route(route_name: str, policy_name: str, filter_name: str, priority: int) -> api_engine.GenericStatus_Response:
    request = api_router.RoutePost_Request()
    request.route.name = route_name
    request.route.filter = filter_name
    request.route.priority = priority
    request.route.policy = policy_name
    error, response = send_recv(request, api_engine.GenericStatus_Response())
    return response


def router_tear_down():
    # Check if there are routes to delete
    request = api_router.TableGet_Request()
    error, response = send_recv(request, api_router.TableGet_Response())
    assert error is None, f"{error}"
    if len(response.table) == 0:
        return

    # Delete all routes
    for entry in response.table:
        request = api_router.RouteDelete_Request()
        request.name = entry.name
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


@given('I create a "{route_name}" route with priority "{priority}" that uses the filter "{filter_name}" and points to policy "{policy_name}"')
def step_impl(context, route_name: str, policy_name: str, filter_name: str, priority: str):
    # TearDown
    router_tear_down()

    # Setup
    create_route(route_name, policy_name, filter_name, int(priority))


@when('I send a request to the router to add a new route called "{route_name}" with the data from policy:"{policy_name}" filter:"{filter_name}" priority:"{priority}"')
def step_impl(context, route_name: str, policy_name: str, filter_name: str, priority: str):
    context.result = create_route(
        route_name, policy_name, filter_name, int(priority))


@when('I send a request to update the priority from route "{route_name}" to value of "{priority}"')
def step_impl(context, route_name: str, priority: str):
    request = api_router.RoutePatchPriority_Request()
    request.name = route_name
    request.priority = int(priority)
    error, context.result = send_recv(
        request, api_engine.GenericStatus_Response())
    context.route_name = route_name


@when('I send a request to delete the route "{route_name}"')
def step_impl(context, route_name: str):
    request = api_router.RouteDelete_Request()
    request.name = route_name
    error, context.result = send_recv(
        request, api_engine.GenericStatus_Response())


@when('I send a request to get the route "{route_name}"')
def step_impl(context, route_name: str):
    request = api_router.RouteGet_Request()
    request.name = route_name
    time.sleep(1) # need for uptime
    error, context.result = send_recv(request, api_router.RouteGet_Response())
    assert error is None, f"{error}"


@when('I send a request to get the list of routes')
def step_impl(context):
    request = api_router.TableGet_Request()
    error, response = send_recv(request, api_router.TableGet_Response())
    assert error is None, f"{error}"
    context.size = len(response.table)


@when('I send a request to the policy "{policy_name}" to add an integration called "{integration_name}"')
def step_impl(context, policy_name: str, integration_name: str):
    add_integration(integration_name)
    add_integration_to_policy(integration_name, policy_name)


@when('I send a request to delete the policy "{policy_name}"')
def step_impl(context, policy_name: str):
    delete_policy(policy_name)


@when('I send a request to {request} the filter "{filter_name}"')
def step_impl(context, request: str, filter_name: str):
    if request == 'create':
        create_filter(filter_name)
    elif request == 'delete':
        delete_filter(filter_name)
    else:
        assert f"The request {request} is not allowed."

@then('I send a restart to server')
def step_impl(context):
    context.shared_data['engine_instance'].stop()
    context.shared_data['engine_instance'].start()


@then('I should receive an {status} response indicating "{response}"')
def step_impl(context, status: str, response: str):
    if status == "error":
        assert context.result.status == api_engine.ERROR, f"{context.result}"
        assert context.result.error == response, f"{context.result}"


@then('I should receive a {response} response')
def step_impl(context, response: str):
    if (response == "success"):
        assert context.result.status == api_engine.OK, f"{context.result}"


@then('I should check if the new priority is {priority}')
def step_impl(context, priority: str):
    request = api_router.RouteGet_Request()
    request.name = context.route_name
    error, response = send_recv(request, api_router.RouteGet_Response())
    assert error is None, f"{error}"
    assert response.route.priority == int(priority)


@then('I should receive all the "{route_name}" route information. Filter "{filter_name}", policy "{policy_name}", priority "{priority}"')
def step_impl(context, route_name: str, filter_name: str, policy_name: str, priority: str):
    assert context.result.route.name == route_name, f"{context.result.route}"
    assert context.result.route.filter == filter_name, f"{context.result.route}"
    assert context.result.route.priority == int(
        priority), f"{context.result.route}"
    assert context.result.route.policy == policy_name, f"{context.result.route}"


@then('I should receive a list with size equal to "{size_list}"')
def step_impl(context, size_list: str):
    assert context.size == int(size_list), f"{context.size}"


@then('I should receive a route with sync "{policy_sync}"')
def step_impl(context, policy_sync: str):
    policySyncToString = {
        0: "SYNC_UNKNOWN",
        1: "UPDATED",
        2: "OUTDATED",
        3: "ERROR"
    }
    assert policySyncToString[
        context.result.route.policy_sync] == policy_sync, f"{context.result.route}"


@then('I send a request to the router to reload the "{route_name}" route and the sync change to "{policy_sync}" again')
def step_impl(context, route_name: str, policy_sync: str):
    request = api_router.RouteReload_Request()
    request.name = route_name
    error, response = send_recv(request, api_engine.GenericStatus_Response())
    assert error is None, f"{error}"

    request = api_router.RouteGet_Request()
    request.name = route_name
    error, response = send_recv(request, api_router.RouteGet_Response())
    assert error is None, f"{error}"

    policySyncToString = {
        0: "SYNC_UNKNOWN",
        1: "UPDATED",
        2: "OUTDATED",
        3: "ERROR"
    }
    assert policySyncToString[
        response.route.policy_sync] == policy_sync, f"{response.route}"


@then('I should receive a route with state "{state}"')
def step_impl(context, state: str):
    state_to_string = {
        0: "STATE_UNKNOWN",
        1: "DISABLED",
        2: "ENABLED"
    }
    assert state_to_string[
        context.result.route.entry_status] == state, f"{context.result.route}"


@then('I should receive a route with last update {request} to {last_update}')
def step_impl(context, request: str, last_update: str):
    if request == 'equal':
        assert context.result.route.uptime == int(last_update), f"{context.result.route}"
    elif request == 'different':
        assert context.result.route.uptime != int(last_update), f"{context.result.route}"
    else:
        assert f"The request {request} is not allowed."

@then('I send a request to the router to reload the "{route_name}"')
def step_impl(context, route_name: str):
    request = api_router.RouteReload_Request()
    request.name = route_name
    error, context.result = send_recv(
        request, api_engine.GenericStatus_Response())


@then('I should receive an error response')
def step_impl(context):
    assert context.result.status == api_engine.ERROR, f"{context.result}"
