from api_communication.client import APIClient
from google.protobuf.json_format import ParseDict
from api_communication.proto import router_pb2 as api_router
from api_communication.proto import catalog_pb2 as api_catalog
from api_communication.proto import kvdb_pb2 as api_kvdb
from api_communication.proto import policy_pb2 as api_policy
from api_communication.proto import engine_pb2 as api_engine

from behave import given, when, then
import os
import subprocess

ENGINE_DIR = os.environ.get("ENGINE_DIR", "")
ENV_DIR = os.environ.get("ENV_DIR", "")
SOCKET_PATH = ENV_DIR + "/queue/sockets/engine-api"
RULESET_DIR = ENV_DIR + "/engine"

api_client = APIClient(SOCKET_PATH)


# First Scenario


@given('I am authenticated with the router API "{name}"')
def step_impl(context, name: str):
    # Check if the policy exists, if not, create it
    request = api_policy.PoliciesGet_Request()
    err, response = api_client.send_recv(request)
    if err:
        context.result = err
        print(err)
        assert False

    policy_resp = ParseDict(response, api_policy.PoliciesGet_Response())
    if policy_resp.status == api_engine.ERROR or len(policy_resp.data) == 0:
        request = api_kvdb.managerDelete_Request()
        request.name = "agents_host_data"
        err, response = api_client.send_recv(request)
        if err:
            context.result = err
            print(err)
            assert False
        command = f"engine-integration add -a {SOCKET_PATH} -n system {RULESET_DIR}/wazuh-core-test/"
        result = subprocess.run(
            command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert result.returncode == 0, f"{result.stderr}"

        request = api_policy.StorePost_Request()
        request.policy = "policy/wazuh/0"
        err, response = api_client.send_recv(request)
        if err:
            context.result = err
            print(err)
            assert False

        request = api_policy.AssetPost_Request()
        request.policy = "policy/wazuh/0"
        request.asset = "integration/wazuh-core-test/0"
        request.namespace = "system"
        err, response = api_client.send_recv(request)
        if err:
            context.result = err
            print(err)
            assert False

    # Check if the filter exists, if not, create it
    request = api_catalog.ResourceGet_Request()
    request.name = "filter/allow-all/0"
    request.format = "json"
    request.namespaceid = "system"
    err, response = api_client.send_recv(request)
    if err:
        context.result = err
        print(err)
        assert False

    filter_resp = ParseDict(response, api_catalog.ResourceGet_Response())
    if filter_resp.status == api_engine.ERROR or len(filter_resp.content) == 0:
        request = api_catalog.ResourcePost_Request()
        request.type = "filter"
        request.format = "yaml"
        # Load content from file
        with open(f"{RULESET_DIR}/wazuh-core-test/filters/allow-all.yml", "r") as f:
            request.content = f.read()
        request.namespaceid = "system"
        err, response = api_client.send_recv(request)
        if err:
            context.result = err
            print(err)
            assert False

    # Check if the route exists, if not, create it
    request = api_router.RouteGet_Request()
    request.name = name
    err, response = api_client.send_recv(request)
    if err:
        context.result = err
        print(err)
        assert False

    route_resp = ParseDict(response, api_router.RouteGet_Response())
    if route_resp.status != api_engine.OK:
        request = api_router.RoutePost_Request()
        request.route.name = "default"
        request.route.filter = "filter/allow-all/0"
        request.route.priority = 255
        request.route.policy = "policy/wazuh/0"
        err, response = api_client.send_recv(request)
        if err:
            context.result = err
            print(err)
            assert False


@when('I send a request to the router to add a new route called "{route}" with the data from policy:"{policy}" filter:"{filter}" priority:"{priority}"')
def step_impl(context, route: str, policy: str, filter: str, priority: str):
    post = api_router.RoutePost_Request()
    post.route.name = route
    post.route.filter = filter
    post.route.priority = int(priority)
    post.route.policy = policy
    err, response = api_client.send_recv(post)
    assert err is None, f"{err}"
    context.result = ParseDict(response, api_engine.GenericStatus_Response())


@then('I should receive an {response} response indicating that the policy already exists')
def step_impl(context, response: str):
    if response == "error":
        route_response: api_engine.GenericStatus_Response = context.result
        assert route_response.status == api_engine.ERROR, f"{route_response}"


# Second Scenario
@when('I send a request to update the priority from route "{name}" to value of "{priority}"')
def step_impl(context, name: str, priority: str):
    patch = api_router.RoutePatchPriority_Request()
    patch.name = name
    patch.priority = int(priority)
    err, response = api_client.send_recv(patch)
    assert err is None, f"{err}"
    context.result = ParseDict(response, api_engine.GenericStatus_Response())


@then('I should receive a {response} response indicating that the route was updated')
def step_impl(context, response: str):
    if (response == "success"):
        route_response: api_engine.GenericStatus_Response = context.result
        assert route_response.status == api_engine.OK, f"{route_response}"


@then('I should check if the new priority is {priority}')
def step_impl(context, priority: str):
    get = api_router.RouteGet_Request()
    get.name = "default"
    err, response = api_client.send_recv(get)
    assert err is None, f"{err}"
    route_response = ParseDict(response, api_router.RouteGet_Response())
    assert route_response.status == api_engine.OK, f"{route_response}"
    assert route_response.route.priority == int(priority)


# Third Scenario
@when('I send a request to delete the route "{name}"')
def step_impl(context, name: str):
    delete = api_router.RouteDelete_Request()
    delete.name = name
    err, response = api_client.send_recv(delete)
    assert err is None, f"{err}"
    context.result = ParseDict(response, api_engine.GenericStatus_Response())


@then('I should receive a {response} response indicating that the route was deleted')
def step_impl(context, response: str):
    if (response == "success"):
        route_response: api_engine.GenericStatus_Response = context.result
        assert route_response.status == api_engine.OK, f"{route_response}"


# Fourth Scenario
@when('I send a request to get the route "{name}"')
def step_impl(context, name: str):
    get = api_router.RouteGet_Request()
    get.name = name
    err, response = api_client.send_recv(get)
    assert err is None, f"{err}"
    context.result = ParseDict(response, api_router.RouteGet_Response())


@then('I should receive a list of routes with their filters, priorities, and security policies')
def step_impl(context):
    get_response: api_router.RouteGet_Response = context.result
    assert get_response.status == api_engine.OK, f"{get_response}"
    assert get_response.route.name == "default"
    assert get_response.route.filter == "filter/allow-all/0"
    assert get_response.route.priority == 255
    assert get_response.route.policy == "policy/wazuh/0"


# Fifth Scenario
@then('I should receive an {response} response indicating that "{message}"')
def step_impl(context, response: str, message: str):
    if response == "error":
        route_response: api_engine.GenericStatus_Response = context.result
        assert route_response.status == api_engine.ERROR, f"{route_response}"
        assert route_response.error == message
