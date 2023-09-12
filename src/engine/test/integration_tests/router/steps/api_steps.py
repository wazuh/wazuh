from api_communication import communication  # TODO: check on a clean install!
from api_communication import router_pb2
from api_communication import catalog_pb2
from api_communication import kvdb_pb2
from api_communication import policy_pb2
from behave import given, when, then, step
import os
import subprocess

ENGINE_DIR = os.environ.get("ENGINE_DIR", "")
ENV_DIR = os.environ.get("ENV_DIR", "")
SOCKET_PATH = ENV_DIR + "/environment/queue/sockets/engine-api"
RULESET_DIR = ENGINE_DIR + "/ruleset"

API_ROUTER = communication.APIClient(SOCKET_PATH, "router")
API_CATALOG = communication.APIClient(SOCKET_PATH, "catalog")
API_KVDB = communication.APIClient(SOCKET_PATH, "kvdb")
API_POLICY = communication.APIClient(SOCKET_PATH, "policy")

POLICY_CONTENT = '''
name: policy/wazuh/0
integrations:
  - integration/wazuh-core-test/0
'''

# First Scenario


@given('I am authenticated with the router API "{name}"')
def step_impl(context, name: str):
    policy_request = policy_pb2.PoliciesGet_Request()

    context.result = API_POLICY.send_command("policies", "get", policy_request)
    if len(context.result['data']) == 0 or context.result['data']['status'] == "ERROR":
        delete = kvdb_pb2.managerDelete_Request()
        delete.name = "agents_host_data"
        context.result = API_KVDB.send_command(
            "manager", "delete", delete)
        command = f"engine-integration add -a {SOCKET_PATH} -n system {RULESET_DIR}/wazuh-core-test/"
        result = subprocess.run(
            command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        policy_request = policy_pb2.StorePost_Request()
        policy_request.policy = "policy/wazuh/0"

        api_result = API_POLICY.send_command(
            "store", "post", policy_request)
        policy_request = policy_pb2.AssetPost_Request()
        policy_request.policy = "policy/wazuh/0"
        policy_request.asset = "integration/wazuh-core-test/0"
        policy_request.namespace = "system"
        API_POLICY.send_command('asset', 'post', policy_request)

    get = router_pb2.RouteGet_Request()
    get.name = name
    routes_json = API_ROUTER.send_command("route", "get", get)
    if routes_json['data']['status'] != "OK":
        post = router_pb2.RoutePost_Request()
        post.route.name = "default"
        post.route.filter = "filter/allow-all/0"
        post.route.priority = 255
        post.route.policy = "policy/wazuh/0"
        context.result = API_ROUTER.send_command(
            "route", "post", post)


@when('I send a request {request} to the router to add a new route called "{route}" with the data from policy:"{policy}" filter:"{filter}" priority:"{priority}"')
def step_impl(context, request: str, route: str, policy: str, filter: str, priority: str):
    post = router_pb2.RoutePost_Request()
    post.route.name = route
    post.route.filter = filter
    post.route.priority = int(priority)
    post.route.policy = policy
    context.result = API_ROUTER.send_command(
        "route", request.lower(), post)


@then('I should receive an {response} response indicating that the policy already exists')
def step_impl(context, response: str):
    if response == "error":
        assert context.result['data']['status'] == "ERROR", f"{routes_json}"


# Second Scenario
@when('I send a {request} request to update the priority from route "{name}" to value of "{priority}"')
def step_impl(context, request: str, name: str, priority: str):
    patch = router_pb2.RoutePatch_Request()
    patch.route.name = name
    patch.route.priority = int(priority)
    context.result = API_ROUTER.send_command(
        "route", request.lower(), patch)


@then('I should receive a {response} response indicating that the route was updated')
def step_impl(context, response: str):
    if (response == "success"):
        context.result['data']['status'] == "OK"


@then('I should check if the new priority is {priority}')
def step_impl(context, priority: str):
    get = router_pb2.RouteGet_Request()
    get.name = "default"
    routes_json = API_ROUTER.send_command("route", "get", get)
    assert routes_json['data']['route']['priority'] == int(priority)


# Third Scenario
@when('I send a {request} request to the route "{name}"')
def step_impl(context, request: str, name: str):
    delete = router_pb2.RouteDelete_Request()
    delete.name = name
    context.result = API_ROUTER.send_command(
        "route", request.lower(), delete)


@then('I should receive a {response} response indicating that the route was deleted')
def step_impl(context, response: str):
    if (response == "success"):
        context.result['data']['status'] == "OK", f"{context.result}"


# Fourth Scenario
@when('I send a {request} request to get the route "{name}"')
def step_impl(context, request: str, name: str):
    get = router_pb2.RouteGet_Request()
    get.name = name
    context.result = API_ROUTER.send_command(
        "route", request.lower(), get)


@then('I should receive a list of routes with their filters, priorities, and security policies')
def step_impl(context):
    assert context.result['data']['status'] == "OK"
    assert 'name' in context.result['data']['route']
    assert 'filter' in context.result['data']['route']
    assert 'priority' in context.result['data']['route']
    assert 'policy' in context.result['data']['route']


# Fifth Scenario
@then('I should receive an {response} response indicating that "{message}"')
def step_impl(context, response: str, message: str):
    if response == "error":
        assert context.result['data']['status'] == "ERROR", f"{routes_json}"
        assert context.result['data']['error'] == message
