from api_communication import communication #TODO: check on a clean install!
from api_communication import router_pb2
from api_communication import catalog_pb2
from api_communication import kvdb_pb2
from google.protobuf.json_format import MessageToDict
from behave import given, when, then, step
import os
import subprocess

def find_engine_directory(start_dir):
    current_dir = os.path.abspath(start_dir)

    while current_dir != "/":  # Detenerse en la raíz del sistema de archivos
        if os.path.basename(current_dir) == "engine":
            return current_dir
        current_dir = os.path.dirname(current_dir)

    return None

def socket_path():
    engine_directory = find_engine_directory(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(os.path.dirname(os.path.dirname(engine_directory)))
    environment_directory = os.path.join(os.getcwd(), "environment")
    os.chdir(environment_directory)
    return os.path.join(os.getcwd(), "queue/sockets/engine-api")

def wazuh_core_path():
    engine_directory = find_engine_directory(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(engine_directory, 'ruleset')

API_ROUTER = communication.APIClient(socket_path(), "router")
API_CATALOG = communication.APIClient(socket_path(), "catalog")
API_KVDB = communication.APIClient(socket_path(), "kvdb")

POLICY_CONTENT = '''
name: policy/wazuh/0
integrations:
  - integration/wazuh-core-test/0
'''

# First Scenario
@given('I am authenticated with the router API "{name}"')
def step_impl(context, name: str):
    get_catalog = catalog_pb2.ResourceGet_Request()
    get_catalog.name = "policy"
    get_catalog.format = "yaml"
    context.result = API_CATALOG.send_command("resource", "get", MessageToDict(get_catalog))
    if context.result['data']['status'] == "ERROR":
        delete = kvdb_pb2.managerDelete_Request()
        delete.name = "agents_host_data"
        context.result = API_KVDB.send_command("manager", "delete", MessageToDict(delete))
        command = f"engine-integration add -a {socket_path()} -n system {wazuh_core_path()}/wazuh-core-test/"
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        post_catalog = catalog_pb2.ResourcePost_Request()
        post_catalog.type = "policy"
        post_catalog.format = "yaml"
        post_catalog.content = POLICY_CONTENT
        post_catalog.namespaceid = "system"
        context.result = API_CATALOG.send_command("resource", "post", MessageToDict(post_catalog))

    get = router_pb2.RouteGet_Request()
    get.name = name
    routes_json = API_ROUTER.send_command("route", "get", MessageToDict(get))
    if routes_json['data']['status'] != "OK":
        post = router_pb2.RoutePost_Request()
        post.route.name = "default"
        post.route.filter = "filter/allow-all/0"
        post.route.priority = 255
        post.route.policy = "policy/wazuh/0"
        context.result = API_ROUTER.send_command("route", "post", MessageToDict(post))

@when('I send a request {request} to the router to add a new route called "{route}" with the data from policy:"{policy}" filter:"{filter}" priority:"{priority}"')
def step_impl(context, request: str, route: str, policy: str, filter: str, priority: str):
    post = router_pb2.RoutePost_Request()
    post.route.name = route
    post.route.filter = filter
    post.route.priority = int(priority)
    post.route.policy = policy
    context.result = API_ROUTER.send_command("route", request.lower(), MessageToDict(post))

@then('I should receive an {response} response indicating that the policy already exists')
def step_impl(context, response: str):
    if response == "error":
        assert context.result['data']['status'] == "ERROR", f"{routes_json}"


# Second Scenario
@when('I send a {request} request to update the priority from route "{name}" to value of "{priority}"')
def step_impl(context, request: str, name: str, priority : str):
    patch = router_pb2.RoutePatch_Request()
    patch.route.name = name
    patch.route.priority = int(priority)
    context.result = API_ROUTER.send_command("route", request.lower(), MessageToDict(patch))

@then('I should receive a {response} response indicating that the route was updated')
def step_impl(context, response: str):
    if (response == "success"):
        context.result['data']['status'] == "OK"

@then('I should check if the new priority is {priority}')
def step_impl(context, priority: str):
    get = router_pb2.RouteGet_Request()
    get.name = "default"
    routes_json = API_ROUTER.send_command("route", "get", MessageToDict(get))
    assert routes_json['data']['route']['priority'] == int(priority)


# Third Scenario
@when('I send a {request} request to the route "{name}"')
def step_impl(context, request: str, name: str):
    delete = router_pb2.RouteDelete_Request()
    delete.name = name
    context.result = API_ROUTER.send_command("route", request.lower(), MessageToDict(delete))

@then('I should receive a {response} response indicating that the route was deleted')
def step_impl(context, response: str):
    if (response == "success"):
        context.result['data']['status'] == "OK", f"{context.result}"


#Fourth Scenario
@when('I send a {request} request to get the route "{name}"')
def step_impl(context, request: str, name: str):
    get = router_pb2.RouteGet_Request()
    get.name = name
    context.result = API_ROUTER.send_command("route", request.lower(), MessageToDict(get))

@then('I should receive a list of routes with their filters, priorities, and security policies')
def step_impl(context):
    assert context.result['data']['status'] == "OK"
    assert 'name' in context.result['data']['route']
    assert 'filter' in context.result['data']['route']
    assert 'priority' in context.result['data']['route']
    assert 'policy' in context.result['data']['route']


#Fifth Scenario
@then('I should receive an {response} response indicating that "{message}"')
def step_impl(context, response: str, message: str):
    if response == "error":
        assert context.result['data']['status'] == "ERROR", f"{routes_json}"
        assert context.result['data']['error'] == message
