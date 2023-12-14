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

ENGINE_DIR = os.environ.get("ENGINE_DIR", "")
ENV_DIR = os.environ.get("ENV_DIR", "")
SOCKET_PATH = ENV_DIR + "/queue/sockets/engine-api"
RULESET_DIR = ENV_DIR + "/engine"

api_client = APIClient(SOCKET_PATH)


# First Scenario
@given('I want create a session called "{sessionName}" with a policy "{policyName}"')
def step_impl(context, sessionName: str, policyName: str):
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
        request.policy = policyName
        err, response = api_client.send_recv(request)
        if err:
            context.result = err
            print(err)
            assert False

        request = api_policy.AssetPost_Request()
        request.policy = policyName
        request.asset = "integration/wazuh-core-test/0"
        request.namespace = "system"
        err, response = api_client.send_recv(request)
        if err:
            context.result = err
            print(err)
            assert False

    # Check if the session exists, if not, create it
    request = api_tester.SessionGet_Request()
    request.name = sessionName
    err, response = api_client.send_recv(request)
    if err:
        context.result = err
        print(err)
        assert False

    session_resp = ParseDict(response, api_tester.SessionGet_Response())
    if session_resp.status != api_engine.OK:
        request = api_tester.SessionPost_Request()
        request.session.name = sessionName
        request.session.policy = policyName
        err, response = api_client.send_recv(request)
        if err:
            context.result = err
            print(err)
            assert False

@when('I send a request to the tester to add a new session called "{sessionName}" with the data from policy:"{policyName}"')
def step_impl(context, sessionName: str, policyName: str):
    request = api_tester.SessionPost_Request()
    request.session.name = sessionName
    request.session.policy = policyName
    err, response = api_client.send_recv(request)
    assert err is None, f"{err}"
    context.result = ParseDict(response, api_engine.GenericStatus_Response())
    context.session = sessionName

@then('I should receive a {status} response indicating that "{message}"')
def step_impl(context, status: str, message: str):
    if status == "failture":
        route_response: api_engine.GenericStatus_Response = context.result
        assert route_response.status == api_engine.ERROR, f"{route_response}"
        assert route_response.error == message, f"{route_response}"

# Second Scenario
@then('I should receive a {status} response')
def step_impl(context, status: str):
    if status == "success":
        route_response: api_engine.GenericStatus_Response = context.result
        assert route_response.status == api_engine.OK, f"{route_response}"

        # Delete session for the next run
        request = api_tester.SessionDelete_Request()
        request.name = context.session
        err, response = api_client.send_recv(request)
        assert err is None, f"{err}"

# Third Scenario
@when('I send a request to the tester to add {sessions} sessions called "{sessionName}" with policy "{policyName}"')
def step_impl(context, sessions: str, sessionName: str, policyName: str):
    for i in range(int(sessions)):
        request = api_tester.SessionPost_Request()
        request.session.name = sessionName + str(i)
        request.session.policy = policyName
        err, response = api_client.send_recv(request)
        assert err is None, f"{err}"
        context.session = sessionName

@when('I send a request to the tester to get all sessions')
def step_impl(context):
    request = api_tester.TableGet_Request()
    err, response = api_client.send_recv(request)
    assert err is None, f"{err}"
    context.result = ParseDict(response, api_tester.TableGet_Response())

@then('I should receive a size list of {size}')
def step_impl(context, size: str):
    tester_response: api_engine.GenericStatus_Response = context.result
    assert len(tester_response.sessions) - 1 == int(size) , f"{len(tester_response.sessions)}"

    # Delete sessions for the next run
    for i in range(int(size)):

        #Query if the session yet exist
        request = api_tester.SessionGet_Request()
        request.name = context.session
        err, response = api_client.send_recv(request)
        assert err is None, f"{err}"
        context.result = ParseDict(response, api_tester.SessionGet_Response())
        tester_response: api_engine.GenericStatus_Response = context.result

        if (tester_response.status == api_engine.OK):
            # Delete
            request = api_tester.SessionDelete_Request()
            request.name = context.session + str(i)
            err, response = api_client.send_recv(request)
            assert err is None, f"{err}"
    context.size = size

# Fourth Scenario
@when('I send a request to the tester to get the session "{sessionName}"')
def step_impl(context, sessionName: str):
    request = api_tester.SessionGet_Request()
    request.name = sessionName
    err, response = api_client.send_recv(request)
    assert err is None, f"{err}"
    context.result = ParseDict(response, api_tester.SessionGet_Response())

@then('I should receive a session with name "{sessionName}"')
def step_impl(context, sessionName: str):
    tester_response: api_engine.GenericStatus_Response = context.result
    assert tester_response.session.name == sessionName, f"{tester_response.session.name}"

    # Get size list
    request = api_tester.TableGet_Request()
    err, response = api_client.send_recv(request)
    assert err is None, f"{err}"
    context.result = ParseDict(response, api_tester.TableGet_Response())
    tester_response: api_engine.GenericStatus_Response = context.result
    size = len(tester_response.sessions)

    # Delete sessions for the next run
    for i in range(size):
        request = api_tester.SessionDelete_Request()
        request.name = context.session + str(i)
        err, response = api_client.send_recv(request)
        assert err is None, f"{err}"

# Fifth Scenario
@when('I send a request to the tester to delete the session "{sessionName}"')
def step_impl(context, sessionName: str):
    request = api_tester.SessionDelete_Request()
    request.name = sessionName
    err, response = api_client.send_recv(request)
    assert err is None, f"{err}"

    request = api_tester.TableGet_Request()
    err, response = api_client.send_recv(request)
    assert err is None, f"{err}"
    context.result = ParseDict(response, api_tester.TableGet_Response())

# Sixth Scenario
@when('I send a request to the policy "{policyName}" to add an integration called "{integrationName}"')
def step_impl(context, policyName: str, integrationName: str):
    # Query if the integration already exist
    request = api_policy.AssetGet_Request()
    request.policy = policyName
    request.namespace = "system"
    err, response = api_client.send_recv(request)
    assert err is None, f"{err}"
    context.result = ParseDict(response, api_policy.AssetGet_Response())
    policy_response: api_engine.GenericStatus_Response = context.result

    if integrationName in policy_response.data:
        request = api_policy.AssetDelete_Request()
        request.policy = policyName
        request.asset = integrationName
        request.namespace = "system"
        err, response = api_client.send_recv(request)
        if err:
            context.result = err
            print(err)
            assert False
    else:
        # Add new integration
        command = f"engine-integration add -a {SOCKET_PATH} -n system {RULESET_DIR}/other-wazuh-core-test/"
        result = subprocess.run(
            command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert result.returncode == 0, f"{result.stderr}"

        # Add integration to policy
        request = api_policy.AssetPost_Request()
        request.policy = policyName
        request.asset = "integration/other-wazuh-core-test/0"
        request.namespace = "system"
        err, response = api_client.send_recv(request)
        if err:
            context.result = err
            print(err)
            assert False

@when('I send a request to get the session "{sessionName}"')
def step_impl(context, sessionName: str):
    request = api_tester.SessionGet_Request()
    request.name = sessionName
    err, response = api_client.send_recv(request)
    assert err is None, f"{err}"
    context.result = ParseDict(response, api_tester.SessionGet_Response())

@then('I should receive a session with sync "{policySync}"')
def step_impl(context, policySync: str):
    policySyncToString = {
        0: "SYNC_UNKNOWN",
        1: "UPDATED",
        2: "OUTDATED",
        3: "ERROR"
    }
    tester_response: api_engine.GenericStatus_Response = context.result
    assert policySyncToString[tester_response.session.policy_sync] == policySync, f"{tester_response.session.policy_sync}"

@then('I send a request to the tester to rebuild the "{sessionName}" session and the sync change to "{policySync}" again')
def step_impl(context, sessionName: str, policySync: str):
    request = api_tester.SessionReload_Request()
    request.name = sessionName
    err, response = api_client.send_recv(request)
    assert err is None, f"{err}"
    context.result = ParseDict(response, api_engine.GenericStatus_Response())

    request = api_tester.SessionGet_Request()
    request.name = sessionName
    err, response = api_client.send_recv(request)
    assert err is None, f"{err}"
    context.result = ParseDict(response, api_tester.SessionGet_Response())

    policySyncToString = {
        0: "SYNC_UNKNOWN",
        1: "UPDATED",
        2: "OUTDATED",
        3: "ERROR"
    }
    tester_response: api_engine.GenericStatus_Response = context.result
    assert policySyncToString[tester_response.session.policy_sync] == policySync, f"{tester_response.session.policy_sync}"

#Seventh Scenario
@when('I send a request to send the event "{message}" from "{sessionName}" session without debug level')
def step_impl(context, message: str, sessionName: str):
    request = api_tester.RunPost_Request()
    request.name = sessionName
    request.trace_level = 0
    request.message = message
    request.queue = "1"
    request.location = "any"
    err, response = api_client.send_recv(request)
    assert err is None, f"{err}"
    context.result = ParseDict(response, api_tester.RunPost_Response())

@then('I should receive the next output: "{response}"')
def step_impl(context, response: str):
    # Load expected and actual JSON responses
    expected_response = json.loads(response)
    actual_response = json.loads(MessageToJson(context.result.result))

    # Normalize and compare JSON strings
    normalized_expected = json.dumps(expected_response, sort_keys=True, separators=(",", ":"))
    normalized_actual = json.dumps(actual_response, sort_keys=True, separators=(",", ":"))

    assert normalized_actual == normalized_expected, f"Responses do not match: {normalized_actual} != {normalized_expected}"

#Eighth Scenario And Nineth Scenario
@when('I send a request to send the event "{message}" from "{sessionName}" session with "{debugLevel}" debug "{namespace}" namespace and "{assetTrace}" asset trace')
def step_impl(context, message: str, sessionName: str, debugLevel: str, namespace: str, assetTrace: str):
    debugLevelToInt = {
        "NONE": 0,
        "ASSET_ONLY": 1,
        "ALL": 2
    }
    request = api_tester.RunPost_Request()
    request.name = sessionName
    request.trace_level = debugLevelToInt[debugLevel]
    request.message = message
    request.queue = "1"
    request.location = "any"
    request.namespaces.extend([namespace])
    request.asset_trace.extend([assetTrace])
    err, response = api_client.send_recv(request)
    assert err is None, f"{err}"
    context.result = ParseDict(response, api_tester.RunPost_Response())
