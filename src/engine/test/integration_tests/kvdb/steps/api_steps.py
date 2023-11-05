from api_communication.client import APIClient
from api_communication.proto import kvdb_pb2 as api_kvdb
from api_communication.proto import engine_pb2 as api_engine
from google.protobuf.json_format import ParseDict
from behave import given, when, then, step
import os

ENGINE_DIR = os.environ.get("ENGINE_DIR", "")
ENV_DIR = os.environ.get("ENV_DIR", "")
SOCKET_PATH = ENV_DIR + "/queue/sockets/engine-api"
RULESET_DIR = ENGINE_DIR + "/ruleset"

api_client = APIClient(SOCKET_PATH)

# First Scenario


def check_and_clear():
    kvdb_request = api_kvdb.managerGet_Request()
    err, response = api_client.send_recv(kvdb_request)
    assert err is None, f"Error: {err}"
    kvdbs_response = ParseDict(response, api_kvdb.managerGet_Response())
    assert kvdbs_response.status == api_engine.OK, f"Error: {kvdbs_response.error}"
    if len(kvdbs_response.dbs) > 0:
        for database in kvdbs_response.dbs:
            delete = api_kvdb.managerDelete_Request()
            delete.name = database
            err, response = api_client.send_recv(delete)
            assert err is None, f"Error: {err}"
            result = ParseDict(response, api_engine.GenericStatus_Response())
            assert result.status == api_engine.OK, f"Error: {result.error}"


@given('I have access to the KVDB API')
def step_impl(context):
    check_and_clear()


@when('I send a {request_type} request to KVDB API with "{database_name}" as unique database name')
def step_impl(context, request_type: str, database_name: str):
    if request_type == 'POST':
        post = api_kvdb.managerPost_Request()
        post.name = database_name
        err, response = api_client.send_recv(post)
        assert err is None, f"Error: {err}"
        context.result = ParseDict(
            response, api_engine.GenericStatus_Response())
    elif request_type == 'DELETE':
        delete = api_kvdb.managerDelete_Request()
        delete.name = database_name
        err, response = api_client.send_recv(delete)
        assert err is None, f"Error: {err}"
        context.result = ParseDict(
            response, api_engine.GenericStatus_Response())


@then('I should receive a {success} response with the new database information')
def step_impl(context, success):
    result: api_engine.GenericStatus_Response = context.result
    if success == 'success':
        assert result.status == api_engine.OK, f"Error: {result.error}"
    elif success == 'error':
        assert result.status == api_engine.ERROR, f"Expected error, got {result.status}"


# Second Scenario
@given('I have already created a database named "{database_name}" using the KVDB API')
def step_impl(context, database_name: str):
    check_and_clear()
    post = api_kvdb.managerPost_Request()
    post.name = database_name
    err, response = api_client.send_recv(post)
    assert err is None, f"Error: {err}"
    result = ParseDict(response, api_engine.GenericStatus_Response())
    assert result.status == api_engine.OK, f"Error: {result.error}"


@when('I send a {request_type} request with the database name "{database_name}"')
def step_impl(context, request_type: str, database_name: str):
    post = api_kvdb.managerPost_Request()
    post.name = database_name
    err, response = api_client.send_recv(post)
    assert err is None, f"Error: {err}"
    context.result = ParseDict(response, api_engine.GenericStatus_Response())


@then('I should receive an {request_result} response indicating that the database name already exists')
def step_impl(context, request_result):
    result: api_engine.GenericStatus_Response = context.result
    if request_result == 'success':
        assert result.status == api_engine.OK, f"Error: {result.error}"
    elif request_result == 'error':
        assert result.status == api_engine.ERROR, f"Expected error, got {result.status}"
        assert result.error == 'The Database already exists.', f"Expected 'The Database already exists.' error, got {result.error}"


# Third Scenario
@given('I have a database named "{database_name}" created using the KVDB API')
def step_impl(context, database_name: str):
    check_and_clear()
    post = api_kvdb.managerPost_Request()
    post.name = database_name
    err, response = api_client.send_recv(post)
    assert err is None, f"Error: {err}"
    result = ParseDict(response, api_engine.GenericStatus_Response())
    assert result.status == api_engine.OK, f"Error: {result.error}"


@when('I send a {request_type} request to "{database_name}"')
def step_impl(context, request_type: str, database_name: str):
    if request_type == 'DELETE':
        delete = api_kvdb.managerDelete_Request()
        delete.name = database_name
        err, response = api_client.send_recv(delete)
        assert err is None, f"Error: {err}"
        context.result = ParseDict(
            response, api_engine.GenericStatus_Response())
    elif request_type == 'GET':
        get = api_kvdb.managerGet_Request()
        err, response = api_client.send_recv(get)
        assert err is None, f"Error: {err}"
        context.result = ParseDict(response, api_kvdb.managerGet_Response())
    elif request_type == 'POST':
        post = api_kvdb.managerPost_Request()
        post.name = database_name
        err, response = api_client.send_recv(post)
        assert err is None, f"Error: {err}"
        context.result = ParseDict(
            response, api_engine.GenericStatus_Response())


@then('I should receive a {request_result} response indicating the database "{database_name}" has been deleted')
def step_impl(context, request_result: str, database_name: str):
    result: api_engine.GenericStatus_Response = context.result
    if request_result == 'success':
        assert result.status == api_engine.OK, f"Error: {result.error}"
    elif request_result == 'error':
        assert result.status == api_engine.ERROR, f"Expected error, got {result.status}"


# Fourth Scenario
@when('I send a {request_type} request to add a key-value pair to the database "{database_name}" with key "{key_name}" and value "{key_value}"')
def step_impl(context, request_type: str, database_name: str, key_name: str, key_value: str):
    put = api_kvdb.dbPut_Request()
    put.name = database_name
    put.entry.key = key_name
    put.entry.value.string_value = key_value
    err, response = api_client.send_recv(put)
    assert err is None, f"Error: {err}"
    context.result = ParseDict(response, api_engine.GenericStatus_Response())


@then('I should receive a {request_result} response with the new key-value pair information')
def step_impl(context, request_result: str):
    result: api_engine.GenericStatus_Response = context.result
    if request_result == 'success':
        assert result.status == api_engine.OK, f"Error: {result.error}"
    elif request_result == 'error':
        assert result.status == api_engine.ERROR, f"Expected error, got {result.status}"

# Fifth  Scenario


@given('I have already added a key-value pair to the database "{database_name}" with the key "{key_name}" and value "{key_value}"')
def step_impl(context, database_name: str, key_name: str, key_value: str):
    put = api_kvdb.dbPut_Request()
    put.name = database_name
    put.entry.key = key_name
    put.entry.value.string_value = key_value
    err, response = api_client.send_recv(put)
    assert err is None, f"Error: {err}"
    result = ParseDict(response, api_engine.GenericStatus_Response())
    assert result.status == api_engine.OK, f"Error: {result.error}"


@when('I send a {request_type} request to modify a key-value pair to the database "{database_name}" with the key "{key_name}" and value "{key_value}"')
def step_impl(context, request_type: str, database_name: str, key_name: str, key_value: str):
    put = api_kvdb.dbPut_Request()
    put.name = database_name
    put.entry.key = key_name
    put.entry.value.string_value = key_value
    err, response = api_client.send_recv(put)
    assert err is None, f"Error: {err}"
    context.result = ParseDict(response, api_engine.GenericStatus_Response())


@then('I should receive a {request_result} indicating that the key value has been updated')
def step_impl(context, request_result: str):
    result: api_engine.GenericStatus_Response = context.result
    if request_result == 'success':
        assert result.status == api_engine.OK, f"Error: {result.error}"
    elif request_result == 'error':
        assert result.status == api_engine.ERROR, f"Expected error, got {result.status}"


# Sixth  Scenario
@when('I send a {request_type} request to remove from the database "{database_name}" the key named "{key_name}"')
def step_impl(context, request_type: str, database_name: str, key_name: str):
    delete = api_kvdb.dbDelete_Request()
    delete.name = database_name
    delete.key = key_name
    err, response = api_client.send_recv(delete)
    assert err is None, f"Error: {err}"
    context.result = ParseDict(response, api_engine.GenericStatus_Response())


@then('I should receive a {request_result} response indicating that the key-value pair with the key has been deleted')
def step_impl(context, request_result: str):
    result: api_engine.GenericStatus_Response = context.result
    if request_result == 'success':
        assert result.status == api_engine.OK, f"Error: {result.error}"
    elif request_result == 'error':
        assert result.status == api_engine.ERROR, f"Expected error, got {result.status}"


# Seventh Scenario
@when('I add in the database "{database_name}" {i} key-value pairs with the key called "{key_name}"_id and another {j} key-value pairs with the key called "{other_key_name}"_id')
def step_impl(context, i: str, j: str, database_name: str, key_name: str, other_key_name: str):
    for first in range(int(i)):
        name = key_name + "_" + str(first)
        put = api_kvdb.dbPut_Request()
        put.name = database_name
        put.entry.key = name
        put.entry.value.string_value = "value"
        err, response = api_client.send_recv(put)
        assert err is None, f"Error: {err}"
        result = ParseDict(response, api_engine.GenericStatus_Response())
        assert result.status == api_engine.OK, f"Error: {result.error}"
    for second in range(int(j)):
        name = other_key_name + "_" + str(second)
        put = api_kvdb.dbPut_Request()
        put.name = database_name
        put.entry.key = name
        put.entry.value.string_value = "value"
        err, response = api_client.send_recv(put)
        assert err is None, f"Error: {err}"
        result = ParseDict(response, api_engine.GenericStatus_Response())


@when('I send a {request_type} request to search by the prefix "{prefix}" in database "{database_name}"')
def step_impl(context, request_type: str, prefix: str, database_name: str):
    search = api_kvdb.dbSearch_Request()
    search.name = database_name
    search.prefix = prefix
    err, response = api_client.send_recv(search)
    assert err is None, f"Error: {err}"
    context.result = ParseDict(response, api_kvdb.dbSearch_Response())


@then('I should receive a list of entries with the {size} key-value pairs whose keyname contains the prefix.')
def step_impl(context, size: str):
    result: api_kvdb.dbSearch_Response = context.result
    assert result.status == api_engine.OK, f"Error: {result.error}"
    assert len(result.entries) == int(size), f"Expected {size} entries, got {len(result.entries)}"
