from api_communication.client import APIClient
from api_communication.proto import kvdb_pb2 as api_kvdb
from api_communication.proto import engine_pb2 as api_engine
from google.protobuf.json_format import ParseDict
from behave import given, when, then, step
from typing import Optional, Tuple, List
import os

ENGINE_DIR = os.environ.get("ENGINE_DIR", "")
ENV_DIR = os.environ.get("ENV_DIR", "")
SOCKET_PATH = ENV_DIR + "/queue/sockets/engine-api"
RULESET_DIR = ENGINE_DIR + "/ruleset"

api_client = APIClient(SOCKET_PATH)

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

def get_all_kvdb():
    request = api_kvdb.managerGet_Request()
    error, response = send_recv(request, api_kvdb.managerGet_Response())
    assert error is None, f"{error}"
    return response

def delete_kvdb(context, name: str):
    request = api_kvdb.managerDelete_Request()
    request.name = name
    error, context.result = send_recv(request, api_engine.GenericStatus_Response())

def post_kvdb(context, name: str):
    request = api_kvdb.managerPost_Request()
    request.name = name
    error, context.result = send_recv(request, api_engine.GenericStatus_Response())

def update_kvdb(context, name: str, key: str, value: str):
    request = api_kvdb.dbPut_Request()
    request.name = name
    request.entry.key = key
    request.entry.value.string_value = value
    error, context.result = send_recv(request, api_engine.GenericStatus_Response())

def remove_key_kvdb(context, database_name: str, key_name: str):
    request = api_kvdb.dbDelete_Request()
    request.name = database_name
    request.key = key_name
    error, context.result = send_recv(request, api_engine.GenericStatus_Response())

def search_kvdb(context, database_name: str, prefix: str):
    request = api_kvdb.dbSearch_Request()
    request.name = database_name
    request.prefix = prefix
    error, context.result = send_recv(request, api_kvdb.dbSearch_Response())

def check_and_clear(context):
    if len(get_all_kvdb().dbs) > 0:
        for database in get_all_kvdb().dbs:
            delete_kvdb(context, database)

@given('I have access to the KVDB API')
def step_impl(context):
    check_and_clear(context)

@when('I send a {request_type} request to database called "{database_name}"')
def step_impl(context, request_type: str, database_name: str):
    if request_type == 'POST':
        post_kvdb(context, database_name)
    elif request_type == 'DELETE':
        delete_kvdb(context, database_name)

@when('I add in the database "{database_name}" {i} key-value pairs with the key called "{key_name}"_id and another {j} key-value pairs with the key called "{other_key_name}"_id')
def step_impl(context, i: str, j: str, database_name: str, key_name: str, other_key_name: str):
    for first in range(int(i)):
        name = key_name + "_" + str(first)
        update_kvdb(context, database_name, name, "value")
    for second in range(int(j)):
        name = other_key_name + "_" + str(second)
        update_kvdb(context, database_name, name, "value")


@when('I send a request to search by the prefix "{prefix}" in database "{database_name}"')
def step_impl(context, prefix: str, database_name: str):
    search_kvdb(context, database_name, prefix)

@when('I send a request to add a key-value pair to the database "{database_name}" with key "{key_name}" and value "{key_value}"')
def step_impl(context, database_name: str, key_name: str, key_value: str):
    update_kvdb(context, database_name, key_name, key_value)

@when('I send a request to remove from the database "{database_name}" the key named "{key_name}"')
def step_impl(context, database_name: str, key_name: str):
    remove_key_kvdb(context, database_name, key_name)

@then('I should receive a list of entries with the {size} key-value pairs whose keyname contains the prefix.')
def step_impl(context, size: str):
    result: api_kvdb.dbSearch_Response = context.result
    assert result.status == api_engine.OK, f"Error: {result.error}"
    assert len(result.entries) == int(size), f"Expected {size} entries, got {len(result.entries)}"

@then('I should receive a {status} response')
def step_impl(context, status: str):
    if status == "failed":
        assert context.result.status == api_engine.ERROR, f"{context.result}"
    else:
        assert context.result.status == api_engine.OK, f"{context.result}"

@then('I should receive a {status} response indicating "{response}"')
def step_impl(context, status: str, response: str):
    if status == "failed":
        if isinstance(context.result, str):
            assert context.result == response, f"{context.result}"
        else:
            assert context.result.status == api_engine.ERROR, f"{context.result}"
            assert context.result.error == response, f"{context.result}"
