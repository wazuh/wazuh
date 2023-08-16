# -- FILE: /home/vagrant/workspace/wazuh/src/engine/test/integration_tests/features/steps/kvdb-steps.py
from __future__ import print_function #TODO: neccesary? or removable?
# import sys
import shared.resource_handler as rs #TODO: check on a clean install!
from behave import given, when, then, step

DEFAULT_API_SOCK = '/var/ossec/queue/sockets/engine-api'

resource_handler = rs.ResourceHandler()

# First Scenario
@given('I have access to the KVDB API')
def step_impl(context):
    kvdbs_available_json = resource_handler.get_kvdb_list(DEFAULT_API_SOCK)
    assert kvdbs_available_json['data']['status'] == "OK"


@when('I send a {request_type} request to KVDB API with "{database_name}" as unique database name')
def step_impl(context, request_type:str, database_name:str):
    try:
        context.result = resource_handler._base_send_command_kvdb(DEFAULT_API_SOCK, request_type.lower(), {"name": database_name})
        context.result = resource_handler._base_send_command_kvdb(DEFAULT_API_SOCK, "delete", {"name": database_name})
    except:
        raise Exception('STEP: Couldn''t send request to API')


@then('I should receive a {success} response with the new database information')
def step_impl(context,success):
    if success=='success':
        assert context.result['data']['status'] == 'OK'
    elif success=='error':
        assert context.result['data']['status'] != 'OK'


# Second Scenario
@given('I have already created a database named "{database_name}" using the KVDB API')
def step_impl(context, database_name:str):
    try:
        context.result = resource_handler._base_send_command_kvdb(DEFAULT_API_SOCK, "post", {"name": database_name})
    except:
        raise Exception('STEP: Couldn''t send request to API')


@when('I send a {request_type} request with the database name "{database_name}"')
def step_impl(context, request_type:str, database_name:str):
    try:
        context.result = resource_handler._base_send_command_kvdb(DEFAULT_API_SOCK, request_type.lower(), {"name": database_name})
    except:
        raise Exception('STEP: Couldn''t send request to API')


@then('I should receive an {request_result} response indicating that the database name already exists')
def step_impl(context, request_result):
    if request_result=='success':
        assert context.result['data']['status'] == 'OK'
    elif request_result=='error':
        assert context.result['data']['status'] == 'ERROR'
        assert context.result['data']['error'] == 'The Database already exists.'


# Third Scenario
@given('I have a database named "{database_name}" created using the KVDB API')
def step_impl(context, database_name:str):
    try:
        context.result = resource_handler._base_send_command_kvdb(DEFAULT_API_SOCK, "post", {"name": database_name})
    except:
        raise Exception('STEP: Couldn''t send request to API')


@when('I send a {request_type} request to "{database_name}"')
def step_impl(context, request_type:str, database_name:str):
    try:
        context.result = resource_handler._base_send_command_kvdb(DEFAULT_API_SOCK, request_type.lower(), {"name": database_name})
    except:
        raise Exception('STEP: Couldn''t send request to API')


@then('I should receive a {request_result} response indicating the database "{database_name}" has been deleted')
def step_impl(context, request_result:str, database_name:str):
    if request_result=='success':
        assert context.result['data']['status'] == 'OK'
    elif request_result=='error':
        assert context.result['data']['status'] == 'ERROR'


# Fourth Scenario
@when('I send a {request_type} request to add a key-value pair to the database "{database_name}" with key "{key_name}" and value "{key_value}"')
def step_impl(context, request_type:str, database_name:str, key_name:str, key_value:str):
    try:
        context.result = resource_handler._base_send_command_kvdb(DEFAULT_API_SOCK, request_type.lower(), {"name": database_name, "entry":{"key": key_name, "value":key_value}}, "db")
    except:
        raise Exception('STEP: Couldn''t send request to API')


@then('I should receive a {request_result} response with the new key-value pair information')
def step_impl(context, request_result:str):
    if request_result=='success':
        assert context.result['data']['status'] == 'OK'
    elif request_result=='error':
        assert context.result['data']['status'] == 'ERROR'


# Fifth  Scenario
@given('I have already added a key-value pair to the database "{database_name}" with the key "{key_name}" and value "{key_value}"')
def step_impl(context, database_name:str, key_name:str, key_value:str):
    try:
        context.result = resource_handler._base_send_command_kvdb(DEFAULT_API_SOCK, "put", {"name": database_name, "entry":{"key": key_name, "value":"key_value"}}, "db")
    except:
        raise Exception('STEP: Couldn''t send request to API')


@when('I send a {request_type} request to modify a key-value pair to the database "{database_name}" with the key "{key_name}" and value "{key_value}"')
def step_impl(context, request_type:str, database_name:str, key_name:str, key_value:str):
    try:
        context.result = resource_handler._base_send_command_kvdb(DEFAULT_API_SOCK, "put", {"name": database_name, "entry":{"key": key_name, "value":"key_value"}}, "db")
    except:
        raise Exception('STEP: Couldn''t send request to API')


@then('I should receive a {request_result} indicating that the key value has been updated')
def step_impl(context, request_result:str):
    if request_result=='success':
        assert context.result['data']['status'] == 'OK'
    elif request_result=='error':
        assert context.result['data']['status'] == 'ERROR'


# Sixth  Scenario
@when('I send a {request_type} request to remove from the database "{database_name}" the key named "{key_name}"')
def step_impl(context, request_type:str, database_name:str, key_name:str):
    try:
        context.result = resource_handler._base_send_command_kvdb(DEFAULT_API_SOCK, request_type.lower(), {"name": database_name, "key": key_name}, "db")
    except:
        raise Exception('STEP: Couldn''t send request to API')


@then('I should receive a {request_result} response indicating that the key-value pair with the key has been deleted')
def step_impl(context, request_result:str):
    if request_result=='success':
        assert context.result['data']['status'] == 'OK'
    elif request_result=='error':
        assert context.result['data']['status'] == 'ERROR'


# Seventh Scenario
@when('I add in the database "{database_name}" {i} key-value pairs with the key called "{key_name}"_id and another {j} key-value pairs with the key called "{other_key_name}"_id')
def step_impl(context, i:str, j:str, database_name:str, key_name:str, other_key_name:str):
    try:
        for first in range(int(i)):
            name = key_name + "_" + str(first)
            resource_handler._base_send_command_kvdb(DEFAULT_API_SOCK, "put", {"name": database_name, "entry":{"key": name, "value": "value"}}, "db")
        for second in range(int(j)):
            name = other_key_name + "_" + str(second)
            resource_handler._base_send_command_kvdb(DEFAULT_API_SOCK, "put", {"name": database_name, "entry":{"key": name, "value": "value"}}, "db")
    except:
        raise Exception('STEP: Couldn''t send request to API')


@when('I send a {request_type} request to search by the prefix "{prefix}" in database "{database_name}"')
def step_impl(context, request_type:str, prefix:str, database_name:str):
    context.result = resource_handler._base_send_command_kvdb(DEFAULT_API_SOCK, request_type.lower(), {"name": database_name, "prefix": prefix}, "db")


@then('I should receive a list of entries with the {size} key-value pairs whose keyname contains the prefix.')
def step_impl(context, size:str):
    assert context.result['data']['status'] == 'OK'
    assert len(context.result['data']['entries']) == int(size)
