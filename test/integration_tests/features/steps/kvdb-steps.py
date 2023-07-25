# -- FILE: /home/vagrant/workspace/wazuh/src/engine/test/integration_tests/features/steps/kvdb-steps.py
from __future__ import print_function #TODO: neccesary? or removable?
# import sys
import shared.resource_handler as rs #TODO: check on a clean install!
from behave import given, when, then, step

DEFAULT_API_SOCK = '/var/ossec/queue/sockets/engine-api'

resource_handler = rs.ResourceHandler()

@given('I have access to the KVDB API')
def step_impl(context):
    # check API status -> TODO: is there another way of doing this?
    kvdb_available_list = []
    kvdbs_available_json = resource_handler.get_kvdb_list(DEFAULT_API_SOCK)
    assert kvdbs_available_json['data']['status'] == "OK"


@when('I send a {request_type} request to KVDB API with "{database_name}" as unique database name')
def step_impl(context, request_type:str, database_name:str):
    try:
        context.result = resource_handler._base_send_command_kvdb(DEFAULT_API_SOCK,database_name,'',request_type.lower())
    except:
        raise Exception('STEP: Couldn''t send request to API')


@then('I should receive a {success} response with the new database information')
def step_impl(context,success):
    if success=='success':
        assert context.result['data']['status'] == 'OK'
    elif success=='error':
        assert context.result['data']['status'] != 'OK'
