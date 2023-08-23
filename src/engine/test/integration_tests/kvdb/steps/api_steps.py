from api_communication import communication #TODO: check on a clean install!
from api_communication import kvdb_pb2
from google.protobuf.json_format import MessageToDict
from behave import given, when, then, step
import os

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

API_KVDB = communication.APIClient(socket_path(), "kvdb")

# First Scenario
@given('I have access to the KVDB API')
def step_impl(context):
    print(engine_binary)
    kvdbs_available_json = API_KVDB.send_command("manager", "get", {})
    assert kvdbs_available_json['data']['status'] == "OK"


@when('I send a {request_type} request to KVDB API with "{database_name}" as unique database name')
def step_impl(context, request_type:str, database_name:str):
    try:
        post = kvdb_pb2.managerPost_Request()
        post.name = database_name
        context.result = API_KVDB.send_command("manager", request_type.lower(), MessageToDict(post))
        delete = kvdb_pb2.managerDelete_Request()
        delete.name = database_name
        context.result = API_KVDB.send_command("manager", "delete", MessageToDict(delete))
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
        post = kvdb_pb2.managerPost_Request()
        post.name = database_name
        context.result = API_KVDB.send_command("manager", "post", MessageToDict(post))
    except:
        raise Exception('STEP: Couldn''t send request to API')


@when('I send a {request_type} request with the database name "{database_name}"')
def step_impl(context, request_type:str, database_name:str):
    try:
        post = kvdb_pb2.managerPost_Request()
        post.name = database_name
        context.result = API_KVDB.send_command("manager", request_type.lower(), MessageToDict(post))
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
        post = kvdb_pb2.managerPost_Request()
        post.name = database_name
        context.result = API_KVDB.send_command("manager", "post", MessageToDict(post))
    except:
        raise Exception('STEP: Couldn''t send request to API')


@when('I send a {request_type} request to "{database_name}"')
def step_impl(context, request_type:str, database_name:str):
    try:
        delete = kvdb_pb2.managerDelete_Request()
        delete.name = database_name
        context.result = API_KVDB.send_command("manager", request_type.lower(), MessageToDict(delete))
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
        put = kvdb_pb2.dbPut_Request()
        put.name = database_name
        put.entry.key = key_name
        put.entry.value.string_value = key_value
        context.result = API_KVDB.send_command("db", request_type.lower(), MessageToDict(put))
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
        put = kvdb_pb2.dbPut_Request()
        put.name = database_name
        put.entry.key = key_name
        put.entry.value.string_value = key_value
        context.result = API_KVDB.send_command("db", "put", MessageToDict(put))
    except:
        raise Exception('STEP: Couldn''t send request to API')


@when('I send a {request_type} request to modify a key-value pair to the database "{database_name}" with the key "{key_name}" and value "{key_value}"')
def step_impl(context, request_type:str, database_name:str, key_name:str, key_value:str):
    try:
        put = kvdb_pb2.dbPut_Request()
        put.name = database_name
        put.entry.key = key_name
        put.entry.value.string_value = key_value
        context.result = API_KVDB.send_command("db", "put", MessageToDict(put))
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
        delete = kvdb_pb2.dbDelete_Request()
        delete.name = database_name
        delete.key = key_name
        context.result = API_KVDB.send_command("db", request_type.lower(), MessageToDict(delete))
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
            put = kvdb_pb2.dbPut_Request()
            put.name = database_name
            put.entry.key = name
            put.entry.value.string_value = "value"
            API_KVDB.send_command("db", "put", MessageToDict(put))
        for second in range(int(j)):
            name = other_key_name + "_" + str(second)
            put = kvdb_pb2.dbPut_Request()
            put.name = database_name
            put.entry.key = name
            put.entry.value.string_value = "value"
            API_KVDB.send_command("db", "put", MessageToDict(put))
    except:
        raise Exception('STEP: Couldn''t send request to API')


@when('I send a {request_type} request to search by the prefix "{prefix}" in database "{database_name}"')
def step_impl(context, request_type:str, prefix:str, database_name:str):
    search = kvdb_pb2.dbSearch_Request()
    search.name = database_name
    search.prefix = prefix
    context.result = API_KVDB.send_command("db", request_type.lower(), MessageToDict(search))


@then('I should receive a list of entries with the {size} key-value pairs whose keyname contains the prefix.')
def step_impl(context, size:str):
    assert context.result['data']['status'] == 'OK'
    assert len(context.result['data']['entries']) == int(size)
