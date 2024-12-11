from typing import Optional, Tuple, List
from pathlib import Path
import shutil
import os

from google.protobuf.json_format import ParseDict
from behave import given, when, then

from api_communication.client import APIClient
from api_communication.proto import geo_pb2 as api_geo
from api_communication.proto import engine_pb2 as api_engine

ENV_DIR = os.environ.get("ENV_DIR", "")
SOCKET_PATH = (Path(ENV_DIR) / "queue/sockets/engine-api").as_posix()
RULESET_DIR = (Path(ENV_DIR) / "engine").as_posix()

api_client = APIClient(SOCKET_PATH)

data_path = Path(__file__).resolve().parent.parent / "data"
base_db_path = data_path / "base.mmdb"


def get_db_path(name: str) -> Path:
    return data_path / "dbs" / name


def gen_db(name: str) -> Path:
    src = base_db_path
    dst = get_db_path(name)

    shutil.copy(src, dst)

    return dst


def send_recv(request, expected_response_type) -> Tuple[Optional[str], dict]:
    error, response = api_client.send_recv(request)
    assert error is None, f"{error}"

    try:
        parse_response = ParseDict(response, expected_response_type)
        return None, parse_response
    except Exception as e:
        assert False, f"{response}"

####################################################################################################
# GIVEN
####################################################################################################


@given('the engine is running with an empty geo manager')
def step_impl(context):
    list_request = api_geo.DbList_Request()
    error, response = send_recv(list_request, api_geo.DbList_Response())
    assert error is None, f"{error}"

    for db in response.entries:
        delete_request = api_geo.DbDelete_Request()
        delete_request.path = db.path
        error, response = send_recv(
            delete_request, api_engine.GenericStatus_Response())
        assert error is None, f"{error}"
        assert response.status == api_engine.OK, f"{response.error}"


@given('an existing db file "{name}"')
def step_impl(context, name: str):
    db_path = gen_db(name)
    assert db_path.exists(), f"File {db_path} does not exist"


@given('a non-existent db file "{name}"')
def step_impl(context, name: str):
    db_path = get_db_path(name)
    assert not db_path.exists(), f"File {db_path} exists"


@given('the database "{name}" for type "{type}" is already added to the geo manager')
def step_impl(context, name: str, type: str):
    request = api_geo.DbPost_Request()
    request.path = get_db_path(name).as_posix()
    request.type = type

    error, response = send_recv(request, api_engine.GenericStatus_Response())
    assert error is None, f"{error}"
    assert response.status == api_engine.OK, f"{response.error}"

####################################################################################################
# WHEN
####################################################################################################


@when('I send a request to add a database with path to "{name}" and type "{type}"')
def step_impl(context, name: str, type: str):
    request = api_geo.DbPost_Request()
    request.path = get_db_path(name).as_posix()
    request.type = type

    error, response = send_recv(request, api_engine.GenericStatus_Response())
    assert error is None, f"{error}"

    context.response = response


@when('I send a delete request for the path to "{name}"')
def step_impl(context, name: str):
    request = api_geo.DbDelete_Request()
    request.path = get_db_path(name).as_posix()

    error, response = send_recv(request, api_engine.GenericStatus_Response())
    assert error is None, f"{error}"

    context.response = response


@when('I send a request to list all databases')
def step_impl(context):
    request = api_geo.DbList_Request()

    error, response = send_recv(request, api_geo.DbList_Response())
    assert error is None, f"{error}"

    context.response = response


@when('I send a request to remotely upsert a database with path to "{name}", type "{type}", db url "{dbUrl}" and hash url "{hashUrl}"')
def step_impl(context, name: str, type: str, dbUrl: str, hashUrl: str):
    request = api_geo.DbRemoteUpsert_Request()
    request.path = get_db_path(name).as_posix()
    request.type = type
    request.dbUrl = dbUrl
    request.hashUrl = hashUrl

    error, response = send_recv(request, api_engine.GenericStatus_Response())
    assert error is None, f"{error}"

    context.response = response


@when('I restart the engine')
def step_impl(context):
    context.shared_data['engine_instance'].stop()
    context.shared_data['engine_instance'].start()


####################################################################################################
# THEN
####################################################################################################


@then('the response should be a "{status}"')
def step_impl(context, status: str):
    if status == "success":
        assert context.response.status == api_engine.OK, f"{context.response.status} -> {context.response.error}"
    else:
        assert context.response.status == api_engine.ERROR, f"{context.response.status}"


@then('the database list "{should}" include "{name}"')
def step_impl(context, should: str, name: str):
    list_request = api_geo.DbList_Request()
    error, response = send_recv(list_request, api_geo.DbList_Response())
    assert error is None, f"{error}"
    if should == "should":
        assert any(
            db.name == name for db in response.entries), f"{name} not in {response.entries}"
    else:
        assert not any(
            db.name == name for db in response.entries), f"{name} in {response.entries}"


@then('the error message "{message}" is returned')
def step_impl(context, message: str):
    # find '{name}' and replace it with the db path
    index = message.find("'{")
    if index != -1:
        index2 = message.find("}'", index)
        assert index2 != -1, "missing '}}"
        message = message[:index+1] + \
            get_db_path(message[index+2:index2]
                        ).as_posix() + message[index2+1:]

    assert context.response.error == message, f'expected "{message}" but got "{context.response.error}"'


@then('the response should include "{name}"')
def step_impl(context, name: str):
    assert any(
        db.name == name for db in context.response.entries), f"{name} not in {context.response.entries}"
