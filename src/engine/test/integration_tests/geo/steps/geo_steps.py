from typing import Optional, Tuple
from pathlib import Path
import os

from google.protobuf.json_format import ParseDict
from behave import given, when, then

from api_communication.client import APIClient
from api_communication.proto import geo_pb2 as api_geo
from api_communication.proto import engine_pb2 as api_engine

ENV_DIR = os.environ.get("ENV_DIR", "")
SOCKET_PATH = (Path(ENV_DIR) / "queue/sockets/engine-api.socket").as_posix()

api_client = APIClient(SOCKET_PATH)


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


@given('the engine is running with geo manager')
def step_impl(context):
    # Just verify the engine is running by listing databases
    list_request = api_geo.DbList_Request()
    error, response = send_recv(list_request, api_geo.DbList_Response())
    assert error is None, f"{error}"
    assert response.status == api_engine.OK, f"{response.error}"


####################################################################################################
# WHEN
####################################################################################################


@when('I send a request to list all databases')
def step_impl(context):
    request = api_geo.DbList_Request()
    error, response = send_recv(request, api_geo.DbList_Response())
    assert error is None, f"{error}"
    context.response = response


@when('I query the IP address "{ip}"')
def step_impl(context, ip: str):
    # Handle special placeholder for empty string
    if ip == "<empty>":
        ip = ""

    request = api_geo.DbGet_Request()
    request.ip = ip

    # Don't assert on error here, let the response be checked in THEN steps
    error, response = api_client.send_recv(request)
    if error is not None:
        # Store error for later verification
        context.error = error
        context.response = None
        return
    
    try:
        context.response = ParseDict(response, api_geo.DbGet_Response())
        context.error = None
    except Exception as e:
        context.error = str(e)
        context.response = None


####################################################################################################
# THEN
####################################################################################################


@then('the response should be a "{status}"')
def step_impl(context, status: str):
    if status == "success":
        assert context.response is not None, f"Expected success but got error: {getattr(context, 'error', 'Unknown error')}"
        assert context.response.status == api_engine.OK, f"{context.response.status} -> {context.response.error}"
    else:
        # For failure, either we have an error or response.status == ERROR
        if context.response is not None:
            assert context.response.status == api_engine.ERROR, f"Expected ERROR status but got {context.response.status}"
        else:
            # We have a transport or parsing error
            assert context.error is not None, "Expected error but got none"


@then('the response should contain a list of databases')
def step_impl(context):
    assert hasattr(context.response, 'entries'), "Response does not have 'entries' field"
    assert len(context.response.entries) > 0, f"Database list is empty. Expected at least one database"
    # Verify each entry has required fields
    for entry in context.response.entries:
        assert hasattr(entry, 'name'), "Database entry missing 'name' field"
        assert hasattr(entry, 'path'), "Database entry missing 'path' field"
        assert hasattr(entry, 'hash'), "Database entry missing 'hash' field"
        assert hasattr(entry, 'type'), "Database entry missing 'type' field"


@then('the response should contain "{field}" data')
def step_impl(context, field: str):
    assert hasattr(context.response, 'data'), "Response does not have 'data' field"
    assert field in context.response.data.keys(), f"'{field}' not found in response data"
    # Verify it's not empty
    field_data = context.response.data[field]
    if isinstance(field_data, dict):
        assert len(field_data) > 0, f"'{field}' data is empty"


@then('the response should contain empty "{field}" data')
def step_impl(context, field: str):
    assert hasattr(context.response, 'data'), "Response does not have 'data' field"
    assert field in context.response.data.keys(), f"'{field}' not found in response data"
    # Verify it's empty
    field_data = context.response.data[field]
    if isinstance(field_data, dict):
        assert len(field_data) == 0, f"'{field}' data is not empty: {field_data}"


@then('the error message should contain "{text}"')
def step_impl(context, text: str):
    if context.response is not None and hasattr(context.response, 'error'):
        assert text in context.response.error, f"Expected '{text}' in error message but got: {context.response.error}"
    elif context.error is not None:
        assert text in context.error, f"Expected '{text}' in error but got: {context.error}"
    else:
        assert False, "No error message found in response"
