import os
import time
import subprocess
from typing import Optional, Tuple, List
from google.protobuf.json_format import ParseDict

from behave import given, when, then
from api_communication.client import APIClient
from api_communication.proto import catalog_pb2 as api_catalog
from api_communication.proto import engine_pb2 as api_engine
from api_utils.commands import engine_clear

ENV_DIR = os.environ.get("ENV_DIR", "")
SOCKET_PATH = ENV_DIR + "/queue/sockets/engine-api.socket"
RULESET_DIR = ENV_DIR + "/engine"

api_client = APIClient(SOCKET_PATH)


def run_command(command):
    result = subprocess.run(
        command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert result.returncode == 0, f"{result.stderr}"


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


def string_to_resource_type(string_value):
    try:
        return api_catalog.ResourceType.Value(string_value)
    except ValueError:
        return api_catalog.ResourceType.UNKNOWN


def string_to_resource_format(string_value):
    try:
        return api_catalog.ResourceFormat.Value(string_value)
    except ValueError:
        return api_catalog.ResourceFormat.json


def post_resource(resource_type: str, format_type: str, content: str, namespaceid: str):
    request = api_catalog.ResourcePost_Request()
    request.type = string_to_resource_type(resource_type)
    request.format = string_to_resource_format(format_type)
    request.content = content
    request.namespaceid = namespaceid

    error, response = send_recv(request, api_engine.GenericStatus_Response())
    return response


def get_resource(resource_name: str, format_type: str, namespaceid: str):
    request = api_catalog.ResourceGet_Request()
    request.name = resource_name
    request.format = string_to_resource_format(format_type)
    request.namespaceid = namespaceid

    error, response = send_recv(request, api_catalog.ResourceGet_Response())
    return response


def delete_resource(name: str, namespaceid: str):
    request = api_catalog.ResourceDelete_Request()
    request.name = name
    request.namespaceid = namespaceid

    error, response = send_recv(request, api_engine.GenericStatus_Response())
    return response


def put_resource(resource_name: str, format_type: str, content: str, namespaceid: str):
    request = api_catalog.ResourcePut_Request()
    request.name = resource_name
    request.format = string_to_resource_format(format_type)
    request.content = content
    request.namespaceid = namespaceid

    error, response = send_recv(request, api_engine.GenericStatus_Response())
    return response


def validate_resource(resource_name: str, format_type: str, content: str):
    request = api_catalog.ResourceValidate_Request()
    request.name = resource_name
    request.format = string_to_resource_format(format_type)
    request.content = content
    request.namespaceid = "test"

    error, response = send_recv(request, api_engine.GenericStatus_Response())
    return response


@given('I have a clear catalog')
def step_impl(context):
    engine_clear(api_client)


@when('I send a request to publish in the "{resource_format}" format in the namespace "{namespaceid}" a new resource of type "{resource_type}" that contains')
def step_impl(context, resource_format: str, namespaceid: str, resource_type: str):
    context.result = post_resource(
        resource_type, resource_format, context.text, namespaceid)


@when('I send a request to get the resource "{resource_name}" with format "{format_type}" in the namespace "{namespaceid}"')
def step_impl(context, resource_name: str, format_type: str, namespaceid: str):
    context.result = get_resource(resource_name, format_type, namespaceid)


@when('I send a request to delete the resource "{resource_name}" in the namespace "{namespaceid}"')
def step_impl(context, resource_name: str, namespaceid: str):
    context.result = delete_resource(resource_name, namespaceid)


@when('I send a request to update in the "{resource_format}" format in the namespace "{namespaceid}" the resource "{resource_name}" that contains')
def step_impl(context, resource_format: str, namespaceid: str, resource_name: str):
    context.result = put_resource(
        resource_name, resource_format, context.text, namespaceid)


@when('I send a request to validate in the "{resource_format}" format in the resource "{resource_name}" that contains')
def step_impl(context, resource_format: str, resource_name: str):
    context.result = validate_resource(
        resource_name, resource_format, context.text)


@then('I should receive a {status} response indicating "{response}"')
def step_impl(context, status: str, response: str):
    if status == "failed":
        if isinstance(context.result, str):
            assert context.result == response, f"{context.result}"
        else:
            assert context.result.status == api_engine.ERROR, f"{context.result}"
            assert context.result.error == response, f"{context.result}"


@then('I should receive a {status} response indicating')
def step_impl(context, status: str):
    if status == "failed":
        assert context.result.status == api_engine.ERROR, f"{context.result}"
        assert context.result.error == context.text, f"{context.result}"


@then('I should receive a {status} response')
def step_impl(context, status: str):
    if status == "failed":
        assert context.result.status == api_engine.ERROR, f"{context.result}"
    else:
        assert context.result.status == api_engine.OK, f"{context.result}"


@then('I should receive the next content')
def step_impl(context):
    assert context.result.content == context.text, f"{context.result.content}"
