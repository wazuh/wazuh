# SPDX-License-Identifier: AGPL-3.0-or-later
from pathlib import Path
import os
from unittest import mock

from behave import given, when, then

from api_communication.client import APIClient
from api_communication.proto import metrics_pb2 as api_metrics
from api_communication.proto import status_pb2 as api_status

ENV_DIR = os.environ.get("ENV_DIR", "")
SOCKET_PATH = (Path(ENV_DIR) / "queue/sockets/engine-api-http.sock").as_posix()

api_client = APIClient(SOCKET_PATH)


def _request_status():
    return api_client.send_recv(api_status.StatusGet_Request())


####################################################################################################
# GIVEN
####################################################################################################


@given('the engine is running')
def step_impl(context):
    error, _ = _request_status()
    assert error is None, f"Engine not reachable on GET /status: {error}"


####################################################################################################
# WHEN
####################################################################################################


@when('I send a request to a path the engine does not serve')
def step_impl(context):
    # The client derives the route from the request message, and every message maps to a served route. Point
    # this one call at a route no module registers, so the whole client path meets the engine's own answer.
    with mock.patch('api_communication.client.get_endpoint',
                    return_value=(None, '_internal/no/such/route', 'post')):
        context.error, context.response = api_client.send_recv(api_status.StatusGet_Request())


@when('I send a metrics request whose name is {size:d} bytes long')
def step_impl(context, size: int):
    request = api_metrics.Get_Request(instrumentName='x' * size)
    context.error, context.response = api_client.send_recv(request)


####################################################################################################
# THEN
####################################################################################################


@then('the client reports the error "{message}"')
def step_impl(context, message: str):
    assert context.error == message, f"Expected error {message!r}, got {context.error!r}"
    assert context.response == {}, f"Expected no response to parse, got {context.response!r}"


@then('the engine still answers its status')
def step_impl(context):
    error, response = _request_status()
    assert error is None, f"GET /status failed after the rejected request: {error}"
    assert response.get('status') == 'OK', f"Unexpected status response: {response}"
