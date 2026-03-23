import os
from typing import Optional, Tuple, List

from behave import given, when, then
from google.protobuf.json_format import ParseDict

from api_communication.client import APIClient
from api_communication.proto import crud_pb2 as api_crud
from api_communication.proto import engine_pb2 as api_engine

# Engine API socket path
ENV_DIR = os.environ.get("ENV_DIR", "")
SOCKET_PATH = ENV_DIR + "/queue/sockets/engine-api.socket"

api_client = APIClient(SOCKET_PATH)

# Namespaces that are read-only / forbidden in CMStore
# "testing" is added to prevent cleanup by crud_ns tests, as it's used by router/tester integration tests
FORBIDDEN_NAMESPACES = {"output", "system", "default", "testing"}


# ============================================================
# Helpers
# ============================================================

def send_recv(request, expected_response):
    """
    Sends a request through the APIClient and parses the returned JSON into
    the expected protobuf response type.

    Returns a tuple:
        (error_message, parsed_response)

    - error_message = None if status != ERROR
    - error_message = parsed_response.error if status == ERROR
    """
    error, response = api_client.send_recv(request)
    assert error is None, f"{error}"

    parsed = ParseDict(response, expected_response)
    status = getattr(parsed, "status", None)

    if status == api_engine.ERROR:
        return parsed.error, parsed

    return None, parsed


def list_namespaces() -> List[str]:
    req = api_crud.namespaceGet_Request()
    error_msg, resp = send_recv(req, api_crud.namespaceGet_Response())
    if error_msg is not None:
        return []
    return list(resp.spaces)


def namespace_exists(space: str) -> bool:
    return space in list_namespaces()


def create_namespace(space: str):
    req = api_crud.namespacePost_Request()
    req.space = space
    error_msg, resp = send_recv(req, api_engine.GenericStatus_Response())
    assert error_msg is None, f"{error_msg}"
    assert resp.status == api_engine.OK, f"{resp}"


def delete_namespace(space: str) -> Tuple[Optional[str], api_engine.GenericStatus_Response]:
    req = api_crud.namespaceDelete_Request()
    req.space = space
    return send_recv(req, api_engine.GenericStatus_Response())


# ============================================================
# Background
# ============================================================

@given("the CM store has no user-defined namespaces")
def step_impl(context):
    """
    Deletes all namespaces that are NOT in FORBIDDEN_NAMESPACES using only
    namespaceDelete. Leaves read-only namespaces intact (e.g. 'cti').
    """
    spaces = list_namespaces()
    for space in spaces:
        if space in FORBIDDEN_NAMESPACES:
            continue
        # Ignore errors here; the goal is to clean up user-defined namespaces
        _, _ = delete_namespace(space)

    # Ensure no user-defined namespaces remain
    remaining = [s for s in list_namespaces() if s not in FORBIDDEN_NAMESPACES]
    assert not remaining, f"Expected no user-defined namespaces, found: {remaining}"


# ============================================================
# LIST
# ============================================================

@when("I request the namespace list")
def step_impl(context):
    req = api_crud.namespaceGet_Request()
    context.ns_error_msg, context.ns_response = send_recv(
        req, api_crud.namespaceGet_Response()
    )


@then("the namespace request should succeed")
def step_impl(context):
    assert context.ns_response.status == api_engine.OK, f"{context.ns_response}"
    assert context.ns_error_msg is None, f"{context.ns_error_msg}"


@then("the namespace request should fail")
def step_impl(context):
    assert context.ns_response.status == api_engine.ERROR, f"{context.ns_response}"
    assert context.ns_error_msg is not None


@then("the namespace list should be empty")
def step_impl(context):
    """
    "Empty" means no user-defined namespaces.
    Forbidden namespaces are ignored in this check.
    """
    spaces = list(context.ns_response.spaces)
    user_spaces = [s for s in spaces if s not in FORBIDDEN_NAMESPACES]
    assert len(user_spaces) == 0, f"Expected no user namespaces, got: {user_spaces}"


@then('the namespace list should contain "{space}"')
def step_impl(context, space):
    spaces = list_namespaces()
    assert space in spaces, f"Namespace '{space}' not found in {spaces}"


@then('the namespace list should not contain "{space}"')
def step_impl(context, space):
    spaces = list_namespaces()
    assert space not in spaces, f"Namespace '{space}' is still present in {spaces}"


# ============================================================
# CREATE
# ============================================================

@given('I have created the namespace "{space}"')
def step_impl(context, space):
    if not namespace_exists(space):
        create_namespace(space)
    assert namespace_exists(space), f"Namespace '{space}' was not created"


@when('I send a request to create the namespace "{space}"')
def step_impl(context, space):
    req = api_crud.namespacePost_Request()
    req.space = space
    context.ns_error_msg, context.ns_response = send_recv(
        req, api_engine.GenericStatus_Response()
    )


@when("I send a request to create a namespace with an empty space")
def step_impl(context):
    req = api_crud.namespacePost_Request()
    req.space = ""
    context.ns_error_msg, context.ns_response = send_recv(
        req, api_engine.GenericStatus_Response()
    )


@then('the error message should be "{msg}"')
def step_impl(context, msg):
    assert context.ns_response.status == api_engine.ERROR, f"{context.ns_response}"
    assert context.ns_error_msg == msg, f"Expected '{msg}', got '{context.ns_error_msg}'"


@then('the error message should start with "{prefix}"')
def step_impl(context, prefix):
    assert context.ns_response.status == api_engine.ERROR, f"{context.ns_response}"
    assert context.ns_error_msg.startswith(prefix), (
        f"Expected prefix '{prefix}', got '{context.ns_error_msg}'"
    )


# ============================================================
# FORBIDDEN NAMES
# ============================================================

@given('the forbidden namespace "{space}" exists in the CM store')
def step_impl(context, space):
    """
    Used only for 'cti'.
    This namespace cannot be created (createNamespace forbids it),
    so we assume the engine initializes it at startup and verify its presence.
    """
    spaces = list_namespaces()
    assert space in FORBIDDEN_NAMESPACES, f"{space} is not in FORBIDDEN_NAMESPACES"
    assert space in spaces, f"Forbidden namespace '{space}' not present in store: {spaces}"


# ============================================================
# DELETE
# ============================================================

@when('I send a request to delete the namespace "{space}"')
def step_impl(context, space):
    req = api_crud.namespaceDelete_Request()
    req.space = space
    context.ns_error_msg, context.ns_response = send_recv(
        req, api_engine.GenericStatus_Response()
    )


@when("I send a request to delete a namespace with an empty space")
def step_impl(context):
    req = api_crud.namespaceDelete_Request()
    req.space = ""
    context.ns_error_msg, context.ns_response = send_recv(
        req, api_engine.GenericStatus_Response()
    )
