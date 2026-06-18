from pathlib import Path
import os

from google.protobuf.json_format import ParseDict
from behave import given, when, then

from api_communication.client import APIClient
from api_communication.proto import status_pb2 as api_status
from api_communication.proto import engine_pb2 as api_engine

ENV_DIR = os.environ.get("ENV_DIR", "")
SOCKET_PATH = (Path(ENV_DIR) / "queue/sockets/engine-api.socket").as_posix()

api_client = APIClient(SOCKET_PATH)

ALLOWED_STATUS = {"ready", "running", "failed"}


def _request_status():
    request = api_status.StatusGet_Request()
    error, response = api_client.send_recv(request)
    if error is not None:
        return error, None
    return None, ParseDict(response, api_status.StatusGet_Response())


def _assert_success(response, error):
    assert response is not None, f"Expected success but got error: {error}"
    assert response.status == api_engine.OK, f"{response.status} -> {response.error}"


def _section(response, name):
    assert hasattr(response, name), f"Response is missing the '{name}' section"
    return getattr(response, name)


####################################################################################################
# GIVEN
####################################################################################################


@given('the engine is running')
def step_impl(context):
    # Sanity check: the status endpoint must answer (also exercises GET routing).
    error, _ = _request_status()
    assert error is None, f"Engine not reachable on GET /status: {error}"


####################################################################################################
# WHEN
####################################################################################################


@when('I request the engine status')
def step_impl(context):
    context.error, context.response = _request_status()


@when('I request the engine status again')
def step_impl(context):
    context.error2, context.response2 = _request_status()


####################################################################################################
# THEN
####################################################################################################


@then('the status response should be a "{status}"')
def step_impl(context, status: str):
    if status == "success":
        _assert_success(context.response, getattr(context, 'error', None))
    else:
        if context.response is not None:
            assert context.response.status == api_engine.ERROR, \
                f"Expected ERROR status but got {context.response.status}"
        else:
            assert context.error is not None, "Expected error but got none"


@then('the status response should contain a boolean "ready" field')
def step_impl(context):
    assert context.response is not None, "No response available"
    assert hasattr(context.response, 'ready'), "Response is missing the 'ready' field"
    assert isinstance(context.response.ready, bool), \
        f"'ready' must be a boolean, got {type(context.response.ready)}"


@then('the status response should contain the "spaces", "ioc" and "geo" sections')
def step_impl(context):
    for section in ("spaces", "ioc", "geo"):
        _section(context.response, section)


@then('every "spaces" entry should expose the space fields')
def step_impl(context):
    spaces = _section(context.response, "spaces")
    for name, entry in spaces.items():
        for field in ("available", "enabled", "status", "hash", "last_successful_update"):
            assert hasattr(entry, field), f"space '{name}' is missing field '{field}'"
        assert isinstance(entry.available, bool), f"space '{name}'.available must be bool"
        assert isinstance(entry.enabled, bool), f"space '{name}'.enabled must be bool"


@then('every "{section}" entry should expose the resource fields')
def step_impl(context, section: str):
    entries = _section(context.response, section)
    for name, entry in entries.items():
        for field in ("available", "status", "hash", "last_successful_update"):
            assert hasattr(entry, field), f"{section} '{name}' is missing field '{field}'"
        assert isinstance(entry.available, bool), f"{section} '{name}'.available must be bool"


@then('every reported "status" value should be one of "ready", "running" or "failed"')
def step_impl(context):
    response = context.response
    for section in ("spaces", "ioc", "geo"):
        for name, entry in getattr(response, section).items():
            assert entry.status in ALLOWED_STATUS, \
                f"{section} '{name}' has invalid status '{entry.status}'"


@then('every "last_successful_update" should be a non-negative integer')
def step_impl(context):
    response = context.response
    for section in ("spaces", "ioc", "geo"):
        for name, entry in getattr(response, section).items():
            ts = entry.last_successful_update
            assert isinstance(ts, int), f"{section} '{name}'.last_successful_update must be int"
            assert ts >= 0, f"{section} '{name}'.last_successful_update must be >= 0, got {ts}"


@then('the "{section}" section should contain the keys "{key1}" and "{key2}"')
def step_impl(context, section: str, key1: str, key2: str):
    entries = _section(context.response, section)
    keys = set(entries.keys())
    assert key1 in keys, f"'{key1}' not found in '{section}' section (got {keys})"
    assert key2 in keys, f"'{key2}' not found in '{section}' section (got {keys})"


@then('the "{section}" section keys should be exactly "{csv}"')
def step_impl(context, section: str, csv: str):
    entries = _section(context.response, section)
    expected = {k.strip() for k in csv.split(",")}
    actual = set(entries.keys())
    assert actual == expected, f"'{section}' keys mismatch. expected {expected}, got {actual}"


@then('only "spaces" entries expose the "enabled" field')
def step_impl(context):
    response = context.response
    # SpaceState carries 'enabled'; ResourceState (ioc/geo) does not define it.
    for name, entry in response.spaces.items():
        assert hasattr(entry, "enabled"), f"space '{name}' is missing the 'enabled' field"
    for section in ("ioc", "geo"):
        for name, entry in getattr(response, section).items():
            assert not hasattr(entry, "enabled"), \
                f"{section} '{name}' unexpectedly exposes an 'enabled' field"


@then('the "ready" flag should match the per-resource availability')
def step_impl(context):
    response = context.response
    # Enabled spaces must be available; all IOC and all geo must be available.
    enabled_spaces_ok = all(
        entry.available for entry in response.spaces.values() if entry.enabled)
    ioc_ok = all(entry.available for entry in response.ioc.values())
    geo_ok = all(entry.available for entry in response.geo.values())
    expected_ready = enabled_spaces_ok and ioc_ok and geo_ok

    assert response.ready == expected_ready, (
        f"ready={response.ready} but computed expected={expected_ready} "
        f"(enabled_spaces_ok={enabled_spaces_ok}, ioc_ok={ioc_ok}, geo_ok={geo_ok})")


@then('both status responses should be a "{status}"')
def step_impl(context, status: str):
    _assert_success(context.response, getattr(context, 'error', None))
    _assert_success(context.response2, getattr(context, 'error2', None))


@then('both status responses should report the same "ready" value')
def step_impl(context):
    assert context.response.ready == context.response2.ready, \
        f"ready changed between calls: {context.response.ready} != {context.response2.ready}"


@then('both status responses should report the same resource keys')
def step_impl(context):
    for section in ("spaces", "ioc", "geo"):
        keys1 = set(getattr(context.response, section).keys())
        keys2 = set(getattr(context.response2, section).keys())
        assert keys1 == keys2, f"'{section}' keys changed between calls: {keys1} != {keys2}"
