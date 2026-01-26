import os
from typing import List

from behave import given, when, then
from google.protobuf.json_format import ParseDict

from api_communication.client import APIClient
from api_communication.proto import crud_pb2 as api_crud
from api_communication.proto import engine_pb2 as api_engine

# Engine API socket path
ENV_DIR = os.environ.get("ENV_DIR", "")
SOCKET_PATH = ENV_DIR + "/queue/sockets/engine-api.socket"

api_client = APIClient(SOCKET_PATH)

# ============================================================
# Constants for policy success tests
# ============================================================

POLICY_DEFAULT_PARENT_NAME = "decoder/integration/0"
POLICY_ROOT_DECODER_NAME = "decoder/core-wazuh-message/0"
POLICY_DECODER_UUID = "85853f26-5779-469b-86c4-c47ee7d400b4"
POLICY_INTEGRATION_UUID = "42e28392-4f5e-473d-89e8-c9030e6fedc2"
POLICY_INTEGRATION_NAME = "integration_development_0"


# ============================================================
# Generic helpers
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
    """
    Lists all namespaces via the namespaceGet handler.
    """
    req = api_crud.namespaceGet_Request()
    error_msg, resp = send_recv(req, api_crud.namespaceGet_Response())
    if error_msg is not None:
        return []
    return list(resp.spaces)


def namespace_exists(space: str) -> bool:
    return space in list_namespaces()


def create_namespace(space: str):
    """
    Creates a namespace via namespacePost.
    """
    req = api_crud.namespacePost_Request()
    req.space = space
    err, resp = send_recv(req, api_engine.GenericStatus_Response())
    return err, resp


def delete_namespace(space: str):
    """
    Tries to delete a namespace via namespaceDelete.
    Used only for cleaning up 'ghost' if it exists.
    Errors are ignored here.
    """
    req = api_crud.namespaceDelete_Request()
    req.space = space
    _, _ = send_recv(req, api_engine.GenericStatus_Response())


def request_resource_upsert(space: str, rtype: str, yml: str):
    req = api_crud.resourcePost_Request()
    req.space = space
    req.type = rtype
    req.ymlContent = yml
    return send_recv(req, api_engine.GenericStatus_Response())


def request_resource_delete(space: str, uuid: str):
    req = api_crud.resourceDelete_Request()
    req.space = space
    req.uuid = uuid
    return send_recv(req, api_engine.GenericStatus_Response())


def request_resource_list(space: str, rtype: str):
    req = api_crud.resourceList_Request()
    req.space = space
    req.type = rtype
    return send_recv(req, api_crud.resourceList_Response())


# ============================================================
# YAML builders for decoder assets
# ============================================================

def build_good_decoder_yaml(name: str) -> str:
    """
    Build a valid decoder asset YAML, following the expected structure.
    """
    return f"""\
name: {name}

check: contains($event.original, "test-pattern")

parse|event.original:
  - |-
    <_tmp_value.metric> <test.metric.value/long>
  - |-
    <_tmp_other.metric> <test.metric.other/long>

normalize:
  - map:
    - event.category: array_append(test)
    - event.kind: metric
    - event.type: array_append(info)
    - wazuh.decoders: array_append(test-decoder)
    - test.value: to_int($_tmp_value.metric, 'truncate')

  - check: $_tmp_other.metric > 0
    map:
    - test.other.is_positive: true
"""


def build_decoder_yaml_without_name() -> str:
    """
    Build a decoder YAML without 'name' field.
    """
    return """\
check: contains($event.original, "test-pattern")

parse|event.original:
  - |-
    <_tmp_value.metric> <test.metric.value/long>

normalize:
  - map:
    - event.category: array_append(test)
"""


def build_decoder_yaml_with_invalid_name(bad_name: str) -> str:
    """
    Build a decoder YAML with an invalid 'name'.
    """
    return f"""\
name: {bad_name}

check: contains($event.original, "test-pattern")

parse|event.original:
  - |-
    <_tmp_value.metric> <test.metric.value/long>

normalize:
  - map:
    - event.category: array_append(test)
"""


def build_decoder_yaml_with_id(name: str, uuid: str, updated: bool = False) -> str:
    """
    YAML for updating/creating a decoder resource, including the 'id' field.
    """
    if updated:
        return f"""\
name: {name}
id: {uuid}

check: contains($event.original, "test-pattern")

parse|event.original:
  - |-
    <_tmp_value.metric> <test.metric.value/long>

normalize:
  - map:
    - event.category: array_append(test)
    - test.value: to_int($_tmp_value.metric, 'truncate')
    - test.updated: true
"""
    else:
        return f"""\
name: {name}
id: {uuid}

check: contains($event.original, "test-pattern")

parse|event.original:
  - |-
    <_tmp_value.metric> <test.metric.value/long>

normalize:
  - map:
    - event.category: array_append(test)
"""


# ============================================================
# POLICY HELPERS
# ============================================================

def request_policy_upsert(space: str, yml: str):
    """
    Calls policyPost handler.
    """
    req = api_crud.policyPost_Request()
    req.space = space
    req.ymlContent = yml
    return send_recv(req, api_engine.GenericStatus_Response())


def request_policy_delete(space: str):
    """
    Calls policyDelete handler.
    """
    req = api_crud.policyDelete_Request()
    req.space = space
    return send_recv(req, api_engine.GenericStatus_Response())


def build_valid_policy_yaml() -> str:
    """
    Minimal valid policy YAML for tests where we only care about
    handler/namespace errors (focus on 'integrations' array).
    """
    return """\
integrations:
  - "dummy-integration-uuid"
"""


def build_policy_yaml_missing_integrations() -> str:
    """
    Policy YAML without 'integrations' key.
    """
    return """\
tittle: bar
"""


def build_policy_yaml_with_empty_integrations() -> str:
    """
    Policy YAML with an empty 'integrations' array.
    """
    return """\
tittle: bar
integrations: []
"""


def build_full_valid_policy_yaml(default_parent: str,
                                 root_decoder: str,
                                 integration_uuid: str) -> str:
    """
    Full valid policy YAML, with mandatory fields and at least one integration UUID.
    Matches the shape:

      {
        "type": "policy",
        "title": "...",
        "default_parent": "...",
        "root_decoder": "...",
        "integrations": [ "<uuid>" ]
      }
    """
    return f"""\
type: policy
title: Development 0.0.1
default_parent: {default_parent}
root_decoder: {root_decoder}
integrations:
  - "{integration_uuid}"
"""


def build_integration_yaml_for_policy(name: str,
                                      integ_uuid: str,
                                      default_parent: str,
                                      decoder_uuid: str) -> str:
    """
    Integration YAML for policy tests, matching (in JSON):

      {
        "id": "...",
        "title": "...",
        "enabled": true,
        "category": "other",
        "default_parent": "...",
        "decoders": [ "<decoder_uuid>" ],
        "kvdbs": []
      }
    """
    return f"""\
id: {integ_uuid}
title: {name}
enabled: true
category: other
default_parent: {default_parent}
decoders:
  - "{decoder_uuid}"
kvdbs: []
"""


# ============================================================
# Given steps (namespaces + resources)
# ============================================================

@given('I have created the namespace "{space}"')
def step_impl(context, space):
    if not namespace_exists(space):
        err, resp = create_namespace(space)
        assert err is None, f"Error creating namespace '{space}': {err}"
        assert resp.status == api_engine.OK, f"{resp}"
    assert namespace_exists(space), f"Namespace '{space}' was not created"


@given('there is no namespace called "{space}"')
def step_impl(context, space):
    if namespace_exists(space):
        delete_namespace(space)
    assert not namespace_exists(space), f"Namespace '{space}' still exists"


@given('there are no "{rtype}" resources in namespace "{space}"')
def step_impl(context, rtype, space):
    err, resp = request_resource_list(space, rtype)
    if err is not None:
        assert False, f"Failed to list resources in '{space}': {err}"

    for item in resp.resources:
        del_err, _ = request_resource_delete(space, item.uuid)
        assert del_err is None, f"Error deleting resource {item.uuid}: {del_err}"

    err2, resp2 = request_resource_list(space, rtype)
    assert err2 is None, f"Error re-listing resources in '{space}': {err2}"
    assert len(resp2.resources) == 0, f"Expected no '{rtype}' resources, got: {list(resp2.resources)}"


@given('I have created a "decoder" resource named "{name}" in namespace "{space}"')
def step_impl(context, name, space):
    yml = build_good_decoder_yaml(name)
    err, resp = request_resource_upsert(space, "decoder", yml)
    assert err is None, f"Error creating decoder resource: {err}"
    assert resp.status == api_engine.OK, f"{resp}"


@given('I have fetched the decoder resources in namespace "{space}"')
def step_impl(context, space):
    context.res_error_msg, context.res_response = request_resource_list(space, "decoder")
    assert context.res_error_msg is None, f"{context.res_error_msg}"
    assert context.res_response.status == api_engine.OK, f"{context.res_response}"


@given('I have stored the UUID of the resource named "{name}"')
def step_impl(context, name):
    resources = list(context.res_response.resources)
    matches = [r.uuid for r in resources if r.name == name]
    assert matches, f"Resource named '{name}' not found in {resources}"
    context.resource_uuid = matches[0]


@given('I have stored the UUID and hash of the resource named "{name}"')
def step_impl(context, name):
    resources = list(context.res_response.resources)
    matches = [(r.uuid, r.hash) for r in resources if r.name == name]
    assert matches, f"Resource named '{name}' not found in {resources}"
    context.resource_uuid, context.resource_hash = matches[0]


@given('I have prepared a valid integration and decoders for policies in namespace "{space}"')
def step_impl(context, space):
    """
    Prepares:
      - A decoder asset for POLICY_DEFAULT_PARENT_NAME with UUID POLICY_DECODER_UUID
      - A decoder asset for POLICY_ROOT_DECODER_NAME (name-only is enough)
      - An integration resource with UUID POLICY_INTEGRATION_UUID that references the decoder UUID
    so that:
      - softPolicyValidate finds default_parent & root_decoder as assets
      - validateIntegration / getIntegrationByUUID work with that integration UUID.
    """
    # 1) Decoder used as default_parent (requires name + id)
    yml_default_parent = build_decoder_yaml_with_id(
        POLICY_DEFAULT_PARENT_NAME,
        POLICY_DECODER_UUID,
        updated=False,
    )
    err, resp = request_resource_upsert(space, "decoder", yml_default_parent)
    assert err is None, f"Error creating default_parent decoder: {err}"
    assert resp.status == api_engine.OK, f"{resp}"

    # 2) Root decoder (only needs to exist by name)
    yml_root_decoder = build_good_decoder_yaml(POLICY_ROOT_DECODER_NAME)
    err, resp = request_resource_upsert(space, "decoder", yml_root_decoder)
    assert err is None, f"Error creating root decoder: {err}"
    assert resp.status == api_engine.OK, f"{resp}"

    # 3) Integration resource, referencing the decoder UUID
    integ_yaml = build_integration_yaml_for_policy(
        name=POLICY_INTEGRATION_NAME,
        integ_uuid=POLICY_INTEGRATION_UUID,
        default_parent=POLICY_DECODER_UUID,
        decoder_uuid=POLICY_DECODER_UUID,
    )
    err, resp = request_resource_upsert(space, "integration", integ_yaml)
    assert err is None, f"Error creating integration for policy: {err}"
    assert resp.status == api_engine.OK, f"{resp}"


# ============================================================
# When steps (resources)
# ============================================================

@when('I send a request to create a "decoder" resource named "{name}" in namespace "{space}"')
def step_impl(context, name, space):
    yml = build_good_decoder_yaml(name)
    context.res_error_msg, context.res_response = request_resource_upsert(space, "decoder", yml)


@when('I request the list of "{rtype}" resources in namespace "{space}"')
def step_impl(context, rtype, space):
    context.res_error_msg, context.res_response = request_resource_list(space, rtype)


@when('I send a request to create a "decoder" resource named "{name}" in an empty space')
def step_impl(context, name):
    yml = build_good_decoder_yaml(name)
    context.res_error_msg, context.res_response = request_resource_upsert("", "decoder", yml)


@when('I send a request to create a resource with empty type in namespace "{space}" and name "{name}"')
def step_impl(context, space, name):
    yml = build_good_decoder_yaml(name)
    context.res_error_msg, context.res_response = request_resource_upsert(space, "", yml)


@when('I send a request to create a "decoder" resource with empty YAML in namespace "{space}"')
def step_impl(context, space):
    context.res_error_msg, context.res_response = request_resource_upsert(space, "decoder", "")


@when('I send a request to create a resource with type "{rtype}" in namespace "{space}" and name "{name}"')
def step_impl(context, rtype, space, name):
    yml = build_good_decoder_yaml(name)
    context.res_error_msg, context.res_response = request_resource_upsert(space, rtype, yml)


@when('I send a request to delete the resource with that UUID in namespace "{space}"')
def step_impl(context, space):
    uuid = getattr(context, "resource_uuid", None)
    assert uuid is not None, "No resource UUID stored in context"
    context.res_error_msg, context.res_response = request_resource_delete(space, uuid)


@when('I send a request to delete a resource with empty space and UUID "{uuid}"')
def step_impl(context, uuid):
    context.res_error_msg, context.res_response = request_resource_delete("", uuid)


@when('I send a request to delete a resource with empty UUID in namespace "{space}"')
def step_impl(context, space):
    context.res_error_msg, context.res_response = request_resource_delete(space, "")


@when('I send a request to delete a resource with UUID "{uuid}" in namespace "{space}"')
def step_impl(context, uuid, space):
    context.res_error_msg, context.res_response = request_resource_delete(space, uuid)


@when('I send a request to create a "decoder" resource without a name in namespace "{space}"')
def step_impl(context, space):
    yml = build_decoder_yaml_without_name()
    context.res_error_msg, context.res_response = request_resource_upsert(space, "decoder", yml)


@when('I send a request to create a "decoder" resource with invalid name "{bad_name}" in namespace "{space}"')
def step_impl(context, bad_name, space):
    yml = build_decoder_yaml_with_invalid_name(bad_name)
    context.res_error_msg, context.res_response = request_resource_upsert(space, "decoder", yml)


@when('I send a request to update that decoder resource with modified YAML in namespace "{space}"')
def step_impl(context, space):
    uuid = getattr(context, "resource_uuid", None)
    assert uuid is not None, "No resource UUID stored in context"

    err, resp = request_resource_list(space, "decoder")
    assert err is None, f"{err}"
    resources = list(resp.resources)
    matches = [r.name for r in resources if r.uuid == uuid]
    assert matches, f"Resource with UUID '{uuid}' not found when updating"
    name = matches[0]

    yml = build_decoder_yaml_with_id(name, uuid, updated=True)
    context.res_error_msg, context.res_response = request_resource_upsert(space, "decoder", yml)


# ============================================================
# Then steps (resources)
# ============================================================

@then("the resource request should succeed")
def step_impl(context):
    assert context.res_response.status == api_engine.OK, f"{context.res_response}"
    assert context.res_error_msg is None, f"{context.res_error_msg}"


@then("the resource request should fail")
def step_impl(context):
    assert context.res_response.status == api_engine.ERROR, f"{context.res_response}"
    assert context.res_error_msg is not None, "Expected an error message but got None"


@then("the resource list request should succeed")
def step_impl(context):
    assert context.res_response.status == api_engine.OK, f"{context.res_response}"
    assert context.res_error_msg is None, f"{context.res_error_msg}"


@then("the resource list request should fail")
def step_impl(context):
    assert context.res_response.status == api_engine.ERROR, f"{context.res_response}"
    assert context.res_error_msg is not None, "Expected an error message but got None"


@then("the resource list should be empty")
def step_impl(context):
    resources = list(context.res_response.resources)
    assert len(resources) == 0, f"Expected empty resource list, got: {resources}"


@then('the resource list should contain a resource named "{name}"')
def step_impl(context, name):
    resources = list(context.res_response.resources)
    names = [r.name for r in resources]
    assert name in names, f"Resource named '{name}' not found in names: {names}"


@then('the resource list should not contain a resource named "{name}"')
def step_impl(context, name):
    resources = list(context.res_response.resources)
    names = [r.name for r in resources]
    assert name not in names, f"Resource named '{name}' is still present in names: {names}"


@then('the resource error message should be "{msg}"')
def step_impl(context, msg):
    assert context.res_response.status == api_engine.ERROR, f"{context.res_response}"
    assert context.res_error_msg == msg, f"Expected '{msg}', got '{context.res_error_msg}'"


@then('the resource error message should start with "{prefix}"')
def step_impl(context, prefix):
    assert context.res_response.status == api_engine.ERROR, f"{context.res_response}"
    assert context.res_error_msg.startswith(prefix), (
        f"Expected prefix '{prefix}', got '{context.res_error_msg}'"
    )


@then('the hash for that stored resource in namespace "{space}" should be different')
def step_impl(context, space):
    old_hash = getattr(context, "resource_hash", None)
    uuid = getattr(context, "resource_uuid", None)
    assert uuid is not None, "No resource UUID stored in context"
    assert old_hash is not None, "No resource hash stored in context"

    err, resp = request_resource_list(space, "decoder")
    assert err is None, f"{err}"
    resources = list(resp.resources)
    matches = [r.hash for r in resources if r.uuid == uuid]
    assert matches, f"Resource with UUID '{uuid}' not found after update"
    new_hash = matches[0]

    assert new_hash != old_hash, f"Expected hash to change, but old={old_hash}, new={new_hash}"


# ============================================================
# WHEN steps (policy)
# ============================================================

@when('I send a request to upsert a policy in an empty space with valid policy YAML')
def step_impl(context):
    yml = build_valid_policy_yaml()
    context.pol_error_msg, context.pol_response = request_policy_upsert("", yml)


@when('I send a request to upsert a policy in namespace "{space}" with empty policy YAML')
def step_impl(context, space):
    context.pol_error_msg, context.pol_response = request_policy_upsert(space, "")


@when('I send a request to upsert a policy in namespace "{space}" with valid policy YAML')
def step_impl(context, space):
    yml = build_valid_policy_yaml()
    context.pol_error_msg, context.pol_response = request_policy_upsert(space, yml)


@when('I send a request to upsert a policy in namespace "{space}" with YAML missing the integrations array')
def step_impl(context, space):
    yml = build_policy_yaml_missing_integrations()
    context.pol_error_msg, context.pol_response = request_policy_upsert(space, yml)


@when('I send a request to upsert a policy in namespace "{space}" with YAML having an empty integrations array')
def step_impl(context, space):
    yml = build_policy_yaml_with_empty_integrations()
    context.pol_error_msg, context.pol_response = request_policy_upsert(space, yml)


@when('I send a request to upsert a valid policy in namespace "{space}"')
def step_impl(context, space):
    """
    Success path: uses the prepared decoders + integration for this namespace
    and builds a full, valid policy YAML.
    """
    yml = build_full_valid_policy_yaml(
        default_parent=POLICY_DECODER_UUID,
        root_decoder=POLICY_DECODER_UUID,
        integration_uuid=POLICY_INTEGRATION_UUID,
    )
    context.pol_error_msg, context.pol_response = request_policy_upsert(space, yml)


@when('I send a request to delete a policy in an empty space')
def step_impl(context):
    context.pol_error_msg, context.pol_response = request_policy_delete("")


@when('I send a request to delete a policy in namespace "{space}"')
def step_impl(context, space):
    context.pol_error_msg, context.pol_response = request_policy_delete(space)


# ============================================================
# THEN steps (policy)
# ============================================================

@then("the policy request should succeed")
def step_impl(context):
    assert context.pol_response.status == api_engine.OK, f"{context.pol_response}"
    assert context.pol_error_msg is None, f"{context.pol_error_msg}"


@then("the policy request should fail")
def step_impl(context):
    assert context.pol_response.status == api_engine.ERROR, f"{context.pol_response}"
    assert context.pol_error_msg is not None, "Expected an error message but got None"


@then('the policy error message should be "{msg}"')
def step_impl(context, msg):
    assert context.pol_response.status == api_engine.ERROR, f"{context.pol_response}"
    assert context.pol_error_msg == msg, f"Expected '{msg}', got '{context.pol_error_msg}'"


@then('the policy error message should start with "{prefix}"')
def step_impl(context, prefix):
    assert context.pol_response.status == api_engine.ERROR, f"{context.pol_response}"
    assert context.pol_error_msg.startswith(prefix), (
        f"Expected prefix '{prefix}', got '{context.pol_error_msg}'"
    )
