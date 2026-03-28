import os
import json
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


def request_resource_upsert(space: str, rtype: str, payload: str):
    req = api_crud.resourcePost_Request()
    req.space = space
    req.type = rtype
    req.ymlContent = payload
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


def request_resource_get(space: str, uuid: str, as_json: bool = False):
    req = api_crud.resourceGet_Request()
    req.space = space
    req.uuid = uuid
    if as_json:
        req.asJson = True
    return send_recv(req, api_crud.resourceGet_Response())


# ============================================================
# JSON builders for decoder assets
# ============================================================

def build_good_decoder_json(name: str) -> str:
    return json.dumps(
        {
            "name": name,
            "enabled": True,
            "check": 'contains($event.original, "test-pattern")',
            "parse|event.original": [
                "<_tmp_value.metric> <_test.metric.value/long>",
                "<_tmp_other.metric> <_test.metric.other/long>",
            ],
            "normalize": [
                {
                    "map": [
                        {"event.category": "array_append(_test)"},
                        {"event.kind": "metric"},
                        {"event.type": "array_append(info)"},
                        {"_test.value": "to_int($_tmp_value.metric, 'truncate')"},
                    ]
                },
                {
                    "check": "$_tmp_other.metric > 0",
                    "map": [
                        {"_test.other.is_positive": True},
                    ],
                },
            ],
        },
        separators=(",", ":"),
    )


def build_decoder_json_without_name() -> str:
    return json.dumps(
        {
            "check": 'contains($event.original, "test-pattern")',
            "enabled": True,
            "parse|event.original": [
                "<_tmp_value.metric> <_test.metric.value/long>",
            ],
            "normalize": [
                {
                    "map": [
                        {"event.category": "array_append(_test)"},
                    ]
                }
            ],
        },
        separators=(",", ":"),
    )


def build_decoder_json_with_invalid_name(bad_name: str) -> str:
    return json.dumps(
        {
            "name": bad_name,
            "enabled": True,
            "check": 'contains($event.original, "test-pattern")',
            "parse|event.original": [
                "<_tmp_value.metric> <_test.metric.value/long>",
            ],
            "normalize": [
                {
                    "map": [
                        {"event.category": "array_append(_test)"},
                    ]
                }
            ],
        },
        separators=(",", ":"),
    )


def build_decoder_json_with_id(name: str, uuid: str, updated: bool = False) -> str:
    payload = {
        "name": name,
        "enabled": True,
        "id": uuid,
        "check": 'contains($event.original, "test-pattern")',
        "parse|event.original": [
            "<_tmp_value.metric> <_test.metric.value/long>",
        ],
        "normalize": [
            {
                "map": [
                    {"event.category": "array_append(_test)"},
                ]
            }
        ],
    }

    if updated:
        payload["normalize"] = [
            {
                "map": [
                    {"event.category": "array_append(_test)"},
                    {"_test.value": "to_int($_tmp_value.metric, 'truncate')"},
                    {"_test.updated": True},
                ]
            }
        ]

    return json.dumps(payload, separators=(",", ":"))


# ============================================================
# POLICY HELPERS
# ============================================================

def request_policy_upsert(space: str, payload: str):
    """
    Calls policyPost handler.
    """
    req = api_crud.policyPost_Request()
    req.space = space
    req.ymlContent = payload
    return send_recv(req, api_engine.GenericStatus_Response())


def request_policy_delete(space: str):
    """
    Calls policyDelete handler.
    """
    req = api_crud.policyDelete_Request()
    req.space = space
    return send_recv(req, api_engine.GenericStatus_Response())


def build_valid_policy_json() -> str:
    return json.dumps(
        {
            "metadata": {"title": "bar"},
            "enabled": True,
            "hash": "crud-cm-test-hash",
            "root_decoder": "00000000-0000-0000-0000-000000000001",
            "integrations": ["dummy-integration-uuid"],
            "enrichments": [],
            "filters": [],
            "index_unclassified_events": False,
            "index_discarded_events": False,
        },
        separators=(",", ":"),
    )


def build_policy_json_missing_integrations() -> str:
    return json.dumps(
        {
            "metadata": {"title": "bar"},
            "enabled": True,
            "hash": "crud-cm-test-hash",
            "root_decoder": "00000000-0000-0000-0000-000000000001",
            "enrichments": [],
            "filters": [],
            "index_unclassified_events": False,
            "index_discarded_events": False,
        },
        separators=(",", ":"),
    )


def build_policy_json_with_unexists_root_decoder() -> str:
    return json.dumps(
        {
            "metadata": {"title": "bar"},
            "enabled": True,
            "hash": "crud-cm-test-hash",
            "root_decoder": "00000000-0000-0000-0000-000000000001",
            "integrations": [],
            "enrichments": [],
            "filters": [],
            "index_unclassified_events": False,
            "index_discarded_events": False,
        },
        separators=(",", ":"),
    )


def build_full_valid_policy_json(default_parent: str,
                                 root_decoder: str,
                                 integration_uuid: str) -> str:
    return json.dumps(
        {
            "type": "policy",
            "enabled": True,
            "metadata": {"title": "Development 0.0.1"},
            "hash": "crud-cm-test-hash",
            "default_parent": default_parent,
            "root_decoder": root_decoder,
            "integrations": [integration_uuid],
            "enrichments": [],
            "filters": [],
            "index_unclassified_events": False,
            "index_discarded_events": False,
        },
        separators=(",", ":"),
    )


def build_integration_json_for_policy(name: str,
                                      integ_uuid: str,
                                      default_parent: str,
                                      decoder_uuid: str) -> str:
    return json.dumps(
        {
            "id": integ_uuid,
            "metadata": {"title": name},
            "enabled": True,
            "enrichments": [],
            "filters": [],
            "index_unclassified_events": False,
            "index_discarded_events": False,
            "category": "other",
            "default_parent": default_parent,
            "decoders": [decoder_uuid],
            "kvdbs": [],
        },
        separators=(",", ":"),
    )


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
    payload = build_good_decoder_json(name)
    err, resp = request_resource_upsert(space, "decoder", payload)
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
    default_parent_payload = build_decoder_json_with_id(
        POLICY_DEFAULT_PARENT_NAME,
        POLICY_DECODER_UUID,
        updated=False,
    )
    err, resp = request_resource_upsert(space, "decoder", default_parent_payload)
    assert err is None, f"Error creating default_parent decoder: {err}"
    assert resp.status == api_engine.OK, f"{resp}"

    # 2) Root decoder (only needs to exist by name)
    root_decoder_payload = build_good_decoder_json(POLICY_ROOT_DECODER_NAME)
    err, resp = request_resource_upsert(space, "decoder", root_decoder_payload)
    assert err is None, f"Error creating root decoder: {err}"
    assert resp.status == api_engine.OK, f"{resp}"

    # 3) Integration resource, referencing the decoder UUID
    integration_payload = build_integration_json_for_policy(
        name=POLICY_INTEGRATION_NAME,
        integ_uuid=POLICY_INTEGRATION_UUID,
        default_parent=POLICY_DECODER_UUID,
        decoder_uuid=POLICY_DECODER_UUID,
    )
    err, resp = request_resource_upsert(space, "integration", integration_payload)
    assert err is None, f"Error creating integration for policy: {err}"
    assert resp.status == api_engine.OK, f"{resp}"


# ============================================================
# When steps (resources)
# ============================================================

@when('I send a request to create a "decoder" resource named "{name}" in namespace "{space}"')
def step_impl(context, name, space):
    payload = build_good_decoder_json(name)
    context.res_error_msg, context.res_response = request_resource_upsert(space, "decoder", payload)


@when('I request the list of "{rtype}" resources in namespace "{space}"')
def step_impl(context, rtype, space):
    context.res_error_msg, context.res_response = request_resource_list(space, rtype)


@when('I send a request to create a "decoder" resource named "{name}" in an empty space')
def step_impl(context, name):
    payload = build_good_decoder_json(name)
    context.res_error_msg, context.res_response = request_resource_upsert("", "decoder", payload)


@when('I send a request to create a resource with empty type in namespace "{space}" and name "{name}"')
def step_impl(context, space, name):
    payload = build_good_decoder_json(name)
    context.res_error_msg, context.res_response = request_resource_upsert(space, "", payload)


@when('I send a request to create a "decoder" resource with empty YAML in namespace "{space}"')
def step_impl(context, space):
    context.res_error_msg, context.res_response = request_resource_upsert(space, "decoder", "")


@when('I send a request to create a resource with type "{rtype}" in namespace "{space}" and name "{name}"')
def step_impl(context, rtype, space, name):
    payload = build_good_decoder_json(name)
    context.res_error_msg, context.res_response = request_resource_upsert(space, rtype, payload)


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
    payload = build_decoder_json_without_name()
    context.res_error_msg, context.res_response = request_resource_upsert(space, "decoder", payload)


@when('I send a request to create a "decoder" resource with invalid name "{bad_name}" in namespace "{space}"')
def step_impl(context, bad_name, space):
    payload = build_decoder_json_with_invalid_name(bad_name)
    context.res_error_msg, context.res_response = request_resource_upsert(space, "decoder", payload)


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

    payload = build_decoder_json_with_id(name, uuid, updated=True)
    context.res_error_msg, context.res_response = request_resource_upsert(space, "decoder", payload)


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


@then('the updated decoder resource in namespace "{space}" should include "test.updated: true"')
def step_impl(context, space):
    uuid = getattr(context, "resource_uuid", None)
    assert uuid is not None, "No resource UUID stored in context"

    err, resp = request_resource_get(space, uuid, as_json=True)
    assert err is None, f"{err}"
    assert resp.status == api_engine.OK, f"{resp}"

    # Parse the JSON content to verify the field exists
    import json
    content = json.loads(resp.content)

    # Check that normalize[0].map contains {"_test.updated": true}
    assert "normalize" in content, f"Missing 'normalize' in response: {resp.content}"
    assert len(content["normalize"]) > 0, f"Empty 'normalize' array: {resp.content}"
    assert "map" in content["normalize"][0], f"Missing 'map' in normalize[0]: {resp.content}"

    # Find the _test.updated field in the map array
    map_items = content["normalize"][0]["map"]
    found_updated = False
    for item in map_items:
        if "_test.updated" in item:
            assert item["_test.updated"] is True, f"Expected _test.updated to be true, got {item['_test.updated']}"
            found_updated = True
            break

    assert found_updated, f"Field '_test.updated' not found in map: {resp.content}"


# ============================================================
# WHEN steps (policy)
# ============================================================

@when('I send a request to upsert a policy in an empty space with valid policy YAML')
def step_impl(context):
    payload = build_valid_policy_json()
    context.pol_error_msg, context.pol_response = request_policy_upsert("", payload)


@when('I send a request to upsert a policy in namespace "{space}" with empty policy YAML')
def step_impl(context, space):
    context.pol_error_msg, context.pol_response = request_policy_upsert(space, "")


@when('I send a request to upsert a policy in namespace "{space}" with valid policy YAML')
def step_impl(context, space):
    payload = build_valid_policy_json()
    context.pol_error_msg, context.pol_response = request_policy_upsert(space, payload)


@when('I send a request to upsert a policy in namespace "{space}" with YAML missing the integrations array')
def step_impl(context, space):
    payload = build_policy_json_missing_integrations()
    context.pol_error_msg, context.pol_response = request_policy_upsert(space, payload)


@when('I send a request to upsert a policy in namespace "{space}" with YAML having an invalid root decoder')
def step_impl(context, space):
    payload = build_policy_json_with_unexists_root_decoder()
    context.pol_error_msg, context.pol_response = request_policy_upsert(space, payload)


@when('I send a request to upsert a valid policy in namespace "{space}"')
def step_impl(context, space):
    """
    Success path: uses the prepared decoders + integration for this namespace
    and builds a full, valid policy YAML.
    """
    payload = build_full_valid_policy_json(
        default_parent=POLICY_DECODER_UUID,
        root_decoder=POLICY_DECODER_UUID,
        integration_uuid=POLICY_INTEGRATION_UUID,
    )
    context.pol_error_msg, context.pol_response = request_policy_upsert(space, payload)


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
