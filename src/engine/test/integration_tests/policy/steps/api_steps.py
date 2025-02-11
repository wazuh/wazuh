import os
import subprocess
from typing import Optional, Tuple, List
from pathlib import Path
from behave import given, when, then
from google.protobuf.json_format import ParseDict

from api_communication.client import APIClient
from api_communication.proto import policy_pb2 as api_policy
from api_communication.proto import engine_pb2 as api_engine
from api_communication.proto import catalog_pb2 as api_catalog
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


def add_integration(integration_name: str, namespace: str):
    integration_path = Path(RULESET_DIR).resolve() / integration_name
    assert integration_path.is_dir(
    ), f"Integration {integration_name} not found"
    asset_types = {
        "decoders": api_catalog.decoder,
        "rules": api_catalog.rule,
        "outputs": api_catalog.output,
        "filters": api_catalog.filter
    }

    for directory, asset_type in asset_types.items():
        path = integration_path / directory
        if path.is_dir():
            for asset_file in path.rglob("*.yml"):
                request = api_catalog.ResourcePost_Request()
                request.namespaceid = namespace
                request.content = asset_file.read_text()
                request.format = api_catalog.yaml
                request.type = asset_type

                error, response = api_client.send_recv(request)
                assert error is None, f"{error}"
                parsed_response = ParseDict(
                    response, api_engine.GenericStatus_Response())
                assert parsed_response.status == api_engine.OK, f"{parsed_response}"

    # Add manifest
    manifest_file = integration_path / "manifest.yml"
    assert manifest_file.is_file(
    ), f"Manifest file not found for integration {integration_name}"
    request = api_catalog.ResourcePost_Request()
    request.namespaceid = namespace
    request.content = manifest_file.read_text()
    request.format = api_catalog.yaml
    request.type = api_catalog.integration

    error, response = api_client.send_recv(request)
    assert error is None, f"{error}"
    parsed_response = ParseDict(response, api_engine.GenericStatus_Response())
    assert parsed_response.status == api_engine.OK, f"{parsed_response}"


def create_policy(policy_name: str):
    request = api_policy.StorePost_Request()
    request.policy = policy_name
    error, response = send_recv(request, api_engine.GenericStatus_Response())
    return response


def list_policies():
    request = api_policy.PoliciesGet_Request()
    error, response = send_recv(request, api_policy.PoliciesGet_Response())
    return response


def get_policy(policy_name: str, namespaces: List[str]):
    request = api_policy.StoreGet_Request()
    request.policy = policy_name
    request.namespaces.extend([namespaces])
    error, response = send_recv(request, api_policy.StoreGet_Response())
    return response


def delete_policy(policy_name: str):
    request = api_policy.StoreDelete_Request()
    request.policy = policy_name
    error, response = send_recv(request, api_engine.GenericStatus_Response())
    return response


def add_integration_to_policy(integration_name: str, policy_name: str, namespace: str):
    request = api_policy.AssetPost_Request()
    request.policy = policy_name
    request.asset = f"integration/{integration_name}/0"
    request.namespace = namespace
    error, response = send_recv(request, api_policy.AssetPost_Response())
    return response


def remove_integration_to_policy(integration_name: str, policy_name: str, namespace: str):
    request = api_policy.AssetDelete_Request()
    request.policy = policy_name
    request.asset = f"integration/{integration_name}/0"
    request.namespace = namespace
    error, response = send_recv(request, api_policy.AssetDelete_Response())
    return response


def add_default_parent(default_parent_name: str, namespace: str):
    request = api_policy.DefaultParentPost_Request()
    request.policy = "policy/wazuh/0"
    request.namespace = namespace
    request.parent = default_parent_name
    error, response = send_recv(
        request, api_policy.DefaultParentPost_Response())
    return response


def get_default_parent(policy_name: str, namespace: str):
    request = api_policy.DefaultParentGet_Request()
    request.policy = policy_name
    request.namespace = namespace
    response, error = send_recv(
        request, api_policy.DefaultParentGet_Response())
    return response


def get_namespace_policy(policy_name: str):
    request = api_policy.NamespacesGet_Request()
    request.policy = policy_name
    error, response = send_recv(request, api_policy.NamespacesGet_Response())
    return response


def policy_tear_down():
    engine_clear(api_client)


@given('I have a policy called "{policy_name}"')
def step_impl(context, policy_name: str):
    # TearDown
    policy_tear_down()

    # Setup
    context.policy = policy_name
    create_policy(policy_name)


@given('I load an integration called "{integration_name}" in the namespace "{namespace}"')
def step_impl(context, integration_name: str, namespace: str):
    # Setup
    add_integration(integration_name, namespace)
    add_integration_to_policy(integration_name, context.policy, namespace)


@when('I send a request to add a new policy called "{policy_name}"')
def step_impl(context, policy_name: str):
    context.result = create_policy(policy_name)


@when('I send a request to remove the policy called "{policy_name}"')
def step_impl(context, policy_name: str):
    context.result = delete_policy(policy_name)


@when('I send a request to get the policy called "{policy_name}" in the namespaces "{namespaces}"')
def step_impl(context, policy_name: str, namespaces: List[str]):
    context.result = get_policy(policy_name, namespaces)


@when('I load an integration called "{integration_name}" in the namespace "{namespace}" to the policy "{policy_name}"')
def step_impl(context, integration_name: str, policy_name: str, namespace: str):
    # Setup
    add_integration(integration_name, namespace)
    context.result = add_integration_to_policy(
        integration_name, policy_name, namespace)


@when('I send a request to delete the asset "{integration_name}" from the policy called "{policy_name}" in the namespace "{namespace}"')
def step_impl(context, integration_name: str, policy_name: str, namespace: str):
    context.result = remove_integration_to_policy(
        integration_name, policy_name, namespace)


@when('I send a request to set the default parent called "{default_parent_name}" in the namespace "{namespace}"')
def step_impl(context, default_parent_name: str, namespace: str):
    context.result = add_default_parent(default_parent_name, namespace)


@when('I send a request to get the default parent of policy "{policy_name}" in the namespace "{namespace}"')
def step_impl(context, policy_name: str, namespace: str):
    context.result = get_default_parent(policy_name, namespace)


@when('I send a request to get namespaces of policy "{policy_name}"')
def step_impl(context, policy_name: str):
    context.result = get_namespace_policy(policy_name)


@then('I should an error indicating "{response}"')
def step_impl(context, response: str):
    assert context.result == response, f"{context.result}"


@then('I should receive a {status} response indicating "{response}"')
def step_impl(context, status: str, response: str):
    if status == "failed":
        if isinstance(context.result, str):
            assert context.result == response, f"{context.result}"
        else:
            assert context.result.status == api_engine.ERROR, f"{context.result}"
            assert context.result.error == response, f"{context.result}"


@then('I should receive a success response with a validation warning indicating "{response}"')
def step_impl(context, response: str):
    assert context.result.status == api_engine.OK, f"{context.result}"
    assert context.result.warning == response, f"{context.result}"


@then('I should receive a {status} response')
def step_impl(context, status: str):
    if status == "failed":
        assert context.result.status == api_engine.ERROR, f"{context.result}"
    else:
        assert context.result.status == api_engine.OK, f"{context.result}"


@then('I should receive a policy with {assets} assets in those namespaces')
def step_impl(context, assets: str):
    assert context.result.status == api_engine.OK, f"{context.result}"
    if 0 == int(assets):
        assert "assets" not in context.result.data, f"{context.result.data}"
    else:
        assert "assets" in context.result.data, f"{context.result.data}"


@then('I should receive a list with size {size}')
def step_impl(context, size: str):
    policies = list_policies()
    assert len(policies.data) == int(size)


@then('I should receive a list of namespace with size {size}')
def step_impl(context, size: str):
    assert len(context.result.data) == int(size), f"{context.result}"
