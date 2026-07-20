from google.protobuf.json_format import ParseDict

from api_communication.client import APIClient
from api_communication.proto import engine_pb2 as api_engine
from api_communication.proto import policy_pb2 as api_policy
from api_communication.proto import catalog_pb2 as api_catalog
from api_communication.proto import kvdb_pb2 as api_kvdb


def engine_clear(api_client: APIClient):
    # Delete all policies
    request = api_policy.PoliciesGet_Request()
    error, response = api_client.send_recv(request)
    if error:
        raise Exception(f"Error getting policies: {error}")

    parsed_response = ParseDict(response, api_policy.PoliciesGet_Response())
    if parsed_response.status != api_engine.ERROR:
        for policy in parsed_response.data:
            request = api_policy.StoreDelete_Request()
            request.policy = policy
            error, response = api_client.send_recv(request)
            if error:
                raise Exception(f"Error deleting policy: {error}")
            parsed_response = ParseDict(
                response, api_engine.GenericStatus_Response())
            if parsed_response.status == api_engine.ERROR:
                raise Exception(
                    f"Error deleting policy: {parsed_response.error}")

    # Get all namespaces
    request = api_catalog.NamespacesGet_Request()
    error, response = api_client.send_recv(request)
    if error:
        raise Exception(f"Error getting namespaces: {error}")
    parsed_response = ParseDict(response, api_catalog.NamespacesGet_Response())
    if parsed_response.status != api_engine.ERROR:
        asset_types = ["integration", "decoder", "rule", "filter", "output"]

        for namespace in parsed_response.namespaces:
            for asset_type in asset_types:
                request = api_catalog.ResourceDelete_Request()
                request.namespaceid = namespace
                request.name = asset_type
                error, response = api_client.send_recv(request)
                if error:
                    raise Exception(f"Error deleting {asset_type}: {error}")

    # Delete all kvdbs
    request = api_kvdb.managerGet_Request()
    request.must_be_loaded = False
    error, response = api_client.send_recv(request)
    if error:
        raise Exception(f"Error getting kvdbs: {error}")
    parsed_response = ParseDict(response, api_kvdb.managerGet_Response())
    if parsed_response.status != api_engine.ERROR:
        for kvdb in parsed_response.dbs:
            request = api_kvdb.managerDelete_Request()
            request.name = kvdb
            error, response = api_client.send_recv(request)
            if error:
                raise Exception(f"Error deleting kvdb: {error}")
            parsed_response = ParseDict(
                response, api_engine.GenericStatus_Response())
            if parsed_response.status == api_engine.ERROR:
                raise Exception(
                    f"Error deleting kvdb: {parsed_response.error}")
