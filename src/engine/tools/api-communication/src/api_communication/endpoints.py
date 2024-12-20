from typing import Optional, Tuple

from google.protobuf.message import Message

# Import all proto messages to deduce component, resource and action
import api_communication.proto.catalog_pb2 as catalog
import api_communication.proto.graph_pb2 as graph
import api_communication.proto.kvdb_pb2 as kvdb
import api_communication.proto.metrics_pb2 as metrics
import api_communication.proto.policy_pb2 as policy
import api_communication.proto.router_pb2 as router
import api_communication.proto.tester_pb2 as tester
import api_communication.proto.geo_pb2 as geo


def get_endpoint(message: Message) -> Tuple[Optional[str], str]:
    """Get the endpoint string for the given message

    Args:
        message (Message): Proto message

    Returns:
        Tuple[Optional[str], str]: Error string if any, endpoint string
    """

    # Catalog
    if isinstance(message, catalog.ResourcePost_Request):
        return None, 'catalog/resource/post'
    if isinstance(message, catalog.ResourceGet_Request):
        return None, 'catalog/resource/get'
    if isinstance(message, catalog.ResourcePut_Request):
        return None, 'catalog/resource/delete'
    if isinstance(message, catalog.ResourceDelete_Request):
        return None, 'catalog/resource/put'
    if isinstance(message, catalog.ResourceValidate_Request):
        return None, 'catalog/resource/validate'
    if isinstance(message, catalog.NamespacesGet_Request):
        return None, 'catalog/namespaces/get'

    # Geo
    if isinstance(message, geo.DbPost_Request):
        return None, 'geo/db/add'
    if isinstance(message, geo.DbList_Request):
        return None, 'geo/db/list'
    if isinstance(message, geo.DbDelete_Request):
        return None, 'geo/db/del'
    if isinstance(message, geo.DbRemoteUpsert_Request):
        return None, 'geo/db/remoteUpsert'

    # KVDB
    if isinstance(message, kvdb.dbGet_Request):
        return None, 'kvdb/db/get'
    if isinstance(message, kvdb.dbDelete_Request):
        return None, 'kvdb/db/delete'
    if isinstance(message, kvdb.dbPut_Request):
        return None, 'kvdb/db/put'
    if isinstance(message, kvdb.managerGet_Request):
        return None, 'kvdb/manager/get'
    if isinstance(message, kvdb.managerPost_Request):
        return None, 'kvdb/manager/post'
    if isinstance(message, kvdb.managerDelete_Request):
        return None, 'kvdb/manager/delete'
    if isinstance(message, kvdb.managerDump_Request):
        return None, 'kvdb/manager/dump'

    # Policy
    if isinstance(message, policy.StorePost_Request):
        return None, 'policy/store/post'
    if isinstance(message, policy.StoreDelete_Request):
        return None, 'policy/store/delete'
    if isinstance(message, policy.StoreGet_Request):
        return None, 'policy/store/get'
    if isinstance(message, policy.AssetPost_Request):
        return None, 'policy/asset/post'
    if isinstance(message, policy.AssetDelete_Request):
        return None, 'policy/asset/delete'
    if isinstance(message, policy.AssetGet_Request):
        return None, 'policy/asset/get'
    if isinstance(message, policy.AssetCleanDeleted_Request):
        return None, 'policy/asset/cleanDeleted'

    if isinstance(message, policy.DefaultParentGet_Request):
        return None, 'policy/default_parent/get'
    if isinstance(message, policy.DefaultParentPost_Request):
        return None, 'policy/default_parent/post'
    if isinstance(message, policy.DefaultParentDelete_Request):
        return None, 'policy/default_parent/delete'

    if isinstance(message, policy.PoliciesGet_Request):
        return None, 'policy/list'
    if isinstance(message, policy.NamespacesGet_Request):
        return None, 'policy/namespaces/list'

    # Router
    if isinstance(message, router.RoutePost_Request):
        return None, 'router/route/post'
    if isinstance(message, router.RouteDelete_Request):
        return None, 'router/route/delete'
    if isinstance(message, router.RouteGet_Request):
        return None, 'router/route/get'
    if isinstance(message, router.RouteReload_Request):
        return None, 'router/route/reload'
    if isinstance(message, router.RoutePatchPriority_Request):
        return None, 'router/route/patchPriority'
    if isinstance(message, router.TableGet_Request):
        return None, 'router/table/get'
    if isinstance(message, router.QueuePost_Request):
        return None, 'router/queue/post'
    if isinstance(message, router.EpsGet_Request):
        return None, 'router/eps/getSettings'
    if isinstance(message, router.EpsEnable_Request):
        return None, 'router/eps/activate'
    if isinstance(message, router.EpsDisable_Request):
        return None, 'router/eps/deactivate'
    if isinstance(message, router.EpsUpdate_Request):
        return None, 'router/eps/changeSettings'

    # Tester
    if isinstance(message, tester.SessionPost_Request):
        return None, 'tester/session/post'
    if isinstance(message, tester.SessionDelete_Request):
        return None, 'tester/session/delete'
    if isinstance(message, tester.SessionGet_Request):
        return None, 'tester/session/get'
    if isinstance(message, tester.SessionReload_Request):
        return None, 'tester/session/reload'
    if isinstance(message, tester.TableGet_Request):
        return None, 'tester/table/get'
    if isinstance(message, tester.RunPost_Request):
        return None, 'tester/run/post'

    # Unknown
    return 'api-communication does not have the api command for the request, check the get_command method', ''
