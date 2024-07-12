from typing import Optional, Tuple

from google.protobuf.message import Message

# Import all proto messages to deduce component, resource and action
import api_communication.proto.catalog_pb2 as catalog
import api_communication.proto.config_pb2 as config
import api_communication.proto.graph_pb2 as graph
import api_communication.proto.kvdb_pb2 as kvdb
import api_communication.proto.metrics_pb2 as metrics
import api_communication.proto.policy_pb2 as policy
import api_communication.proto.router_pb2 as router
import api_communication.proto.tester_pb2 as tester
import api_communication.proto.geo_pb2 as geo


def get_command(message: Message) -> Tuple[Optional[str], str]:
    """Get the command string for the given message

    Args:
        message (Message): Proto message

    Returns:
        Tuple[Optional[str], str]: Error string if any, command string
    """

    # Catalog
    if isinstance(message, catalog.ResourcePost_Request):
        return None, 'catalog.resource/post'
    elif isinstance(message, catalog.ResourceGet_Request):
        return None, 'catalog.resource/get'
    elif isinstance(message, catalog.ResourcePut_Request):
        return None, 'catalog.resource/put'
    elif isinstance(message, catalog.ResourceDelete_Request):
        return None, 'catalog.resource/delete'
    elif isinstance(message, catalog.ResourceValidate_Request):
        return None, 'catalog.resource/validate'
    elif isinstance(message, catalog.NamespacesGet_Request):
        return None, 'catalog.namespaces/get'

    # Config
    elif isinstance(message, config.RuntimeGet_Request):
        return None, 'config.runtime/get'
    elif isinstance(message, config.RuntimePut_Request):
        return None, 'config.runtime/put'
    elif isinstance(message, config.RuntimeSave_Request):
        return None, 'config.runtime/save'

    # Graph
    elif isinstance(message, graph.GraphGet_Request):
        return None, 'graph.resource/get'

    # KVDB
    elif isinstance(message, kvdb.dbGet_Request):
        return None, 'kvdb.db/get'
    elif isinstance(message, kvdb.dbSearch_Request):
        return None, 'kvdb.db/search'
    elif isinstance(message, kvdb.dbDelete_Request):
        return None, 'kvdb.db/delete'
    elif isinstance(message, kvdb.dbPut_Request):
        return None, 'kvdb.db/put'
    elif isinstance(message, kvdb.managerGet_Request):
        return None, 'kvdb.manager/get'
    elif isinstance(message, kvdb.managerPost_Request):
        return None, 'kvdb.manager/post'
    elif isinstance(message, kvdb.managerDelete_Request):
        return None, 'kvdb.manager/delete'
    elif isinstance(message, kvdb.managerDump_Request):
        return None, 'kvdb.manager/dump'

    # Metrics
    elif isinstance(message, metrics.Dump_Request):
        return None, 'metrics/dump'
    elif isinstance(message, metrics.Get_Request):
        return None, 'metrics/get'
    elif isinstance(message, metrics.Enable_Request):
        return None, 'metrics/enable'
    elif isinstance(message, metrics.List_Request):
        return None, 'metrics/list'
    elif isinstance(message, metrics.Test_Request):
        return None, 'metrics/test'

    # Policy
    elif isinstance(message, policy.StorePost_Request):
        return None, 'policy.store/post'
    elif isinstance(message, policy.StoreDelete_Request):
        return None, 'policy.store/delete'
    elif isinstance(message, policy.StoreGet_Request):
        return None, 'policy.store/get'
    elif isinstance(message, policy.AssetPost_Request):
        return None, 'policy.asset/post'
    elif isinstance(message, policy.AssetDelete_Request):
        return None, 'policy.asset/delete'
    elif isinstance(message, policy.AssetGet_Request):
        return None, 'policy.asset/get'
    elif isinstance(message, policy.DefaultParentGet_Request):
        return None, 'policy.defaultParent/get'
    elif isinstance(message, policy.DefaultParentPost_Request):
        return None, 'policy.defaultParent/post'
    elif isinstance(message, policy.DefaultParentDelete_Request):
        return None, 'policy.defaultParent/delete'
    elif isinstance(message, policy.PoliciesGet_Request):
        return None, 'policy.policies/get'
    elif isinstance(message, policy.NamespacesGet_Request):
        return None, 'policy.namespaces/get'
    elif isinstance(message, policy.AssetCleanDeleted_Request):
        return None, 'policy.asset/cleanDeleted'

    # Router
    elif isinstance(message, router.RoutePost_Request):
        return None, 'router.route/post'
    elif isinstance(message, router.RouteDelete_Request):
        return None, 'router.route/delete'
    elif isinstance(message, router.RouteGet_Request):
        return None, 'router.route/get'
    elif isinstance(message, router.RouteReload_Request):
        return None, 'router.route/reload'
    elif isinstance(message, router.RoutePatchPriority_Request):
        return None, 'router.route/patchPriority'
    elif isinstance(message, router.TableGet_Request):
        return None, 'router.table/get'
    elif isinstance(message, router.QueuePost_Request):
        return None, 'router.queue/post'

    # Tester
    elif isinstance(message, tester.SessionPost_Request):
        return None, 'tester.session/post'
    elif isinstance(message, tester.SessionDelete_Request):
        return None, 'tester.session/delete'
    elif isinstance(message, tester.SessionGet_Request):
        return None, 'tester.session/get'
    elif isinstance(message, tester.SessionReload_Request):
        return None, 'tester.session/reload'
    elif isinstance(message, tester.TableGet_Request):
        return None, 'tester.table/get'
    elif isinstance(message, tester.RunPost_Request):
        return None, 'tester.run/post'

    # Geo
    elif isinstance(message, geo.DbList_Request):
        return None, 'geo.db/list'
    elif isinstance(message, geo.DbPost_Request):
        return None, 'geo.db/post'
    elif isinstance(message, geo.DbDelete_Request):
        return None, 'geo.db/delete'
    elif isinstance(message, geo.DbRemoteUpsert_Request):
        return None, 'geo.db/remoteUpsert'

    # Unknown
    else:
        return 'api-communication does not have the api command for the request, check the get_command method', ''
