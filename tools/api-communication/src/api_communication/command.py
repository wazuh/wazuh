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
import api_communication.proto.test_pb2 as test


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
        return None, 'policy.defaultparent/get'
    elif isinstance(message, policy.DefaultParentPost_Request):
        return None, 'policy.defaultparent/post'
    elif isinstance(message, policy.DefaultParentDelete_Request):
        return None, 'policy.defaultparent/delete'
    elif isinstance(message, policy.PoliciesGet_Request):
        return None, 'policy.policies/get'
    elif isinstance(message, policy.NamespacesGet_Request):
        return None, 'policy.namespaces/get'

    # Router
    elif isinstance(message, router.RouteGet_Request):
        return None, 'router.route/get'
    elif isinstance(message, router.RoutePost_Request):
        return None, 'router.route/post'
    elif isinstance(message, router.RoutePatch_Request):
        return None, 'router.route/patch'
    elif isinstance(message, router.RouteDelete_Request):
        return None, 'router.route/delete'
    elif isinstance(message, router.TableGet_Request):
        return None, 'router.table/get'
    elif isinstance(message, router.QueuePost_Request):
        return None, 'router.queue/post'

    # Test
    elif isinstance(message, test.SessionGet_Request):
        return None, 'test.session/get'
    elif isinstance(message, test.SessionPost_Request):
        return None, 'test.session/post'
    elif isinstance(message, test.SessionsGet_Request):
        return None, 'test.sessions/get'
    elif isinstance(message, test.SessionsDelete_Request):
        return None, 'test.sessions/delete'
    elif isinstance(message, test.RunPost_Request):
        return None, 'test.run/post'

    else:
        return 'Unknown message type', ''
