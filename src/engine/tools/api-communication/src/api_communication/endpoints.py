from typing import Optional, Tuple

from google.protobuf.message import Message

# Import all proto messages to deduce component, resource and action
import api_communication.proto.crud_pb2 as crud
import api_communication.proto.router_pb2 as router
import api_communication.proto.tester_pb2 as tester
import api_communication.proto.geo_pb2 as geo
import api_communication.proto.archiver_pb2 as archiver


def get_endpoint(message: Message) -> Tuple[Optional[str], str]:
    """Get the endpoint string for the given message

    Args:
        message (Message): Proto message

    Returns:
        Tuple[Optional[str], str]: Error string if any, endpoint string
    """

    # Geo
    if isinstance(message, geo.DbGet_Request):
        return None, 'geo/db/get'
    if isinstance(message, geo.DbList_Request):
        return None, 'geo/db/list'

    # CRUD NS
    if isinstance(message, crud.namespacePost_Request):
        return None, '_internal/content/namespace/create'
    if isinstance(message, crud.namespaceDelete_Request):
        return None, '_internal/content/namespace/delete'
    if isinstance(message, crud.namespaceGet_Request):
        return None, '_internal/content/namespace/list'
    if isinstance(message, crud.namespaceImport_Request):
        return None, '_internal/content/namespace/import'

    # CRUD CM
    if isinstance(message, crud.resourcePost_Request):
        return None, '_internal/content/upsert'
    if isinstance(message, crud.resourceDelete_Request):
        return None, '_internal/content/delete'
    if isinstance(message, crud.resourceGet_Request):
        return None, '_internal/content/get'
    if isinstance(message, crud.resourceList_Request):
        return None, '_internal/content/list'
    if isinstance(message, crud.policyPost_Request):
        return None, '_internal/content/policy/upsert'
    if isinstance(message, crud.policyDelete_Request):
        return None, '_internal/content/policy/delete'
    if isinstance(message, crud.policyValidate_Request):
        return None, 'content/validate/policy'
    if isinstance(message, crud.resourceValidate_Request):
        return None, 'content/validate/resource'

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
    if isinstance(message, tester.LogtestDelete_Request):
        return None, 'logtest'

    # Archiver
    if isinstance(message, archiver.ArchiverActivate_Request):
        return None, 'archiver/activate'
    if isinstance(message, archiver.ArchiverDeactivate_Request):
        return None, 'archiver/deactivate'
    if isinstance(message, archiver.ArchiverStatus_Request):
        return None, 'archiver/status'

    # Unknown
    return 'api-communication does not have the api command for the request, check the get_command method', ''
