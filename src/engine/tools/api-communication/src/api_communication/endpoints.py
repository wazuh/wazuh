from typing import Optional, Tuple

from google.protobuf.message import Message

# Import all proto messages to deduce component, resource and action
import api_communication.proto.crud_pb2 as crud
import api_communication.proto.router_pb2 as router
import api_communication.proto.tester_pb2 as tester
import api_communication.proto.geo_pb2 as geo
import api_communication.proto.archiver_pb2 as archiver
import api_communication.proto.rawevtindexer_pb2 as rawevtindexer


def get_endpoint(message: Message) -> Tuple[Optional[str], str, str]:
    """Get the endpoint string and HTTP method for the given message

    Args:
        message (Message): Proto message

    Returns:
        Tuple[Optional[str], str, str]: Error string if any, endpoint string, HTTP method
    """
    endpoint = ''
    method = 'post'

    # Geo
    if isinstance(message, geo.DbGet_Request):
        endpoint = 'geo/db/get'
    if isinstance(message, geo.DbList_Request):
        endpoint = 'geo/db/list'

    # CRUD NS
    if isinstance(message, crud.namespacePost_Request):
        endpoint = '_internal/content/namespace/create'
    if isinstance(message, crud.namespaceDelete_Request):
        endpoint = '_internal/content/namespace/delete'
    if isinstance(message, crud.namespaceGet_Request):
        endpoint = '_internal/content/namespace/list'
    if isinstance(message, crud.namespaceImport_Request):
        endpoint = '_internal/content/namespace/import'

    # CRUD CM
    if isinstance(message, crud.resourcePost_Request):
        endpoint = '_internal/content/upsert'
    if isinstance(message, crud.resourceDelete_Request):
        endpoint = '_internal/content/delete'
    if isinstance(message, crud.resourceGet_Request):
        endpoint = '_internal/content/get'
    if isinstance(message, crud.resourceList_Request):
        endpoint = '_internal/content/list'
    if isinstance(message, crud.policyPost_Request):
        endpoint = '_internal/content/policy/upsert'
    if isinstance(message, crud.policyDelete_Request):
        endpoint = '_internal/content/policy/delete'
    if isinstance(message, crud.policyValidate_Request):
        endpoint = 'content/validate/policy'
    if isinstance(message, crud.resourceValidate_Request):
        endpoint = 'content/validate/resource'

    # Router
    if isinstance(message, router.RoutePost_Request):
        endpoint = 'router/route/post'
    if isinstance(message, router.RouteDelete_Request):
        endpoint = 'router/route/delete'
    if isinstance(message, router.RouteGet_Request):
        endpoint = 'router/route/get'
    if isinstance(message, router.RouteReload_Request):
        endpoint = 'router/route/reload'
    if isinstance(message, router.RoutePatchPriority_Request):
        endpoint = 'router/route/patchPriority'
    if isinstance(message, router.TableGet_Request):
        endpoint = 'router/table/get'
    if isinstance(message, router.EpsGet_Request):
        endpoint = 'router/eps/getSettings'
    if isinstance(message, router.EpsEnable_Request):
        endpoint = 'router/eps/activate'
    if isinstance(message, router.EpsDisable_Request):
        endpoint = 'router/eps/deactivate'
    if isinstance(message, router.EpsUpdate_Request):
        endpoint = 'router/eps/changeSettings'

    # Tester
    if isinstance(message, tester.SessionPost_Request):
        endpoint = 'tester/session/post'
    if isinstance(message, tester.SessionDelete_Request):
        endpoint = 'tester/session/delete'
    if isinstance(message, tester.SessionGet_Request):
        endpoint = 'tester/session/get'
    if isinstance(message, tester.SessionReload_Request):
        endpoint = 'tester/session/reload'
    if isinstance(message, tester.TableGet_Request):
        endpoint = 'tester/table/get'
    if isinstance(message, tester.RunPost_Request):
        endpoint = 'tester/run/post'
    if isinstance(message, tester.LogtestDelete_Request):
        endpoint = 'logtest'
        method = 'delete'

    # Archiver
    if isinstance(message, archiver.ArchiverActivate_Request):
        endpoint = 'archiver/activate'
    if isinstance(message, archiver.ArchiverDeactivate_Request):
        endpoint = 'archiver/deactivate'
    if isinstance(message, archiver.ArchiverStatus_Request):
        endpoint = 'archiver/status'

    # Raw event indexer
    if isinstance(message, rawevtindexer.RawEvtIndexerEnable_Request):
        endpoint = '_internal/raweventindexer/enable'
    if isinstance(message, rawevtindexer.RawEvtIndexerDisable_Request):
        endpoint = '_internal/raweventindexer/disable'
    if isinstance(message, rawevtindexer.RawEvtIndexerStatus_Request):
        endpoint = '_internal/raweventindexer/status'

    # Unknown
    if endpoint == '':
        return 'api-communication does not have the api command for the request, check the get_command method', '', ''

    return None, endpoint, method
