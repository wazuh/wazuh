from fastapi import APIRouter, Depends, Request, Response, status
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
from wazuh.core.exception import WazuhEngineError, WazuhError, WazuhIndexerError

from comms_api.authentication.authentication import JWTBearer
from comms_api.core.events import parse_stateful_events, send_stateful_events, send_stateless_events
from comms_api.models.events import StatefulEventsResponse
from comms_api.routers.exceptions import HTTPError, validation_exception_handler
from comms_api.routers.utils import timeout


@timeout(30)
async def post_stateful_events(request: Request) -> StatefulEventsResponse:
    """Handle posting stateful events.

    Parameters
    ----------
    request : Request
        Incoming HTTP request.

    Raises
    ------
    HTTPError
        If there is an error when indexing the events.

    Returns
    -------
    JSONResponse
        Response from the Indexer.
    """
    try:
        events = await parse_stateful_events(request)
        results = await send_stateful_events(events, request.app.state.batcher_queue)
        return StatefulEventsResponse(results=results)
    except WazuhError as exc:
        raise HTTPError(message=exc.message, status_code=status.HTTP_400_BAD_REQUEST)
    except WazuhIndexerError as exc:
        raise HTTPError(message=exc.message, code=exc.code, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    except ValidationError as exc:
        return await validation_exception_handler(request, RequestValidationError(exc.errors()))


@timeout(10)
async def post_stateless_events(request: Request) -> Response:
    """Post stateless events handler.

    Parameters
    ----------
    request : Request
        Incoming HTTP request.

    Raises
    ------
    HTTPError
        If there is any error when communicating with the engine.

    Returns
    -------
    Response
        HTTP OK empty response.
    """
    try:
        await send_stateless_events(request)
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    except WazuhError as exc:
        raise HTTPError(message=exc.message, status_code=status.HTTP_400_BAD_REQUEST)
    except WazuhEngineError as exc:
        raise HTTPError(message=exc.message, code=exc.code, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


events_router = APIRouter(prefix='/events')
events_router.add_api_route('/stateful', post_stateful_events, dependencies=[Depends(JWTBearer())], methods=['POST'])
events_router.add_api_route('/stateless', post_stateless_events, dependencies=[Depends(JWTBearer())], methods=['POST'])
