from typing import Annotated

from fastapi import APIRouter, Depends, Header, Request, Response, status

from comms_api.authentication.authentication import decode_token, JWTBearer
from comms_api.core.events import create_stateful_events, send_stateless_events
from comms_api.core.utils import parse_agent_metadata
from comms_api.models.events import StatefulEvents, StatefulEventsResponse, StatelessEvents
from comms_api.routers.exceptions import HTTPError
from comms_api.routers.utils import timeout
from wazuh.core.exception import WazuhEngineError, WazuhError, WazuhCommsAPIError


@timeout(30)
async def post_stateful_events(
    token: Annotated[str, Depends(JWTBearer())],
    user_agent: Annotated[str, Header()],
    request: Request,
    events: StatefulEvents,
    agent_groups: Annotated[str, Header()] = '',
) -> StatefulEventsResponse:
    """Handle posting stateful events.

    Parameters
    ----------
    token : str
        JWT token.
    user_agent : str
        User-Agent header value.
    request : Request
        Incoming HTTP request.
    events : StatefulEvents
        Events to post.
    agent_groups : str
        Agent-Groups header value. Default value is an emtpy string.

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
        agent_id = decode_token(token)["uuid"]
        agent_metadata = parse_agent_metadata(agent_id, user_agent, agent_groups)

        results = await create_stateful_events(agent_metadata, events, request.app.state.batcher_queue)
        return StatefulEventsResponse(results=results)
    except WazuhError as exc:
        raise HTTPError(message=exc.message, status_code=status.HTTP_400_BAD_REQUEST)
    except WazuhCommsAPIError as exc:
        raise HTTPError(message=exc.message, code=exc.code, status_code=status.HTTP_403_FORBIDDEN)



@timeout(10)
async def post_stateless_events(events: StatelessEvents) -> Response:
    """Post stateless events handler.

    Parameters
    ----------
    events : StatelessEvents
        Stateless events list.

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
        await send_stateless_events(events)
        return Response(status_code=status.HTTP_200_OK)
    except WazuhEngineError as exc:
        raise HTTPError(message=exc.message, code=exc.code, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


events_router = APIRouter(prefix='/events')
events_router.add_api_route('/stateful', post_stateful_events, dependencies=[Depends(JWTBearer())], methods=['POST'])
events_router.add_api_route('/stateless', post_stateless_events, dependencies=[Depends(JWTBearer())], methods=['POST'])
