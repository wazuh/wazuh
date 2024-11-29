import contextlib
import json
import logging
import time

from starlette.requests import Request
from starlette.responses import Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

logger = logging.getLogger('wazuh-comms-api')


async def log_request(request: Request, response: Response, start_time: time) -> None:
    """Generates a log message from a request.

    Parameters
    ----------
    request : Request
        HTTP request received.
    response : Response
        HTTP response created.
    start_time : time
        Time at the start of the request.
    """
    elapsed_time = time.time() - start_time
    agent_uuid = request.state.agent_uuid if hasattr(request.state, 'agent_uuid') else None
    path = request.scope.get('path', '') if hasattr(request, 'scope') else ''
    method = getattr(request, 'method', '')
    query = dict(getattr(request, 'query_params', {}))
    body = await request.json() if hasattr(request, '_json') else {}
    status_code = response.status_code

    if 'key' in body and '/authentication' in path:
        body['key'] = '***'

    if logger.isEnabledFor(logging.DEBUG):
        await log_request_debug(request, path)

    log_info = f'({agent_uuid}) ' if agent_uuid is not None else ''
    log_info += f'"{method} {path}" with parameters {json.dumps(query)} and body '
    log_info += f'{json.dumps(body)} done in {elapsed_time:.3f}s: {status_code}'
    json_info = {
        'http_method': method,
        'uri': f'{method} {path}',
        'parameters': query,
        'body': body,
        'time': f'{elapsed_time:.3f}s',
        'status_code': status_code
    }
    if agent_uuid is not None:
        json_info['agent_uuid'] = agent_uuid

    logger.info(log_info, extra={'log_type': 'log'})
    logger.info(json_info, extra={'log_type': 'json'})


async def log_request_debug(request: Request, path: str) -> None:
    """Log request headers and body JSON streams.

    Parameters
    ----------
    request : Request
        HTTP request received.
    path : str
        URL path.
    """
    logger.debug(f'Request headers: {dict(request.headers.items())}', extra={'log_type': 'log'})

    if '/events' in path:
        body = b''
        async for chunk in request.stream():
            body += chunk
        
        logger.debug(f'Request body stream: {body.decode()}',  extra={'log_type': 'log'})


class LoggingMiddleware(BaseHTTPMiddleware):
    """Middleware to log requests information."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Logs Communications API requests.

        Parameters
        ----------
        request : Request
            HTTP Request received.
        call_next :  RequestResponseEndpoint
            Endpoint callable to be executed.

        Returns
        -------
        Response
            Endpoint response.
        """
        start_time = time.time()

        body = await request.body()
        if body:
            with contextlib.suppress(json.decoder.JSONDecodeError):
                # Load the request body to the _json field before calling the controller so it's cached before the 
                # stream is consumed. If there's a json error we skip it so it's handled later.
                # Related to https://github.com/wazuh/wazuh/issues/24060.
                _ = await request.json()

        response = await call_next(request)
        _ = await log_request(request, response, start_time)
        return response
