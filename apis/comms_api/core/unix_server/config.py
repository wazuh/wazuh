from fastapi import Request, Response, status
from starlette.responses import JSONResponse

from wazuh.core.config.client import CentralizedConfig


async def get_config(request: Request) -> Response:
    """Retrieve the current configuration from the Server.

    Parameters
    ----------
    request : Request
        Incoming HTTP request.

    Returns
    -------
    JSONResponse
        HTTP OK response with the configuration as content.
    """
    config = CentralizedConfig.get_config_dic()

    return JSONResponse(status_code=status.HTTP_200_OK, content=config)
