from typing import Annotated

from fastapi import Depends, Request, status
from wazuh.core.exception import WazuhCommsAPIError

from comms_api.authentication.authentication import JWTBearer, decode_token
from comms_api.core.commands import pull_commands
from comms_api.models.commands import Commands
from comms_api.routers.exceptions import HTTPError
from comms_api.routers.utils import timeout


@timeout(30)
async def get_commands(token: Annotated[str, Depends(JWTBearer())], request: Request) -> Commands:
    """Get commands endpoint handler.

    Parameters
    ----------
    token : str
        JWT token.
    request : Request
        Incoming HTTP request.

    Raises
    ------
    HTTPError
        If there is any system or validation error.

    Returns
    -------
    Commands
        List of commands.
    """
    try:
        uuid = decode_token(token)['uuid']
        commands = await pull_commands(request.app.state.commands_manager, uuid)
        return Commands(commands=commands)
    except WazuhCommsAPIError as exc:
        raise HTTPError(message=exc.message, code=exc.code, status_code=status.HTTP_403_FORBIDDEN)
