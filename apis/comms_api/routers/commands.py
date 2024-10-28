from typing import Annotated

from fastapi import Depends, status

from comms_api.authentication.authentication import decode_token, JWTBearer
from comms_api.core.commands import pull_commands
from comms_api.models.commands import Commands
from comms_api.routers.exceptions import HTTPError
from comms_api.routers.utils import timeout
from wazuh.core.exception import WazuhCommsAPIError, WazuhResourceNotFound


@timeout(30)
async def get_commands(token: Annotated[str, Depends(JWTBearer())]) -> Commands:
    """Get commands endpoint handler.

    Parameters
    ----------
    token : str
        JWT token.

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
        uuid = decode_token(token)["uuid"]
        commands = await pull_commands(uuid)
        return Commands(commands=commands)
    except WazuhCommsAPIError as exc:
        raise HTTPError(message=exc.message, code=exc.code, status_code=status.HTTP_403_FORBIDDEN)
    except WazuhResourceNotFound as exc:
        raise HTTPError(message=exc.message, code=exc.code, status_code=status.HTTP_404_NOT_FOUND)
