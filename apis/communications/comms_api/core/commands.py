from typing import List

from fastapi import status
from uuid6 import UUID
from wazuh.core.commands_manager import CommandsManager
from wazuh.core.indexer.models.commands import Command

from comms_api.routers.exceptions import HTTPError


async def pull_commands(commands_manager: CommandsManager, agent_id: UUID) -> List[Command]:
    """Get commands from the indexer and mark them as sent.

    Parameters
    ----------
    commands_manager : CommandsManager
        Commands manager.
    agent_id : UUID
        Agent universally unique identifier.

    Returns
    -------
    List[Command]
        List of commands.
    """
    commands = await commands_manager.get_commands(agent_id)
    if commands is None:
        raise HTTPError(
            message='Request exceeded the processing time limit',
            status_code=status.HTTP_408_REQUEST_TIMEOUT,
        )

    return commands
