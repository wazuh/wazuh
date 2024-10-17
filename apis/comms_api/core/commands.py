import asyncio
from typing import List

from uuid6 import UUID

from wazuh.core.indexer import get_indexer_client
from wazuh.core.indexer.models.commands import Command, Status


async def pull_commands(uuid: UUID) -> List[Command]:
    """Get commands from the indexer and mark them as sent.

    Parameters
    ----------
    uuid : UUID
        Agent universally unique identifier.
    
    Returns
    -------
    List[Command]
        List of commands.
    """
    async with get_indexer_client() as indexer_client:
        while True:
            commands = await indexer_client.commands_manager.get(uuid, Status.PENDING)
            if commands is None:
                # TODO(#25121): get sleep time from the configuration?
                await asyncio.sleep(5)
                continue

            for command in commands:
                command.status = Status.SENT

            await indexer_client.commands_manager.update(commands)

            return commands
