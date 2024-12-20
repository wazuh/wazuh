import asyncio
from multiprocessing.managers import SyncManager
from multiprocessing.synchronize import Event
from typing import Dict, List, Optional

from fastapi import status
from uuid6 import UUID
from wazuh.core.indexer.models.commands import Command

from comms_api.routers.exceptions import HTTPError


class CommandsManager:
    """Expose commands received from the local server to the Communications API worker processes."""

    def __init__(self):
        self._manager: SyncManager = SyncManager()
        self._manager.start()
        self._commands: Dict[str, List[Command]] = self._manager.dict()
        self._subscriptions: Dict[str, Event] = self._manager.dict()

    def add_commands(self, commands: List[Command]) -> None:
        """Add a command to the dictionary and call the corresponding subscribers callbacks.

        Parameters
        ----------
        commands : List[Command]
            Commands list.
        """
        for command in commands:
            agent_id = command.target.id

            if agent_id not in self._subscriptions:
                continue

            if agent_id not in self._commands:
                self._commands[agent_id] = [command]
                continue

            # Using self._commands[agent_id].append() doesn't work because
            # it doesn't hold the reference of nested objects
            command_list = self._commands[agent_id]
            command_list.append(command)
            self._commands[agent_id] = command_list

        for agent_id in self._subscriptions.keys():
            if agent_id in self._subscriptions:
                self._subscriptions[agent_id].set()

    async def get_commands(self, agent_id: UUID) -> Optional[List[Command]]:
        """Get commands from the manager.

        It returns immediately if there are commands for the agent specified, otherwise it waits for new commands until
        the timeout is reached.

        Parameters
        ----------
        agent_id : UUID
            Agent ID.
        timeout : float
            Timeout in seconds.

        Returns
        -------
        Optional[List[Command]]
            Commands list or None if the timeout is reached.
        """
        if agent_id not in self._commands:
            event = asyncio.Event()
            self._subscriptions.update({agent_id: event})

            signaled = await event.wait()

            self._subscriptions.pop(agent_id, None)
            if not signaled:
                return

        return self._commands.pop(agent_id, None)

    def shutdown(self):
        """Shutdown sync manager."""
        self._manager.shutdown()


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
