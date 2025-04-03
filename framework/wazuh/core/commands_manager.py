from multiprocessing.managers import SyncManager
from multiprocessing.synchronize import Event
from typing import Dict, List, Optional

from uuid6 import UUID
from wazuh.core.indexer.models.commands import Command


class CommandsManager:
    """Expose commands received from the local server to the APIs processes."""

    def __init__(self):
        self._manager: SyncManager = SyncManager()
        self._manager.start()
        self._commands: Dict[str, List[Command]] = self._manager.dict()
        self._subscriptions: Dict[str, Event] = self._manager.dict()

    def add_commands(self, commands: List[Command]) -> List[Command]:
        """Add a command to the dictionary and call the corresponding subscribers callbacks.

        Parameters
        ----------
        commands : List[Command]
            Commands list.

        Returns
        -------
        List[str]
            List of the processed commands.
        """
        processed_commands = []
        for command in commands:
            target_id = command.target.id

            if target_id not in self._subscriptions:
                continue

            if target_id not in self._commands:
                self._commands[target_id] = [command]
                processed_commands.append(command)
                continue

            # Using self._commands[agent_id].append() doesn't work because
            # it doesn't hold the reference of nested objects
            command_list = self._commands[target_id]
            command_list.append(command)
            self._commands[target_id] = command_list
            processed_commands.append(command)

        for target_id in self._subscriptions.keys():
            if target_id in self._subscriptions:
                self._subscriptions[target_id].set()

        return processed_commands

    def get_commands(self, target_id: UUID) -> Optional[List[Command]]:
        """Get commands from the manager.

        It returns immediately if there are commands for the target specified, otherwise it waits for new commands until
        the timeout is reached.

        Parameters
        ----------
        target_id : UUID
            Target ID.
        timeout : float
            Timeout in seconds.

        Returns
        -------
        Optional[List[Command]]
            Commands list or None if the timeout is reached.
        """
        if target_id not in self._commands:
            event = self._manager.Event()
            self._subscriptions.update({target_id: event})

            signaled = event.wait()

            self._subscriptions.pop(target_id, None)
            if not signaled:
                return

        return self._commands.pop(target_id, None)

    def shutdown(self):
        """Shutdown sync manager."""
        self._manager.shutdown()
