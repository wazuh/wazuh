from asyncio import sleep
from typing import Dict, List

from models import Command

timeout = 60

class CommandsManager:
    __commands: Dict[str, List[Command]] = {}

    def add_command(self, uuid: str, command: Command) -> None:
        if uuid in self.__commands:
            self.__commands[uuid].append(command)
        else:
            self.__commands[uuid] = [command]

    async def get_commands(self, uuid: str) -> List[Command]:
        for _ in range(timeout):
            if uuid in self.__commands and len(self.__commands[uuid]) > 0:
                # TODO: these operations should be atomic and thread-safe
                commands = self.__commands[uuid][:]
                self.__commands[uuid][:] = []
                return commands
            else:
                await sleep(1)

        return None

commands_manager = CommandsManager()
