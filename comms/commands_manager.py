import asyncio
from multiprocessing import Manager, Process
from multiprocessing.managers import SyncManager
import sys
from typing import Dict, List
import time

from models import Command

class CommandsManager():

    def __init__(self):
        self.manager: SyncManager = Manager()
        self.commands: Dict[str, List[Command]] = self.manager.dict()
        self.timeout: int = 60

    def add_command(self, uuid: str, command: Command) -> None:
        lock = self.manager.Lock()
        lock.acquire()

        if uuid in self.commands:
            # Using self.__commands[uuid].append() doesn't work because
            # it doesn't hold the reference of nested objects
            commands_list = self.commands[uuid]
            commands_list.append(command)
            self.commands[uuid] = commands_list
        else:
            self.commands[uuid] = [command]

        lock.release()

    async def get_commands(self, uuid: str) -> List[Command]:
        for _ in range(self.timeout):
            if uuid in self.commands and len(self.commands[uuid]) > 0:
                lock = self.manager.Lock()
                lock.acquire()

                commands = self.commands[uuid][:]
                del self.commands[uuid]

                lock.release()
                return commands
            else:
                await asyncio.sleep(1)

        return None

commands_manager = CommandsManager()

def run(agent_ids: List[str]):
    try:
        send_commands(agent_ids)

        while True:
            time.sleep(10)
            send_commands(agent_ids)
    except Exception as e:
        print(f"Internal error: {e}")
        exit(1)

def send_commands(agent_ids: List[str]):
    print("Sending new command", file=sys.stderr)

    if len(agent_ids) == 0:
        ## Mock ID to send the command to at least one agent
        agent_ids = ["018fe477-31c8-7580-ae4a-e0b36713eb05"]

    command = {"id": "1", "type": "restart"}
    for uuid in agent_ids:
        commands_manager.add_command(uuid, command)

def generate_commands(agent_ids: List[str]):
    p = Process(target=run, args=[agent_ids.split(",")])
    p.start()
