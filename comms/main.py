from argparse import ArgumentParser, Namespace
from fastapi import FastAPI
from time import sleep
import sys
import threading
from typing import List
import uvicorn

from api import router
from commands_manager import commands_manager

app = FastAPI()
app.include_router(router)

def get_script_arguments() -> Namespace:
    """Get script arguments.

    Returns
    -------
    argparse.Namespace
        Arguments passed to the script.
    """
    parser = ArgumentParser()
    parser.add_argument("--host", type=str, default="0.0.0.0", help="API host.")
    parser.add_argument("-p", "--port", type=int, default=5000, help="API port.")
    parser.add_argument("-a", "--agent_ids", type=str, help="List of agent IDs.")

    return parser.parse_args()

def commands_generator(agent_ids: List[str]):
    try:
        generate_commands(agent_ids)

        while True:
            sleep(10)
            generate_commands(agent_ids)
    except Exception as e:
        print(f"Internal error: {e}")
        exit(1)

def generate_commands(agent_ids: List[str]):
    print("Generating new command", file=sys.stderr)
    command = {"id": "1", "type": "restart"}
    for uuid in agent_ids:
        commands_manager.add_command(uuid, command)

if __name__ == "__main__":
    args = get_script_arguments()

    if not args.agent_ids:
        ## Mock ID to send the command to at least one agent
        args.agent_ids = "018fe477-31c8-7580-ae4a-e0b36713eb05"

    commands_generator = threading.Thread(target=commands_generator, args=[args.agent_ids.split(",")])
    commands_generator.start()

    try:
        uvicorn.run(app, host=args.host, port=args.port)
    except Exception as e:
        print(f"Internal error: {e}")
        exit(1)
