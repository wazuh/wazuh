from argparse import ArgumentParser, Namespace
from fastapi import FastAPI
from time import sleep
import sys
import threading
from typing import List
import uvicorn

from api import router
from commands_manager import generate_commands

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

if __name__ == "__main__":
    args = get_script_arguments()

    generate_commands(args.agent_ids)

    try:
        uvicorn.run("main:app", host=args.host, port=args.port, workers=4)
    except Exception as e:
        print(f"Internal error: {e}")
        exit(1)
