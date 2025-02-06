from threading import Thread

import uvicorn
from fastapi import APIRouter, FastAPI
from wazuh.core import common

from comms_api.core.commands import CommandsManager
from comms_api.core.unix_server.commands import post_commands


def start_unix_server(commands_manager: CommandsManager):
    """Start the local server using HTTP over a unix socket.

    Parameters
    ----------
    commands_manager : CommandsManager
        Commands manager.
    """
    router = APIRouter(prefix='/api/v1')
    router.add_api_route('/commands', post_commands, methods=['POST'])

    app = FastAPI()
    app.include_router(router)
    app.state.commands_manager = commands_manager

    t = Thread(target=uvicorn.run, kwargs={'app': app, 'uds': common.COMMS_API_SOCKET_PATH}, daemon=True)
    t.start()
