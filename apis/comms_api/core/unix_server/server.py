from threading import Thread

import uvicorn
from fastapi import APIRouter, FastAPI

from comms_api.core.unix_server.commands import post_commands
from comms_api.core.commands import CommandsManager
from wazuh.core import common


UNIX_SOCKET_PATH = common.WAZUH_SOCKET / 'comms-api.sock'


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

    t = Thread(target=uvicorn.run, kwargs={'app': app, 'uds': UNIX_SOCKET_PATH}, daemon=True)
    t.start()
