from threading import Thread

import uvicorn
from fastapi import APIRouter, FastAPI

from wazuh.core.cluster.unix_server.config import get_config
from wazuh.core import common

SERVER_UNIX_SOCKET_PATH = common.WAZUH_RUN / 'config-server.sock'


def start_unix_server():
    """Start the local server using HTTP over a unix socket."""
    router = APIRouter(prefix='/api/v1')
    router.add_api_route('/config', get_config, methods=['GET'])

    app = FastAPI()
    app.include_router(router)

    t = Thread(target=uvicorn.run, kwargs={'app': app, 'uds': SERVER_UNIX_SOCKET_PATH}, daemon=True)
    t.start()
