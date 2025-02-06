from threading import Thread
from typing import Any

import uvicorn
from fastapi import APIRouter, FastAPI
from wazuh.core import common
from wazuh.core.cluster.unix_server.config import get_config


def get_log_config(node: str) -> dict[str, Any]:
    """Generate a logging configuration with a consistent format.

    Parameters
    ----------
    node: str
        Identifier for the node to include in the log messages.

    Returns
    -------
    dict[str, Any]
        A dictionary containing the logging configuration for Uvicorn.
    """
    log_config = uvicorn.config.LOGGING_CONFIG
    log_config['formatters']['default']['fmt'] = f'%(asctime)s %(levelname)s: [{node}] [Config Server] %(message)s'
    log_config['formatters']['default']['datefmt'] = '%Y/%m/%d %H:%M:%S'

    for handler in log_config['handlers'].values():
        if 'formatter' in handler:
            handler['formatter'] = 'default'

    return log_config


def start_unix_server(node: str):
    """Start the local server using HTTP over a unix socket."""
    router = APIRouter(prefix='/api/v1')
    router.add_api_route('/config', get_config, methods=['GET'])

    app = FastAPI()
    app.include_router(router)

    log_config = get_log_config(node=node)
    t = Thread(target=uvicorn.run,
               kwargs={'app': app, 'uds': common.CONFIG_SERVER_SOCKET_PATH, 'log_config': log_config},
               daemon=True)
    t.start()
