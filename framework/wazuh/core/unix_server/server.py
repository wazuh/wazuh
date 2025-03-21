from threading import Thread
from typing import Any, Callable

import uvicorn
from fastapi import APIRouter, FastAPI
from wazuh.core.commands_manager import CommandsManager


class HTTPUnixServer:
    """Unix server over HTTP to communicate between processes."""

    def __init__(self, socket_path: str, commands_manager: CommandsManager):
        self.socket_path = socket_path
        self.commands_manager = commands_manager
        self.router = APIRouter(prefix='/api/v1')

    def add_route(self, path: str, handler: Callable[..., Any], methods: list[str]):
        """Add route to the server.

        Parameters
        ----------
        path : str
            Path to the unix socket.
        handler : Callable[..., Any]
            Endpoint handler.
        methods : list[str]
            Supported HTTP methods.
        """
        self.router.add_api_route(path=path, endpoint=handler, methods=methods)

    def start(self):
        """Start server inside a thread."""
        app = FastAPI()
        app.include_router(self.router)
        app.state.commands_manager = self.commands_manager

        t = Thread(target=uvicorn.run, kwargs={'app': app, 'uds': self.socket_path}, daemon=True)
        t.start()
