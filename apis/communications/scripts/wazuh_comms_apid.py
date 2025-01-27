#!/usr/share/wazuh-server/framework/python/bin/python3

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
import logging.config
import os
import signal
import ssl
import sys
import atexit
from argparse import ArgumentParser, Namespace
from functools import partial
from sys import exit
from typing import Any, Callable
from multiprocessing import Process
from multiprocessing.util import _exit_function

from brotli_asgi import BrotliMiddleware
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from gunicorn.app.base import BaseApplication
from starlette.exceptions import HTTPException as StarletteHTTPException

from server_management_api.alogging import set_logging
from server_management_api.configuration import load_private_key, generate_self_signed_certificate
from server_management_api.middlewares import SecureHeadersMiddleware
from comms_api.core.batcher import create_batcher_process
from comms_api.core.commands import CommandsManager
from comms_api.core.unix_server.server import start_unix_server
from comms_api.middlewares.logging import LoggingMiddleware
from comms_api.routers.exceptions import HTTPError, http_error_handler, validation_exception_handler, \
    exception_handler, starlette_http_exception_handler
from comms_api.routers.router import router
from wazuh.core import common, pyDaemonModule, utils
from wazuh.core.exception import WazuhCommsAPIError
from wazuh.core.batcher.mux_demux import MuxDemuxQueue, MuxDemuxManager
from wazuh.core.cluster.utils import print_version
from wazuh.core.config.client import CentralizedConfig
from wazuh.core.config.models.logging import APILoggingConfig
from wazuh.core.config.models.comms_api import CommsAPIConfig
from wazuh.core.config.models.server import ServerConfig

MAIN_PROCESS = 'wazuh-comms-apid'
LOGGING_TAG = 'Communications API'


def create_app(batcher_queue: MuxDemuxQueue, commands_manager: CommandsManager) -> FastAPI:
    """Create a FastAPI application instance and add middlewares, exception handlers, and routers to it.

    Parameters
    ----------
    batcher_queue : MuxDemuxQueue
        Queue instance used for managing batcher processes.
    commands_manager : CommandsManager
        Commands manager.

    Returns
    -------
    FastAPI
        FastAPI application instance.
    """
    app = FastAPI()
    app.add_middleware(SecureHeadersMiddleware)
    app.add_middleware(BrotliMiddleware)
    app.add_middleware(LoggingMiddleware)
    app.add_exception_handler(HTTPError, http_error_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(Exception, exception_handler)
    app.add_exception_handler(StarletteHTTPException, starlette_http_exception_handler)
    app.include_router(router)

    app.state.batcher_queue = batcher_queue
    app.state.commands_manager = commands_manager

    return app


def setup_logging(logging_config: APILoggingConfig) -> dict:
    """Set up the logging module and returns the configuration used.

    Parameters
    ----------
    logging_config :  APILoggingConfig
        Logger configuration.

    Returns
    -------
    dict
        Logging configuration dictionary.
    """
    log_config = set_logging(logging_config=logging_config, tag=LOGGING_TAG)

    logging.config.dictConfig(log_config)

    return log_config


def configure_ssl(keyfile: str, certfile: str) -> None:
    """Generate SSL key file and self-siged certificate if they do not exist.

    Raises
    ------
    ssl.SSLError
        Invalid private key.
    IOError
        File permissions or path error.
    """
    try:
        if not os.path.exists(certfile):
            private_key = load_private_key(keyfile)
            logger.info(f"Generated private key file in {keyfile}")

            generate_self_signed_certificate(private_key, certfile)
            logger.info(f"Generated certificate file in {certfile}")
    except ssl.SSLError as exc:
        raise WazuhCommsAPIError(2700, extra_message=str(exc))
    except IOError as exc:
        if exc.errno == 22:
            raise WazuhCommsAPIError(2701, extra_message=str(exc))
        elif exc.errno == 13:
            raise WazuhCommsAPIError(2702, extra_message=str(exc))
        else:
            raise WazuhCommsAPIError(2703, extra_message=str(exc))


def ssl_context(conf, default_ssl_context_factory) -> ssl.SSLContext:
    """Return the default SSL context with a custom minimum version.

    Returns
    -------
    ssl.SSLContext
        Server SSL context.
    """
    context = default_ssl_context_factory()
    context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    return context


def post_worker_init(worker):
    """Unregister the _exit_function from the worker processes."""
    atexit.unregister(_exit_function)


def get_gunicorn_options(pid: int, log_config_dict: dict, config: CommsAPIConfig, server_config: ServerConfig) -> dict:
    """Get the gunicorn app configuration options.

    Parameters
    ----------
    pid : int
        Main process ID.
    log_config_dict : dict
        Logging configuration dictionary.
    config : CommsAPIConfig
        Comms API configuration object.

    Returns
    -------
    dict
        Gunicorn configuration options.
    """
    configure_ssl(server_config.jwt.private_key, config.ssl.cert)

    pidfile = common.WAZUH_RUN / f'{MAIN_PROCESS}-{pid}.pid'

    return {
        'proc_name': MAIN_PROCESS,
        'pidfile': str(pidfile),
        'daemon': False,
        'bind': f'{config.host}:{config.port}',
        'workers': config.workers,
        'worker_class': 'uvicorn.workers.UvicornWorker',
        'preload_app': True,
        'keyfile': server_config.jwt.private_key,
        'certfile': config.ssl.cert,
        'ca_certs': config.ssl.ca if config.ssl.use_ca else None,
        'ssl_context': ssl_context,
        'ciphers': config.ssl.ssl_ciphers,
        'logconfig_dict': log_config_dict,
        'user': os.getuid(),
        'post_worker_init': post_worker_init,
        'timeout': 300,
    }


def get_script_arguments() -> Namespace:
    """Get script arguments.

    Returns
    -------
    argparse.Namespace
        Arguments passed to the script.
    """
    parser = ArgumentParser()
    parser.add_argument('-r', '--root', action='store_true', dest='root', help='Run as root')
    parser.add_argument('-v', '--version', action='store_true', dest='version', help='Print version')
    return parser.parse_args()


class StandaloneApplication(BaseApplication):
    def __init__(self, app: Callable, options: dict[str, Any] = None):
        self.options = options or {}
        self.app = app
        super().__init__()

    def load_config(self):
        config = {
            key: value
            for key, value in self.options.items()
            if key in self.cfg.settings and value is not None
        }
        for key, value in config.items():
            self.cfg.set(key.lower(), value)

    def load(self):
        return self.app


def signal_handler(
    signum: int,
    frame: Any,
    parent_pid: int,
    mux_demux_manager: MuxDemuxManager,
    batcher_process: Process,
    commands_manager: CommandsManager
) -> None:
    """Handle incoming signals to gracefully shutdown the API.

    Parameters
    ----------
    signum : int
        The signal number received.
    frame : Any
        The current stack frame (unused).
    parent_pid : int
        The parent process ID used to verify if the termination should proceed.
    mux_demux_manager : MuxDemuxManager
        The MuxDemux manager instance to be shut down.
    batcher_process : Process
        The batcher process to be terminated.
    commands_manager : CommandsManager
        Commands manager.
    """
    logger.info(f"Received signal {signal.Signals(signum).name}, shutting down")
    terminate_processes(parent_pid, mux_demux_manager, batcher_process, commands_manager)


def terminate_processes(
    parent_pid: int, mux_demux_manager: MuxDemuxManager, batcher_process: Process, commands_manager: CommandsManager
) -> None:
    """Terminate all related resources, and delete child and main processes
    if the current process ID matches the parent process ID.

    Parameters
    ----------
    parent_pid : int
        The parent process ID used to verify if the termination should proceed.
    mux_demux_manager : MuxDemuxManager
        The MuxDemux manager instance to be shut down.
    batcher_process : Process
        The batcher process to be terminated.
    commands_manager : CommandsManager
        Commands manager.
    """
    if parent_pid == os.getpid():
        logger.info('Shutting down')
        mux_demux_manager.shutdown()
        batcher_process.terminate()
        commands_manager.shutdown()
        pyDaemonModule.delete_child_pids(MAIN_PROCESS, pid, logger)
        pyDaemonModule.delete_pid(MAIN_PROCESS, pid)


if __name__ == '__main__':
    args = get_script_arguments()

    if args.version:
        print_version()
        sys.exit(0)

    try:
        CentralizedConfig.load()
    except Exception as e:
        print(f"Error when trying to load the configuration. {e}")
        sys.exit(1)

    comms_api_config = CentralizedConfig.get_comms_api_config()
    server_config = CentralizedConfig.get_server_config()

    utils.clean_pid_files(MAIN_PROCESS)

    log_config_dict = setup_logging(logging_config=comms_api_config.logging)
    logger = logging.getLogger('wazuh-comms-api')

    if not args.root:
        logger.info('Starting API')
        # Drop privileges to wazuh
        os.setgid(common.wazuh_gid())
        os.setuid(common.wazuh_uid())
    else:
        logger.info('Starting API as root')

    mux_demux_manager, batcher_process = create_batcher_process(config=comms_api_config.batcher)

    # Start HTTP over unix socket server
    commands_manager = CommandsManager()
    start_unix_server(commands_manager)

    pid = os.getpid()
    signal.signal(
        signal.SIGTERM,
        partial(
            signal_handler, parent_pid=pid, mux_demux_manager=mux_demux_manager, batcher_process=batcher_process,
            commands_manager=commands_manager
        )
    )
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    logger.info(f'Listening on {comms_api_config.host}:{comms_api_config.port}')

    exit_code = 0
    try:
        app = create_app(mux_demux_manager.get_queue(), commands_manager)
        options = get_gunicorn_options(pid, log_config_dict, comms_api_config, server_config)
        StandaloneApplication(app, options).run()
    except WazuhCommsAPIError as e:
        logger.error(f'Error when trying to start the Wazuh Communications API. {e}')
        exit_code = 1
    except Exception as e:
        logger.error(f'Internal error when trying to start the Wazuh Communications API. {e}')
        exit_code = 1
    finally:
        terminate_processes(pid, mux_demux_manager, batcher_process, commands_manager)
        exit(exit_code)
