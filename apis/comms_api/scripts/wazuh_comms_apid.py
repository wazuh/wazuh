import logging
import logging.config
import os
import signal
import ssl
from argparse import ArgumentParser, Namespace
from functools import partial
from sys import exit
from typing import Any, Callable, Dict
from multiprocessing import Process

from brotli_asgi import BrotliMiddleware
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from gunicorn.app.base import BaseApplication
from starlette.exceptions import HTTPException as StarletteHTTPException

from api.alogging import set_logging
from api.configuration import generate_private_key, generate_self_signed_certificate
from api.constants import COMMS_API_LOG_PATH
from api.middlewares import SecureHeadersMiddleware
from comms_api.routers.exceptions import HTTPError, http_error_handler, validation_exception_handler, \
    exception_handler, starlette_http_exception_handler
from comms_api.routers.router import router
from comms_api.middlewares.logging import LoggingMiddleware
from comms_api.core.batcher import create_batcher_process
from wazuh.core import common, pyDaemonModule, utils
from wazuh.core.exception import WazuhCommsAPIError
from wazuh.core.batcher.config import BatcherConfig
from wazuh.core.batcher.mux_demux import MuxDemuxQueue, MuxDemuxManager

# TODO(#25121) - Delete after centralized configuration
from wazuh.core.batcher.config import BATCHER_MAX_ELEMENTS, BATCHER_MAX_SIZE, BATCHER_MAX_TIME_SECONDS

MAIN_PROCESS = 'wazuh-comms-apid'


def create_app(batcher_queue: MuxDemuxQueue) -> FastAPI:
    """Creates a FastAPI application instance and adds middlewares, exceptions handlers and routers to it."""
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

    return app


def setup_logging(foreground_mode: bool) -> dict:
    """Sets up the logging module and returns the configuration used.

    Parameters
    ----------
    foreground_mode : bool
        Whether to execute the script in foreground mode or not.

    Returns
    -------
    dict
        Logging configuration dictionary.
    """
    log_config_dict = set_logging(log_filepath=COMMS_API_LOG_PATH,
                                  log_level='INFO',
                                  foreground_mode=foreground_mode)

    for handler in log_config_dict['handlers'].values():
        if 'filename' in handler:
            utils.assign_wazuh_ownership(handler['filename'])
            os.chmod(handler['filename'], 0o660)

    logging.config.dictConfig(log_config_dict)

    return log_config_dict


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
        if not os.path.exists(keyfile) or not os.path.exists(certfile):
            private_key = generate_private_key(keyfile)
            logger.info(f"Generated private key file in {certfile}")
            
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
    """Returns the default SSL context with a custom minimum version.

    Returns
    -------
    ssl.SSLContext
        Server SSL context.
    """
    context = default_ssl_context_factory()
    context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    return context


def get_gunicorn_options(pid: int, foreground_mode: bool, log_config_dict: dict) -> dict:
    """Get the gunicorn app configuration options.

    Parameters
    ----------
    pid : int
        Main process ID.
    foreground_mode : bool
        Whether to execute the script in foreground mode or not.
    log_config_dict : dict
        Logging configuration dictionary.

    Returns
    -------
    dict
        Gunicorn configuration options.
    """
    # TODO(#25121): get values from the configuration
    keyfile = '/var/ossec/api/configuration/ssl/server.key'
    certfile = '/var/ossec/api/configuration/ssl/server.crt'
    configure_ssl(keyfile, certfile)

    pidfile = os.path.join(common.WAZUH_PATH, common.OS_PIDFILE_PATH, f'{MAIN_PROCESS}-{pid}.pid')

    return {
        'proc_name': MAIN_PROCESS,
        'pidfile': pidfile,
        'daemon': not foreground_mode,
        'bind': f'{args.host}:{args.port}',
        'workers': 4,
        'worker_class': 'uvicorn.workers.UvicornWorker',
        'preload_app': True,
        'keyfile': keyfile,
        'certfile': certfile,
        'ca_certs': '/etc/ssl/certs/ca-certificates.crt',
        'ssl_context': ssl_context,
        'ciphers': '',
        'logconfig_dict': log_config_dict,
        'user': os.getuid()
    }


def get_script_arguments() -> Namespace:
    """Get script arguments.

    Returns
    -------
    argparse.Namespace
        Arguments passed to the script.
    """
    parser = ArgumentParser()
    parser.add_argument('--host', type=str, default='0.0.0.0', help='API host.')
    parser.add_argument('-p', '--port', type=int, default=27000, help='API port.')
    parser.add_argument('-f', action='store_true', dest='foreground', help='Run API in foreground mode.')
    parser.add_argument('-r', action='store_true', dest='root', help='Run as root')
    parser.add_argument('-t', action='store_true', dest='test_config', help='Test configuration')

    return parser.parse_args()


class StandaloneApplication(BaseApplication):
    def __init__(self, app: Callable, options: Dict[str, Any] = None):
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
    mux_demux_manager: MuxDemuxManager,
    batcher_process: Process
) -> None:
    """Handles incoming signals for graceful shutdown of the API.

    This function is triggered when a termination signal (SIGTERM) is received. It handles the cleanup
    of resources by terminating the batcher process, shutting down the mux/demux manager, and deleting
    any child and main process IDs.

    Parameters
    ----------
    signum : int
        The signal number received.
    frame : Any
        The current stack frame (unused).
    mux_demux_manager : MuxDemuxManager
        The MuxDemux manager instance to be shut down.
    batcher_process : Any
        The batcher process to be terminated.

    Notes
    -----
    This function is designed to be used with the `signal` module to handle termination and
    interruption signals (e.g., SIGTERM).
    """
    logger.info(f"Received signal {signum}, initiating shutdown.")
    if batcher_process:
        batcher_process.terminate()
    if mux_demux_manager:
        mux_demux_manager.shutdown()
    pyDaemonModule.delete_child_pids(MAIN_PROCESS, pid, logger)
    pyDaemonModule.delete_pid(MAIN_PROCESS, pid)


if __name__ == '__main__':
    args = get_script_arguments()

    # The bash script that starts all services first executes them using the `-t` flag to check the configuration.
    # We don't have a configuration yet, but it will be added in the future, so we just exit successfully for now.
    #
    # TODO(#25121): check configuration
    if args.test_config:
        exit(0)

    utils.clean_pid_files(MAIN_PROCESS)
    
    log_config_dict = setup_logging(args.foreground)
    logger = logging.getLogger('wazuh-comms-api')

    if args.foreground:
        logger.info('Starting API in foreground')
    else:
        pyDaemonModule.pyDaemon()

    if not args.root:
        # Drop privileges to wazuh
        os.setgid(common.wazuh_gid())
        os.setuid(common.wazuh_uid())
    else:
        logger.info('Starting API as root')

    batcher_config = BatcherConfig(
        max_elements=BATCHER_MAX_ELEMENTS,
        max_size=BATCHER_MAX_SIZE,
        max_time_seconds=BATCHER_MAX_TIME_SECONDS
    )
    mux_demux_manager, batcher_process = create_batcher_process(config=batcher_config)

    pid = os.getpid()
    signal.signal(signal.SIGTERM, partial(signal_handler, mux_demux_manager=mux_demux_manager, batcher_process=batcher_process))
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    try:
        app = create_app(mux_demux_manager.get_queue())
        options = get_gunicorn_options(pid, args.foreground, log_config_dict)
        StandaloneApplication(app, options).run()
    except WazuhCommsAPIError as e:
        logger.error(f'Error when trying to start the Wazuh Communications API. {e}')
        exit(1)
    except Exception as e:
        logger.error(f'Internal error when trying to start the Wazuh Communications API. {e}')
        exit(1)
    finally:
        batcher_process.terminate()
        mux_demux_manager.shutdown()
        pyDaemonModule.delete_child_pids(MAIN_PROCESS, pid, logger)
        pyDaemonModule.delete_pid(MAIN_PROCESS, pid)
