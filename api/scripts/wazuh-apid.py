#!/var/ossec/framework/python/bin/python3

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import os
import signal
import sys
import warnings

from api.constants import API_LOG_PATH
from wazuh.core.wlogging import TimeBasedFileRotatingHandler, SizeBasedFileRotatingHandler
from wazuh.core import pyDaemonModule

SSL_DEPRECATED_MESSAGE = 'The `{ssl_protocol}` SSL protocol is deprecated.'

API_MAIN_PROCESS = 'wazuh-apid'
API_LOCAL_REQUEST_PROCESS = 'wazuh-apid_exec'
API_AUTHENTICATION_PROCESS = 'wazuh-apid_auth'
API_SECURITY_EVENTS_PROCESS = 'wazuh-apid_events'


def spawn_process_pool():
    """Spawn general process pool child."""

    exec_pid = os.getpid()
    pyDaemonModule.create_pid(API_LOCAL_REQUEST_PROCESS, exec_pid)

    signal.signal(signal.SIGINT, signal.SIG_IGN)


def spawn_events_pool():
    """Spawn events process pool child."""

    events_pid = os.getpid()
    pyDaemonModule.create_pid(API_SECURITY_EVENTS_PROCESS, events_pid)

    signal.signal(signal.SIGINT, signal.SIG_IGN)


def spawn_authentication_pool():
    """Spawn authentication process pool child."""

    auth_pid = os.getpid()
    pyDaemonModule.create_pid(API_AUTHENTICATION_PROCESS, auth_pid)

    signal.signal(signal.SIGINT, signal.SIG_IGN)


def start():
    """Run the Wazuh API.

    If another Wazuh API is running, this function fails.
    This function exits with 0 if successful or 1 if failed because the API was already running.
    """
    try:
        check_database_integrity()
    except Exception as db_integrity_exc:
        raise APIError(2012, details=str(db_integrity_exc))

    # Spawn child processes with their own needed imports
    if 'thread_pool' not in common.mp_pools.get():
        loop = asyncio.get_event_loop()
        loop.run_until_complete(
            asyncio.wait([loop.run_in_executor(pool, getattr(sys.modules[__name__], f'spawn_{name}'))
                          for name, pool in common.mp_pools.get().items()]))

    # Set up API
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    app = connexion.AioHttpApp(__name__, host=api_conf['host'],
                               port=api_conf['port'],
                               specification_dir=os.path.join(api_path[0], 'spec'),
                               options={"swagger_ui": False, 'uri_parser_class': APIUriParser},
                               only_one_api=True
                               )
    app.add_api('spec.yaml',
                arguments={'title': 'Wazuh API',
                           'protocol': 'https' if api_conf['https']['enabled'] else 'http',
                           'host': api_conf['host'],
                           'port': api_conf['port']
                           },
                strict_validation=True,
                validate_responses=False,
                pass_context_arg_name='request',
                options={"middlewares": [response_postprocessing, security_middleware, request_logging,
                                         set_secure_headers]})

    # Maximum body size that the API can accept (bytes)
    app.app._client_max_size = configuration.api_conf['max_upload_size']

    # Enable CORS
    if api_conf['cors']['enabled']:
        import aiohttp_cors
        cors = aiohttp_cors.setup(app.app, defaults={
            api_conf['cors']['source_route']: aiohttp_cors.ResourceOptions(
                expose_headers=api_conf['cors']['expose_headers'],
                allow_headers=api_conf['cors']['allow_headers'],
                allow_credentials=api_conf['cors']['allow_credentials']
            )
        })
        # Configure CORS on all endpoints.
        for route in list(app.app.router.routes()):
            cors.add(route)

    # Enable cache plugin
    if api_conf['cache']['enabled']:
        setup_cache(app.app)

    # Add application signals
    app.app.on_response_prepare.append(modify_response_headers)
    app.app.cleanup_ctx.append(register_background_tasks)

    # API configuration logging
    logger.debug(f'Loaded API configuration: {api_conf}')
    logger.debug(f'Loaded security API configuration: {security_conf}')

    # Start API
    try:
        app.run(port=api_conf['port'],
                host=api_conf['host'],
                ssl_context=ssl_context,
                access_log_class=alogging.AccessLogger,
                use_default_access_log=True
                )
    except OSError as exc:
        if exc.errno == 98:
            error = APIError(2010)
            logger.error(error)
            raise error
        else:
            logger.error(exc)
            raise exc


def print_version():
    from wazuh.core.cluster import __version__, __author__, __wazuh_name__, __licence__
    print("\n{} {} - {}\n\n{}".format(__wazuh_name__, __version__, __author__, __licence__))


def test_config(config_file: str):
    """Make an attempt to read the API config file. Exits with 0 code if successful, 1 otherwise.

    Arguments
    ---------
    config_file : str
        Path of the file
    """
    try:
        from api.configuration import read_yaml_config
        read_yaml_config(config_file=config_file)
    except Exception as exc:
        print(f"Configuration not valid. ERROR: {exc}")
        sys.exit(1)
    sys.exit(0)


def version():
    """Print API version and exits with 0 code. """
    print_version()
    sys.exit(0)


def exit_handler(signum, frame):
    """Try to kill API child processes and remove their PID files."""
    api_pid = os.getpid()
    pyDaemonModule.delete_child_pids(API_MAIN_PROCESS, api_pid, logger)
    pyDaemonModule.delete_pid(API_MAIN_PROCESS, api_pid)


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    ####################################################################################################################
    parser.add_argument('-f', help="Run in foreground", action='store_true', dest='foreground')
    parser.add_argument('-V', help="Print version", action='store_true', dest="version")
    parser.add_argument('-t', help="Test configuration", action='store_true', dest='test_config')
    parser.add_argument('-r', help="Run as root", action='store_true', dest='root')
    parser.add_argument('-c', help="Configuration file to use", type=str, metavar='config', dest='config_file')
    parser.add_argument('-d', help="Enable debug messages. Use twice to increase verbosity.", action='count',
                        dest='debug_level')
    args = parser.parse_args()

    if args.version:
        version()
        sys.exit(0)

    elif args.test_config:
        test_config(args.config_file)
        sys.exit(0)

    import logging
    from api.api_exception import APIError
    from wazuh.core import common
    from api import alogging, configuration
    from api.api_exception import APIError
    from api.util import APILoggerSize, to_relative_path

    from wazuh.core import common, utils


    def set_logging(log_path=f'{API_LOG_PATH}.log', foreground_mode=False, debug_mode='info'):
        """Set up logging for the API.
        
        Parameters
        ----------
        log_path : str
            Path of the log file.
        foreground_mode : bool
            If True, the log will be printed to stdout.
        debug_mode : str
            Debug level. Possible values: disabled, info, warning, error, debug, debug2.
        """
        if not api_conf['logs']['max_size']['enabled']:
            custom_handler = TimeBasedFileRotatingHandler(filename=log_path, when='midnight')
        else:
            max_size = APILoggerSize(api_conf['logs']['max_size']['size']).size
            custom_handler = SizeBasedFileRotatingHandler(filename=log_path, maxBytes=max_size, backupCount=1)

        for logger_name in ('connexion.aiohttp_app', 'connexion.apis.aiohttp_api', 'wazuh-api'):
            api_logger = alogging.APILogger(
                log_path=log_path, foreground_mode=foreground_mode, logger_name=logger_name,
                debug_level='info' if logger_name != 'wazuh-api' and debug_mode != 'debug2' else debug_mode
            )
            api_logger.setup_logger(custom_handler)
        if os.path.exists(log_path):
            os.chown(log_path, common.wazuh_uid(), common.wazuh_gid())
            os.chmod(log_path, 0o660)

    try:
        from wazuh.core import utils
        from api import alogging, configuration

        if args.config_file is not None:
            configuration.api_conf.update(configuration.read_yaml_config(config_file=args.config_file))
        api_conf = configuration.api_conf
        security_conf = configuration.security_conf
    except APIError as e:
        print(f"Error when trying to start the Wazuh API. {e}")
        sys.exit(1)

    # Set up logger
    try:
        plain_log = 'plain' in api_conf['logs']['format']
        json_log = 'json' in api_conf['logs']['format']

        if plain_log:
            set_logging(log_path=f'{API_LOG_PATH}.log', debug_mode=api_conf['logs']['level'],
                        foreground_mode=args.foreground)
        if json_log:
            set_logging(log_path=f'{API_LOG_PATH}.json', debug_mode=api_conf['logs']['level'],
                        foreground_mode=args.foreground and not plain_log)
    except APIError as api_log_error:
        print(f"Error when trying to start the Wazuh API. {api_log_error}")
        sys.exit(1)

    logger = logging.getLogger('wazuh-api')

    import asyncio
    import ssl

    import connexion
    import uvloop
    from aiohttp_cache import setup_cache
    from api import __path__ as api_path
    # noinspection PyUnresolvedReferences
    from api.constants import CONFIG_FILE_PATH
    from api.middlewares import security_middleware, response_postprocessing, request_logging, set_secure_headers
    from api.signals import modify_response_headers, register_background_tasks
    from api.uri_parser import APIUriParser
    from api.util import to_relative_path
    from wazuh.rbac.orm import check_database_integrity

    # Check deprecated options. To delete after expected versions
    if 'use_only_authd' in api_conf:
        del api_conf['use_only_authd']
        logger.warning("'use_only_authd' option was deprecated on v4.3.0. Wazuh Authd will always be used")

    if 'path' in api_conf['logs']:
        del api_conf['logs']['path']
        logger.warning("Log 'path' option was deprecated on v4.3.0. Default path will always be used: "
                       f"{API_LOG_PATH}.<log_format>")

    # Configure https
    ssl_context = None
    if api_conf['https']['enabled']:
        try:
            # Generate SSL if it does not exist and HTTPS is enabled
            if not os.path.exists(api_conf['https']['key']) or not os.path.exists(api_conf['https']['cert']):
                logger.info('HTTPS is enabled but cannot find the private key and/or certificate. '
                            'Attempting to generate them')
                private_key = configuration.generate_private_key(api_conf['https']['key'])
                logger.info(
                    f"Generated private key file in WAZUH_PATH/{to_relative_path(api_conf['https']['key'])}")
                configuration.generate_self_signed_certificate(private_key, api_conf['https']['cert'])
                logger.info(
                    f"Generated certificate file in WAZUH_PATH/{to_relative_path(api_conf['https']['cert'])}")

            # Load SSL context
            allowed_ssl_protocols = {
                'tls': ssl.PROTOCOL_TLS,
                'tlsv1': ssl.PROTOCOL_TLSv1,
                'tlsv1.1': ssl.PROTOCOL_TLSv1_1,
                'tlsv1.2': ssl.PROTOCOL_TLSv1_2,
                'auto': ssl.PROTOCOL_TLS_SERVER
            }

            config_ssl_protocol = api_conf['https']['ssl_protocol']
            ssl_protocol = allowed_ssl_protocols[config_ssl_protocol.lower()]

            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=DeprecationWarning)
                if ssl_protocol in (ssl.PROTOCOL_TLSv1, ssl.PROTOCOL_TLSv1_1):
                    logger.warning(SSL_DEPRECATED_MESSAGE.format(ssl_protocol=config_ssl_protocol))
                ssl_context = ssl.SSLContext(protocol=ssl_protocol)

            if api_conf['https']['use_ca']:
                ssl_context.verify_mode = ssl.CERT_REQUIRED
                ssl_context.load_verify_locations(api_conf['https']['ca'])

            ssl_context.load_cert_chain(certfile=api_conf['https']['cert'], keyfile=api_conf['https']['key'])

            # Load SSL ciphers if any has been specified
            if api_conf['https']['ssl_ciphers']:
                ssl_ciphers = api_conf['https']['ssl_ciphers'].upper()
                try:
                    ssl_context.set_ciphers(ssl_ciphers)
                except ssl.SSLError:
                    error = APIError(2003, details='SSL ciphers cannot be selected')
                    logger.error(error)
                    raise error

        except ssl.SSLError:
            error = APIError(2003, details='Private key does not match with the certificate')
            logger.error(error)
            raise error
        except IOError as exc:
            if exc.errno == 22:
                error = APIError(2003, details='PEM phrase is not correct')
                logger.error(error)
                raise error
            elif exc.errno == 13:
                error = APIError(2003, details='Ensure the certificates have the correct permissions')
                logger.error(error)
                raise error
            else:
                msg = f'Wazuh API SSL ERROR. Please, ensure if path to certificates is correct in the configuration ' \
                      f'file WAZUH_PATH/{to_relative_path(CONFIG_FILE_PATH)}'
                print(msg)
                logger.error(msg)
                raise exc

    # Check for unused PID files
    utils.clean_pid_files(API_MAIN_PROCESS)

    # Foreground/Daemon
    if not args.foreground:
        pyDaemonModule.pyDaemon()
    else:
        print('Starting API in foreground')

    # Drop privileges to wazuh
    if not args.root:
        if api_conf['drop_privileges']:
            os.setgid(common.wazuh_gid())
            os.setuid(common.wazuh_uid())
    else:
        print('Starting API as root')

    pid = os.getpid()
    pyDaemonModule.create_pid(API_MAIN_PROCESS, pid)

    signal.signal(signal.SIGTERM, exit_handler)

    try:
        start()
    except APIError as e:
        print(f"Error when trying to start the Wazuh API. {e}")
        sys.exit(1)
    except Exception as e:
        print(f'Internal error when trying to start the Wazuh API. {e}')
        sys.exit(1)
    finally:
        pyDaemonModule.delete_child_pids(API_MAIN_PROCESS, pid, logger)
        pyDaemonModule.delete_pid(API_MAIN_PROCESS, pid)
