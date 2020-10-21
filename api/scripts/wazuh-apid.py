#!/var/ossec/framework/python/bin/python3

# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import sys

from api import alogging, configuration
from wazuh.core import common


def start(foreground, root, config_file):
    """Run the Wazuh API.

    If another Wazuh API is running, this function fails.
    This function exits with 0 if successful or 1 if failed because the API was already running.

    Arguments
    ---------
    foreground : bool
        If the API must be daemonized or not
    root : bool
        If true, the daemon is run as root. Normally not recommended for security reasons
    config_file : str
        Path to the API config file
    """
    import asyncio
    import logging
    import os
    import ssl

    import connexion
    import uvloop
    from aiohttp_cache import setup_cache

    import wazuh.security
    from api import __path__ as api_path
    # noinspection PyUnresolvedReferences
    from api import validator
    from api.api_exception import APIError
    from api.constants import CONFIG_FILE_PATH
    from api.middlewares import set_user_name, security_middleware, response_postprocessing
    from api.uri_parser import APIUriParser
    from api.util import to_relative_path
    from wazuh.core import pyDaemonModule

    configuration.api_conf.update(configuration.read_yaml_config(config_file=config_file))
    api_conf = configuration.api_conf
    log_path = api_conf['logs']['path']

    # Set up logger
    set_logging(log_path=log_path, debug_mode=api_conf['logs']['level'], foreground_mode=foreground)
    logger = logging.getLogger('wazuh')

    # Set correct permissions on api.log file
    if os.path.exists(os.path.join(common.ossec_path, log_path)):
        os.chown(os.path.join(common.ossec_path, log_path), common.ossec_uid(), common.ossec_gid())
        os.chmod(os.path.join(common.ossec_path, log_path), 0o660)

    # Configure https
    ssl_context = None
    if api_conf['https']['enabled']:
        try:
            # Generate SSL if it does not exist and HTTPS is enabled
            if not os.path.exists(api_conf['https']['key']) or not os.path.exists(api_conf['https']['cert']):
                logger.info('HTTPS is enabled but cannot find the private key and/or certificate. '
                            'Attempting to generate them')
                private_key = configuration.generate_private_key(api_conf['https']['key'])
                logger.info(f"Generated private key file in WAZUH_PATH/{to_relative_path(api_conf['https']['key'])}")
                configuration.generate_self_signed_certificate(private_key, api_conf['https']['cert'])
                logger.info(f"Generated certificate file in WAZUH_PATH/{to_relative_path(api_conf['https']['cert'])}")

            # Load SSL context
            ssl_context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS)
            if api_conf['https']['use_ca']:
                ssl_context.verify_mode = ssl.CERT_REQUIRED
                ssl_context.load_verify_locations(api_conf['https']['ca'])
            ssl_context.load_cert_chain(certfile=api_conf['https']['cert'],
                                        keyfile=api_conf['https']['key'])
        except ssl.SSLError:
            logger.error(str(APIError(2003, details='Private key does not match with the certificate')))
            sys.exit(1)
        except IOError as e:
            if e.errno == 22:
                logger.error(str(APIError(2003, details='PEM phrase is not correct')))
            elif e.errno == 13:
                logger.error(str(APIError(2003, details='Ensure the certificates have the correct permissions')))
            else:
                print('Wazuh API SSL ERROR. Please, ensure if path to certificates is correct in the configuration '
                      f'file WAZUH_PATH/{to_relative_path(CONFIG_FILE_PATH)}')
            sys.exit(1)

    # Drop privileges to ossec
    if not root:
        if api_conf['drop_privileges']:
            os.setgid(common.ossec_gid())
            os.setuid(common.ossec_uid())
    else:
        print(f"Starting API as root")

    # Foreground/Daemon
    if not foreground:
        pyDaemonModule.pyDaemon()
        pyDaemonModule.create_pid('wazuh-apid', os.getpid())
    else:
        print(f"Starting API in foreground")

    # Load the SPEC file into memory to use as a reference for future calls
    wazuh.security.load_spec()

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
                options={"middlewares": [response_postprocessing, set_user_name, security_middleware]})

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

    # Start API
    app.run(port=api_conf['port'],
            host=api_conf['host'],
            ssl_context=ssl_context,
            access_log_class=alogging.AccessLogger,
            use_default_access_log=True
            )


def set_logging(log_path='logs/api.log', foreground_mode=False, debug_mode='info'):
    for logger_name in ('connexion.aiohttp_app', 'connexion.apis.aiohttp_api', 'wazuh'):
        api_logger = alogging.APILogger(log_path=log_path, foreground_mode=foreground_mode,
                                        debug_level=debug_mode,
                                        logger_name=logger_name)
        api_logger.setup_logger()


def print_version():
    from wazuh.core.cluster import __version__, __author__, __ossec_name__, __licence__
    print("\n{} {} - {}\n\n{}".format(__ossec_name__, __version__, __author__, __licence__))


def test_config(config_file):
    """Make an attempt to read the API config file. Exits with 0 code if successful, 1 otherwise.

    Arguments
    ---------
    config_file : str
        Path of the file
    """
    try:
        configuration.read_yaml_config(config_file=config_file)
    except Exception as e:
        print(f"Configuration not valid: {e}")
        sys.exit(1)
    sys.exit(0)


def version():
    """Print API version and exits with 0 code. """
    print_version()
    sys.exit(0)


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    ####################################################################################################################
    parser.add_argument('-f', help="Run in foreground", action='store_true', dest='foreground')
    parser.add_argument('-V', help="Print version", action='store_true', dest="version")
    parser.add_argument('-t', help="Test configuration", action='store_true', dest='test_config')
    parser.add_argument('-r', help="Run as root", action='store_true', dest='root')
    parser.add_argument('-c', help="Configuration file to use", type=str, metavar='config', dest='config_file',
                        default=common.api_config_path)
    parser.add_argument('-d', help="Enable debug messages. Use twice to increase verbosity.", action='count',
                        dest='debug_level')
    args = parser.parse_args()

    if args.version:
        version()
    elif args.test_config:
        test_config(args.config_file)
    else:
        start(args.foreground, args.root, args.config_file)
