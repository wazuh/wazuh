#!/var/ossec/framework/python/bin/python3

# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import asyncio
import os
import ssl
import sys

import aiohttp_cors
import connexion
import uvloop
from aiohttp_swagger import setup_swagger

from api import alogging, configuration, __path__ as api_path
# noinspection PyUnresolvedReferences
from api import validator
from api.aiohttp_cache import setup_cache
from api.api_exception import APIException
from api.constants import CONFIG_FILE_PATH
from api.middlewares import set_user_name, check_experimental
from api.util import to_relative_path
from wazuh import pyDaemonModule, common
from wazuh.core.cluster import __version__, __author__, __ossec_name__, __licence__
from wazuh.core.cluster.utils import read_config


def set_logging(log_path='logs/api.log', foreground_mode=False, debug_mode='info'):
    for logger_name in ('connexion.aiohttp_app', 'connexion.apis.aiohttp_api', 'wazuh'):
        api_logger = alogging.APILogger(log_path=log_path, foreground_mode=foreground_mode,
                                        debug_level=debug_mode,
                                        logger_name=logger_name)
        api_logger.setup_logger()


def print_version():
    print("\n{} {} - {}\n\n{}".format(__ossec_name__, __version__, __author__, __licence__))


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    ####################################################################################################################
    parser.add_argument('-f', help="Run in foreground", action='store_true', dest='foreground')
    parser.add_argument('-V', help="Print version", action='store_true', dest="version")
    parser.add_argument('-t', help="Test configuration", action='store_true', dest='test_config')
    parser.add_argument('-r', help="Run as root", action='store_true', dest='root')
    parser.add_argument('-c', help="Configuration file to use", type=str, metavar='config', dest='config_file',
                        default=common.api_config_path)
    args = parser.parse_args()

    if args.test_config:
        try:
            configuration.read_api_config(config_file=args.config_file)
        except Exception as e:
            print(f"Configuration not valid: {e}")
            sys.exit(1)
        sys.exit(0)

    if args.version:
        print_version()
        sys.exit(0)

    # Foreground/Daemon
    if not args.foreground:
        pyDaemonModule.pyDaemon()

    cluster_config = read_config()
    configuration = configuration.read_api_config(config_file=args.config_file)
    cache_conf = configuration['cache']
    cors = configuration['cors']
    log_path = configuration['logs']['path']
    experimental = configuration['experimental_features']

    # Drop privileges to ossec
    if not args.root:
        if configuration['drop_privileges']:
            os.setgid(common.ossec_gid())
            os.setuid(common.ossec_uid())

    set_logging(log_path=log_path, debug_mode=configuration['logs']['level'], foreground_mode=args.foreground)

    # set correct permissions on api.log file
    if os.path.exists(os.path.join(common.ossec_path, log_path)):
        os.chown(os.path.join(common.ossec_path, log_path), common.ossec_uid(), common.ossec_gid())
        os.chmod(os.path.join(common.ossec_path, log_path), 0o660)

    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    app = connexion.AioHttpApp(__name__, host=configuration['host'],
                               port=configuration['port'],
                               specification_dir=os.path.join(api_path[0], 'spec'),
                               options={"swagger_ui": False}
                               )
    app.add_api('spec.yaml',
                arguments={'title': 'Wazuh API',
                           'protocol': 'https' if configuration['https']['enabled'] else 'http',
                           'host': configuration['host'],
                           'port': configuration['port']
                           },
                strict_validation=True,
                validate_responses=True,
                pass_context_arg_name='request',
                options={"middlewares": [set_user_name, check_experimental(experimental)]})

    # Enable CORS
    if cors['enabled']:
        cors = aiohttp_cors.setup(app.app, defaults={
            cors['source_route']: aiohttp_cors.ResourceOptions(
                expose_headers=cors['expose_headers'],
                allow_headers=cors['allow_headers'],
                allow_credentials=cors['allow_credentials']
            )
        })
        # Configure CORS on all endpoints.
        for route in list(app.app.router.routes()):
            cors.add(route)

    # Enable cache plugin
    if cache_conf['enabled']:
        setup_cache(app.app)

    # Enable swagger UI plugin
    setup_swagger(app.app,
                  ui_version=3,
                  swagger_url='/ui',
                  swagger_from_file=os.path.join(app.specification_dir, 'spec.yaml'))

    # Configure https
    if configuration['https']['enabled']:
        try:
            ssl_context = ssl.SSLContext()
            if configuration['https']['use_ca']:
                ssl_context.verify_mode = ssl.CERT_REQUIRED
                ssl_context.load_verify_locations(configuration['https']['ca'])
            ssl_context.load_cert_chain(certfile=configuration['https']['cert'],
                                        keyfile=configuration['https']['key'])
        except ssl.SSLError as e:
            raise APIException(2003, details='Private key does not match with the certificate')
        except IOError as e:
            raise APIException(2003, details=f'{e} - Please, ensure '
                                             'if path to certificates is correct in '
                                             'the configuration file '
                                             f'(WAZUH_PATH/{to_relative_path(CONFIG_FILE_PATH)})')
    else:
        ssl_context = None

    pyDaemonModule.create_pid('wazuh-apid', os.getpid())

    app.run(port=configuration['port'],
            host=configuration['host'],
            ssl_context=ssl_context,
            access_log_class=alogging.AccessLogger,
            use_default_access_log=True
            )
