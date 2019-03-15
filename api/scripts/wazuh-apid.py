#!/var/ossec/framework/python/bin/python3
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import argparse
import os
import sys
import ssl

import connexion
from flask_cors import CORS

from api import alogging, encoder, configuration, __path__ as api_path
from api.api_exception import APIException
from api import validator  # To register custom validators (do not remove)
from wazuh import common, pyDaemonModule, Wazuh
from wazuh.cluster import __version__, __author__, __ossec_name__, __licence__


#
# Aux functions
#
def set_logging(foreground_mode=False, debug_mode='info'):
    api_logger = alogging.APILogger(foreground_mode=foreground_mode, debug_level=debug_mode)
    api_logger.setup_logger()
    return api_logger


def print_version():
    print("\n{} {} - {}\n\n{}".format(__ossec_name__, __version__, __author__, __licence__))


def main(cors, port, host, ssl_context, main_logger):
    app = connexion.App(__name__, specification_dir=os.path.join(api_path[0], 'spec'))
    app.app.json_encoder = encoder.JSONEncoder
    app.add_api('spec.yaml', arguments={'title': 'Wazuh API'})
    app.app.logger = main_logger
    app.app.before_request(alogging.set_request_user_logs)
    if cors:
        # add CORS support
        CORS(app.app)
    try:
        app.run(port=port, host=host, ssl_context=ssl_context)
    except Exception as e:
        main_logger.error("Error starting API server: {}".format(e))


#
# Main
#
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    ####################################################################################################################
    parser.add_argument('-f', help="Run in foreground", action='store_true', dest='foreground')
    parser.add_argument('-V', help="Print version", action='store_true', dest="version")
    parser.add_argument('-t', help="Test configuration", action='store_true', dest='test_config')
    parser.add_argument('-c', help="Configuration file to use", type=str, metavar='config', dest='config_file',
                        default=common.ossec_conf)
    args = parser.parse_args()

    my_wazuh = Wazuh(get_init=True)

    configuration = configuration.read_config()
    if args.test_config:
        sys.exit(0)

    if args.version:
        print_version()
        sys.exit(0)

    # Foreground/Daemon
    if not args.foreground:
        pyDaemonModule.pyDaemon()

    # set correct permissions on api.log file
    if os.path.exists('{0}/logs/api.log'.format(common.ossec_path)):
        os.chown('{0}/logs/api.log'.format(common.ossec_path), common.ossec_uid, common.ossec_gid)
        os.chmod('{0}/logs/api.log'.format(common.ossec_path), 0o660)

    if configuration['https']['enabled']:
        try:
            ssl_context = ssl.SSLContext()
            if configuration['https']['use_ca']:
                ssl_context.verify_mode = ssl.CERT_REQUIRED
                ssl_context.load_verify_locations(configuration['https']['ca'])
            ssl_context.load_cert_chain(certfile=configuration['https']['cert'], keyfile=configuration['https']['key'])
        except IOError:
            raise APIException(2003)
    else:
        ssl_context = None

    # Drop privileges to ossec
    if configuration['drop_privileges']:
        os.setgid(common.ossec_gid)
        os.setuid(common.ossec_uid)

    main_logger = set_logging(args.foreground, configuration['logs']['level'])

    pyDaemonModule.create_pid('wazuh-apid', os.getpid())

    try:
        main(configuration['cors'], configuration['port'], configuration['host'], ssl_context, main_logger)
    except KeyboardInterrupt:
        main_logger.info("SIGINT received. Bye!")
