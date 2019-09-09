#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import ssl

import connexion
from flask_caching import Cache
from flask_cors import CORS

from api import alogging, encoder, configuration, __path__ as api_path
from api import validator  # To register custom validators (do not remove)
from api.api_exception import APIException
from api.constants import CONFIG_FILE_PATH
from api.util import to_relative_path

from wazuh import common
from wazuh.cluster.cluster import read_config


#
# Aux functions
#
def set_logging(foreground_mode=False, debug_mode='info'):
    api_logger = alogging.APILogger(log_path='logs/api.log', foreground_mode=foreground_mode, debug_level=debug_mode)
    api_logger.setup_logger()
    return api_logger


cluster_config = read_config()
configuration = configuration.read_api_config()
cache_conf = configuration['cache']
cors = configuration['cors']

main_logger = set_logging(debug_mode=configuration['logs']['level'])

# set correct permissions on api.log file
if os.path.exists('{0}/logs/api.log'.format(common.ossec_path)):
    os.chown('{0}/logs/api.log'.format(common.ossec_path), common.ossec_uid(), common.ossec_gid())
    os.chmod('{0}/logs/api.log'.format(common.ossec_path), 0o660)

app = connexion.App(__name__, specification_dir=os.path.join(api_path[0], 'spec'))
wazuh_api = app.app
app.app.json_encoder = encoder.JSONEncoder
app.add_api('spec.yaml', arguments={'title': 'Wazuh API'}, strict_validation=True, validate_responses=True)
app.app.logger = main_logger
app.app.before_request(alogging.set_request_user_logs)

if cors:
    # add CORS support
    CORS(app.app)
# add Cache support
if cache_conf['enabled']:
    app.app.config['CACHE_TYPE'] = 'simple'
    app.app.config['CACHE_DEFAULT_TIMEOUT'] = cache_conf['time']/1000
else:
    app.app.config['CACHE_TYPE'] = 'null'
app.app.cache = Cache(app.app)

#
# Main
#
if __name__ == '__main__':

    try:
        # Set host and port (only for development purposes, by default these will be set in uwsgi)
        port = configuration['port']
        host = configuration['host']

        # Enable https (only for development purposes, by default these will be set in uwsgi)
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
                raise APIException(2003, details='Please, ensure '
                                                 'if path to certificates is correct in '
                                                 'the configuration file '
                f'(WAZUH_PATH/{to_relative_path(CONFIG_FILE_PATH)})')
        else:
            ssl_context = None

        app.run(host=host, port=port, ssl_context=ssl_context)
    except Exception as e:
        main_logger.error("Error starting API server: {}".format(e))
