#!/var/ossec/framework/python/bin/python3
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import argparse
import logging
import os
import sys
import yaml
import ssl

import connexion
from flask_cors import CORS

from api import encoder, configuration
from wazuh import common, pyDaemonModule, Wazuh
from wazuh.cluster import cluster, __version__, __author__, __ossec_name__, __licence__

#
# Aux functions
#
def set_logging(configuration, foreground_mode=False):
    logger = logging.getLogger('api')
    logger.propagate = False
    # configure logger
    fh = cluster.CustomFileRotatingHandler(filename=configuration['logs']['path'], when='midnight')
    formatter = logging.Formatter('%(asctime)s %(levelname)-8s: [%(tag)-15s] [%(subtag)-15s] %(message)s')
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    if foreground_mode:
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        logger.addHandler(ch)

    logger.addFilter(cluster.ClusterFilter(tag='API', subtag='Main'))

    # add a new debug level
    logging.DEBUG2 = 5

    def debug2(self, message, *args, **kws):
        if self.isEnabledFor(logging.DEBUG2):
            self._log(logging.DEBUG2, message, args, **kws)

    def error(self, msg, *args, **kws):
        if self.isEnabledFor(logging.ERROR):
            kws['exc_info'] = self.isEnabledFor(logging.DEBUG2)
            self._log(logging.ERROR, msg, args, **kws)

    logging.addLevelName(logging.DEBUG2, "DEBUG2")

    logging.Logger.debug2 = debug2
    logging.Logger.error = error

    if configuration['logs']['level'] == 'debug2':
        debug_level = logging.DEBUG2
    elif configuration['logs']['level'] == 'debug':
        debug_level = logging.DEBUG
    elif configuration['logs']['level'] == 'critical':
        debug_level = logging.CRITICAL
    elif configuration['logs']['level'] == 'error':
        debug_level = logging.ERROR
    elif configuration['logs']['level'] == 'warning':
        debug_level = logging.WARNING
    else:  # configuration['logs']['level'] == 'info'
        debug_level = logging.INFO

    logger.setLevel(debug_level)
    return logger


def print_version():
    print("\n{} {} - {}\n\n{}".format(__ossec_name__, __version__, __author__, __licence__))


def main(cors, port, host, ssl_context):
    app = connexion.App(__name__, specification_dir=f'{common.ossec_path}/api/api/spec/')
    app.app.json_encoder = encoder.JSONEncoder
    app.add_api('spec.yaml', arguments={'title': 'Wazuh API'})
    if cors:
        # add CORS support
        CORS(app.app)
    app.run(port=port, host=host, ssl_context=ssl_context)


#
# Main
#
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    ####################################################################################################################
    parser.add_argument('-f', help="Run in foreground", action='store_true', dest='foreground')
    parser.add_argument('-V', help="Print version", action='store_true', dest="version")
    args = parser.parse_args()

    my_wazuh = Wazuh(get_init=True)

    configuration = configuration.read_config()

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
        ssl_context = ssl.SSLContext()
        ssl_context.load_cert_chain(certfile=configuration['https']['cert'], keyfile=configuration['https']['key'])
    else:
        ssl_context = None

    # Drop privileges to ossec
    if configuration['drop_privileges']:
        os.setgid(common.ossec_gid)
        os.setuid(common.ossec_uid)

    main_logger = set_logging(configuration, args.foreground)

    pyDaemonModule.create_pid('wazuh-apid', os.getpid())

    try:
        main(configuration['cors'], configuration['port'], configuration['host'], ssl_context)
    except KeyboardInterrupt:
        main_logger.info("SIGINT received. Bye!")
