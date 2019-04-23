#!/var/ossec/framework/python/bin/python3
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import os
import subprocess
import sys

from api import configuration
from wazuh import pyDaemonModule, common
from wazuh.cluster import __version__, __author__, __ossec_name__, __licence__


def print_version():
    print("\n{} {} - {}\n\n{}".format(__ossec_name__, __version__, __author__, __licence__))


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    ####################################################################################################################
    parser.add_argument('-f', help="Run in foreground", action='store_true', dest='foreground')
    parser.add_argument('-V', help="Print version", action='store_true', dest="version")
    parser.add_argument('-t', help="Test configuration", action='store_true', dest='test_config')
    parser.add_argument('-c', help="Configuration file to use", type=str, metavar='config', dest='config_file',
                        default=common.ossec_conf)
    args = parser.parse_args()

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

    proc = subprocess.Popen(["/var/ossec/framework/python/bin/uwsgi", "--yaml", "/var/ossec/api/configuration/api.yml"])
    pyDaemonModule.create_pid('wazuh-apid', proc.pid)
