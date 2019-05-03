#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import os
import subprocess
import sys
from signal import SIGABRT, SIGTERM, SIGINT, signal
import yaml

from api import api
from api.constants import UWSGI_CONFIG_PATH, UWSGI_EXE
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
    parser.add_argument('-r', help="Run as root", action='store_true', dest='root')
    parser.add_argument('-c', help="Configuration file to use", type=str, metavar='config', dest='config_file',
                        default=UWSGI_CONFIG_PATH)
    args = parser.parse_args()

    if args.test_config:
        try:
            with open(args.config_file, 'r') as stream:
                yaml.load(stream)
        except Exception as e:
            sys.exit(1)
        sys.exit(0)

    if args.version:
        print_version()
        sys.exit(0)

    # Foreground/Daemon
    if not args.foreground:
        pyDaemonModule.pyDaemon()

    # Drop privileges to ossec
    if not args.root:
        os.setgid(common.ossec_gid)
        os.setuid(common.ossec_uid)

    uwsgi_logger = api.main_logger

    proc = subprocess.Popen([UWSGI_EXE,
                             "--yaml", args.config_file,
                             "--wsgi-file", api.__file__,
                             "--callable", "wazuh_api"
                             ],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            encoding='utf8'
                            )

    pyDaemonModule.create_pid('wazuh-apid', proc.pid)

    # Set termination handlers to kill subprocesses on exit
    def clean(*args):
        proc.kill()

    for sig in (SIGABRT, SIGINT, SIGTERM):
        signal(sig, clean)

    while True:
        output = proc.stdout.readline()
        if output == '' and proc.poll() is not None:
            break
        if output:
            uwsgi_logger.info("[UWSGI]" + output.strip())
    rc = proc.poll()

    sys.exit(rc)
