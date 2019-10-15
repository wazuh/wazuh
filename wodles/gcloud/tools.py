#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""This module contains generic functions for this wodle."""

import argparse
import logging
import os
import re
import sys

logger_name = 'gcloud_wodle'
logger = logging.getLogger(logger_name)


def get_script_arguments():
    """Get script arguments."""
    parser = argparse.ArgumentParser(usage="usage: %(prog)s [options]",
                                     description="Wazuh wodle for monitoring Google Cloud",  # noqa: E501
                                     formatter_class=argparse.RawTextHelpFormatter)  # noqa: E501

    parser.add_argument('-p', '--project', dest='project',
                        help='Project ID', required=True)

    parser.add_argument('-s', '--subscription_id', dest='subscription_id',
                        help='Subscription name', required=True)

    parser.add_argument('-c', '--credentials_file', dest='credentials_file',
                        help='Path to credentials file', required=True)

    parser.add_argument('-m', '--max_messages', dest='max_messages', type=int,
                        help='Number of maximum messages pulled in each iteration',  # noqa: E501
                        required=False, default=100)

    parser.add_argument('-l', '--log_level', dest='log_level', type=int,
                        help='Log level', required=False, default=3)

    return parser.parse_args()


def get_logger(name: str, level: int = 3) -> logging.Logger:
    """Configure logger.

    :param name: Logger name
    :param level: Log level to be set
    """
    levels = {0: logging.NOTSET,
              1: logging.DEBUG,
              2: logging.INFO,
              3: logging.WARNING,
              4: logging.ERROR,
              5: logging.CRITICAL,
              }

    logger = logging.getLogger(name)
    # set log level
    logger.setLevel(levels.get(level, logging.WARNING))
    # set handler for stdout
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_format = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
    stdout_handler.setFormatter(stdout_format)
    logger.addHandler(stdout_handler)

    return logger


def get_wazuh_paths() -> tuple:
    """Get Wazuh paths from ossec-init file."""
    # regular expressions for getting path and version
    re_path = re.compile(r'^(DIRECTORY){1}={1}\"{1}([\w\/.]+)\"{1}$')
    re_version = re.compile(r'^(VERSION){1}={1}\"{1}([\w\/.]+)\"{1}$')
    # initialize variables
    wazuh_path = None
    wazuh_version = None
    try:
        with open('/etc/ossec-init.conf') as f:
            lines = f.readlines()
            for line in lines:
                path = re.search(re_path, line)
                version = re.search(re_version, line)
                if path:
                    wazuh_path = path.group(2)
                    continue
                if version:
                    wazuh_version = version.group(2)
    except FileNotFoundError as e:
        logger.critical('ERROR: Wazuh installation not found')
        raise e

    if not (wazuh_path and wazuh_version):
        error_message = "ERROR: Error reading '/etc/ossec-init.conf' " \
            "file. Wodle cannot start"
        raise Exception(error_message)

    wazuh_queue = os.path.join(wazuh_path, 'queue', 'ossec', 'queue')

    return wazuh_path, wazuh_version, wazuh_queue
