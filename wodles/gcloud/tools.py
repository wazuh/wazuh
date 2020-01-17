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
from logging.handlers import TimedRotatingFileHandler

logger_name = 'gcloud_wodle'
logger = logging.getLogger(logger_name)
log_levels = {0: logging.NOTSET,
              1: logging.DEBUG,
              2: logging.INFO,
              3: logging.WARNING,
              4: logging.ERROR,
              5: logging.CRITICAL,
              }
logging_format = logging.Formatter('%(name)s - %(levelname)s - %(message)s')


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


def get_stdout_logger(name: str, level: int = 3) -> logging.Logger:
    """Create a logger which returns the messages by stdout.

    :param name: Logger name
    :param level: Log level to be set
    :return: Logger configured with input parameters. Returns the messages by
        stdout
    """
    logger_stdout = logging.getLogger(name)
    # set log level
    logger.setLevel(log_levels.get(level, logging.WARNING))
    # set handler for stdout
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(logging_format)
    logger_stdout.addHandler(stdout_handler)

    return logger_stdout


def get_file_logger(output_file: str, level: int = 3) -> logging.Logger:
    """Create a logger which returns the messages in a file. Useful for debugging.

    :return: Logger configured with input parameters. Returns the messages in
        a output file
    """
    logger_file = logging.getLogger(f'{logger_name}_debug')
    # set log level
    logger_file.setLevel(log_levels.get(level, logging.WARNING))
    # set handler for stdout
    log_rotation_handler = TimedRotatingFileHandler(output_file,
                                                    when='midnight',
                                                    interval=1,
                                                    backupCount=1,
                                                    utc=True
                                                    )
    log_rotation_handler.setFormatter(logging_format)
    logger_file.addHandler(log_rotation_handler)

    return logger_file


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
        logger.critical('Wazuh installation not found')
        raise e

    if not (wazuh_path and wazuh_version):
        error_message = "Error reading '/etc/ossec-init.conf' file. " \
            "Wodle cannot start"
        raise Exception(error_message)

    wazuh_queue = os.path.join(wazuh_path, 'queue', 'ossec', 'queue')

    return wazuh_path, wazuh_version, wazuh_queue
