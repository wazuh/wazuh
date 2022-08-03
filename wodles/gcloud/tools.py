#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""This module contains generic functions for this wodle."""

import argparse
import logging
from sys import stdout
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler
from pytz import UTC


logger_name = ':gcloud_wodle:'
logger = logging.getLogger(logger_name)
log_levels = {0: logging.WARNING,
              1: logging.INFO,
              2: logging.DEBUG}
logging_format = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
min_num_threads = 1
min_num_messages = 1
valid_types = ['pubsub', 'access_logs']


def get_script_arguments():
    """Get script arguments.

    Returns
    -------
    Namespace
        Namespace with the arguments passed to the script.
    """
    parser = argparse.ArgumentParser(usage="usage: %(prog)s [options]",
                                     description="Wazuh wodle for monitoring Google Cloud",
                                     formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('-T', '--integration_type', dest='integration_type',
                        help=f'Supported integration types: {*valid_types,}', required=True)

    parser.add_argument('-p', '--project', dest='project',
                        help='Project ID')

    parser.add_argument('-s', '--subscription_id', dest='subscription_id',
                        help='Subscription name')

    parser.add_argument('-c', '--credentials_file', dest='credentials_file',
                        help='Path to credentials file', required=True)

    parser.add_argument('-m', '--max_messages', dest='max_messages', type=int,
                        help='Number of maximum messages pulled in each iteration', default=100)

    parser.add_argument('-l', '--log_level', dest='log_level', type=int,
                        help='Log level', required=False, default=0)

    parser.add_argument('-b', '--bucket_name', dest='bucket_name', type=str,
                        help='The name of the bucket to read the logs from')

    parser.add_argument('-P', '--prefix', dest='prefix', help='The relative path to the logs', default='')

    parser.add_argument('-r', '--remove', action='store_true', dest='delete_file',
                        help='Remove processed blobs from the GCS bucket', default=False)

    parser.add_argument('-o', '--only_logs_after', dest='only_logs_after',
                        help='Only parse logs after this date - format YYYY-MMM-DD',
                        default=None, type=arg_valid_date)

    parser.add_argument('-t', '--num_threads', dest='n_threads', type=int,
                        help='Number of threads', required=False, default=min_num_threads)
    
    parser.add_argument('--reparse', action='store_true', dest='reparse', 
                        help='Parse the log, even if its been parsed before', default=False)

    return parser.parse_args()


def get_stdout_logger(name: str, level: int = 0) -> logging.Logger:
    """Create a logger which returns the messages by stdout.

    Parameters
    ----------
    name : str
        Logger name.
    level : int
        Log level to be set.

    Returns
    -------
    logging.Logger
        Logger configured with input parameters. Returns the messages by stdout.
    """
    logger_stdout = logging.getLogger(name)
    # set log level
    logger.setLevel(log_levels.get(level, logging.WARNING))
    # set handler for stdout
    stdout_handler = logging.StreamHandler(stdout)
    stdout_handler.setFormatter(logging_format)
    logger_stdout.addHandler(stdout_handler)

    return logger_stdout


def arg_valid_date(arg_string: str) -> datetime:
    """Validation function for only_logs_after dates.

    Parameters
    ----------
    arg_string : str
        The only_logs_after value in YYYY-MMM-DD format.

    Returns
    -------
    datetime
        The date corresponding to the string passed.

    Raises
    ------
    ValueError
        If the parameter passed is not in the expected format.
    """
    try:
        return datetime.strptime(arg_string, "%Y-%b-%d").replace(tzinfo=UTC)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Argument not a valid date in format YYYY-MMM-DD: '{arg_string}'.")
