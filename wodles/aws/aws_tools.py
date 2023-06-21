#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""This module contains generic functions for this wodle."""

import argparse
import configparser
from os import path
from datetime import datetime
import sys
import re

DEFAULT_AWS_CONFIG_PATH = path.join(path.expanduser('~'), '.aws', 'config')
CREDENTIALS_URL = 'https://documentation.wazuh.com/current/amazon/services/prerequisites/credentials.html'
DEPRECATED_MESSAGE = 'The {name} authentication parameter was deprecated in {release}. ' \
                     'Please use another authentication method instead. Check {url} for more information.'

ALL_REGIONS = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ap-northeast-1', 'ap-northeast-2',
               'ap-southeast-2', 'ap-south-1', 'eu-central-1', 'eu-west-1']

# Enable/disable debug mode
debug_level = 0


def handler(signal, frame):
    print("ERROR: SIGINT received.")
    sys.exit(2)


def debug(msg, msg_level):
    if debug_level >= msg_level:
        print('DEBUG: {debug_msg}'.format(debug_msg=msg))


def arg_valid_date(arg_string):
    try:
        parsed_date = datetime.strptime(arg_string, "%Y-%b-%d")
        # Return str created from date in YYYYMMDD format
        return parsed_date.strftime('%Y%m%d')
    except ValueError:
        raise argparse.ArgumentTypeError("Argument not a valid date in format YYYY-MMM-DD: '{0}'.".format(arg_string))


def arg_valid_key(arg_string, append_slash=True):
    CHARACTERS_TO_AVOID = "\\{}^%`[]'\"<>~#|"
    XML_CONSTRAINTS = ["&apos;", "&quot;", "&amp;", "&lt;", "&gt;", "&#13;", "&#10;"]

    # Validate against the naming guidelines https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-keys.html
    if any([char in arg_string for char in list(CHARACTERS_TO_AVOID) + XML_CONSTRAINTS]):
        raise argparse.ArgumentTypeError(
            f"'{arg_string}' has an invalid character."
            f" Avoid to use '{CHARACTERS_TO_AVOID}' or '{''.join(XML_CONSTRAINTS)}'."
        )

    if append_slash and arg_string and arg_string[-1] != '/':
        return '{arg_string}/'.format(arg_string=arg_string)
    return arg_string


def aws_logs_groups_valid_key(arg_string):
    return arg_valid_key(arg_string, append_slash=False)


def arg_valid_accountid(arg_string):
    if arg_string is None:
        return []
    account_ids = arg_string.split(',')
    for account in account_ids:
        if not account.strip().isdigit() or len(account) != 12:
            raise argparse.ArgumentTypeError(
                "Not valid AWS account ID (numeric digits only): '{0}'.".format(arg_string))

    return account_ids


def arg_valid_regions(arg_string):
    if not arg_string:
        return []
    final_regions = []
    regions = arg_string.split(',')
    for arg_region in regions:
        if not re.match(r'^([a-z]{2}(-gov)?)-([a-z]{4,7})-\d$', arg_region):
            raise argparse.ArgumentTypeError(
                f"WARNING: The region '{arg_region}' has not a valid format.'"
            )
        if arg_region.strip():
            final_regions.append(arg_region.strip())
    final_regions = list(set(final_regions))
    final_regions.sort()
    return final_regions


def arg_valid_iam_role_duration(arg_string):
    """Checks if the role session duration specified is a valid parameter.

    Parameters
    ----------
    arg_string: str or None
        The desired session duration in seconds.

    Returns
    -------
    num_seconds: None or int
        The returned value will be None if no duration was specified or if it was an invalid value; elsewhere,
        it will return the number of seconds that the session will last.

    Raises
    ------
    argparse.ArgumentTypeError
        If the number provided is not in the expected range.
    """
    # Session duration must be between 15m and 12h
    if not (arg_string is None or (900 <= int(arg_string) <= 3600)):
        raise argparse.ArgumentTypeError("Invalid session duration specified. Value must be between 900 and 3600.")
    return int(arg_string)


def arg_valid_bucket_name(arg: str) -> str:
    """Validate the bucket name against the S3 naming rules.
    https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html

    Parameters
    ----------
    arg : str
        Argument to validate.

    Returns
    -------
    str
        The bucket name if match with the rules.

    Raises
    ------
    argparse.ArgumentTypeError
        If the bucket name is not valid.
    """
    if not re.match(r'(?!(^xn--|.+-s3alias$|.+--ol-s3$))^[a-z0-9][a-z0-9-.]{1,61}[a-z0-9]$', arg):
        raise argparse.ArgumentTypeError(f"'{arg}' isn't a valid bucket name.")
    return arg


def get_aws_config_params() -> configparser.RawConfigParser:
    """Read and retrieve parameters from aws config file

    Returns
    -------
    configparser.RawConfigParser
        The parsed configuration.
    """
    config = configparser.RawConfigParser()
    config.read(DEFAULT_AWS_CONFIG_PATH)

    return config


def get_script_arguments():
    parser = argparse.ArgumentParser(usage="usage: %(prog)s [options]",
                                     description="Wazuh wodle for monitoring AWS",
                                     formatter_class=argparse.RawTextHelpFormatter)
    # only one must be present (bucket or service)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-b', '--bucket', dest='logBucket', help='Specify the S3 bucket containing AWS logs',
                       action='store', type=arg_valid_bucket_name)
    group.add_argument('-sr', '--service', dest='service', help='Specify the name of the service',
                       action='store')
    group.add_argument('-sb', '--subscriber', dest='subscriber', help='Specify the type of the subscriber',
                       action='store')
    parser.add_argument('-q', '--queue', dest='queue', help='Specify the name of the SQS',
                        action='store')
    parser.add_argument('-O', '--aws_organization_id', dest='aws_organization_id',
                        help='AWS organization ID for logs', required=False)
    parser.add_argument('-c', '--aws_account_id', dest='aws_account_id',
                        help='AWS Account ID for logs', required=False,
                        type=arg_valid_accountid)
    parser.add_argument('-d', '--debug', action='store', dest='debug', default=0, help='Enable debug')
    parser.add_argument('-a', '--access_key', dest='access_key', default=None,
                        help='S3 Access key credential. '
                             f'{DEPRECATED_MESSAGE.format(name="access_key", release="4.4", url=CREDENTIALS_URL)}')
    parser.add_argument('-k', '--secret_key', dest='secret_key', default=None,
                        help='S3 Access key credential. '
                             f'{DEPRECATED_MESSAGE.format(name="secret_key", release="4.4", url=CREDENTIALS_URL)}')
    # Beware, once you delete history it's gone.
    parser.add_argument('-R', '--remove', action='store_true', dest='deleteFile',
                        help='Remove processed files from the AWS S3 bucket', default=False)
    parser.add_argument('-p', '--aws_profile', dest='aws_profile', help='The name of credential profile to use',
                        default=None)
    parser.add_argument('-x', '--external_id', dest='external_id', help='The name of the External ID to use',
                        default=None)
    parser.add_argument('-i', '--iam_role_arn', dest='iam_role_arn',
                        help='ARN of IAM role to assume for access to S3 bucket',
                        default=None)
    parser.add_argument('-n', '--aws_account_alias', dest='aws_account_alias',
                        help='AWS Account ID Alias', default='')
    parser.add_argument('-l', '--trail_prefix', dest='trail_prefix',
                        help='Log prefix for S3 key',
                        default='', type=arg_valid_key)
    parser.add_argument('-L', '--trail_suffix', dest='trail_suffix',
                        help='Log suffix for S3 key',
                        default='', type=arg_valid_key)
    parser.add_argument('-s', '--only_logs_after', dest='only_logs_after',
                        help='Only parse logs after this date - format YYYY-MMM-DD',
                        default=None, type=arg_valid_date)
    parser.add_argument('-r', '--regions', dest='regions', help='Comma delimited list of AWS regions to parse logs',
                        default='', type=arg_valid_regions)
    parser.add_argument('-e', '--skip_on_error', action='store_true', dest='skip_on_error',
                        help='If fail to parse a file, error out instead of skipping the file')
    parser.add_argument('-o', '--reparse', action='store_true', dest='reparse',
                        help='Parse the log file, even if its been parsed before', default=False)
    parser.add_argument('-t', '--type', dest='type', type=str, help='Bucket type.', default='cloudtrail')
    parser.add_argument('-g', '--aws_log_groups', dest='aws_log_groups', help='Name of the log group to be parsed',
                        default='', type=aws_logs_groups_valid_key)
    parser.add_argument('-P', '--remove-log-streams', action='store_true', dest='deleteLogStreams',
                        help='Remove processed log streams from the log group', default=False)
    parser.add_argument('-df', '--discard-field', type=str, dest='discard_field', default=None,
                        help='The name of the event field where the discard_regex should be applied to determine if '
                             'an event should be skipped.', )
    parser.add_argument('-dr', '--discard-regex', type=str, dest='discard_regex', default=None,
                        help='REGEX value to be applied to determine whether an event should be skipped.', )
    parser.add_argument('-st', '--sts_endpoint', type=str, dest='sts_endpoint', default=None,
                        help='URL for the VPC endpoint to use to obtain the STS token.')
    parser.add_argument('-se', '--service_endpoint', type=str, dest='service_endpoint', default=None,
                        help='URL for the endpoint to use to obtain the logs.')
    parser.add_argument('-rd', '--iam_role_duration', type=arg_valid_iam_role_duration, dest='iam_role_duration',
                        default=None,
                        help='The duration, in seconds, of the role session. Value can range from 900s to the max'
                             ' session duration set for the role.')
    parsed_args = parser.parse_args()

    if parsed_args.iam_role_duration is not None and parsed_args.iam_role_arn is None:
        raise argparse.ArgumentTypeError('Used --iam_role_duration argument but no --iam_role_arn provided.')

    return parsed_args
