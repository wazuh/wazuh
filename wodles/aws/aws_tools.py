#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""This module contains generic functions for this wodle."""

import argparse
import configparser
from datetime import datetime
from typing import Optional
import sys
import re

import constants

# Enable/disable debug mode
debug_level = 0


def set_profile_dict_config(boto_config: dict, profile: str, profile_config: dict):
    """Create a botocore.config.Config object with the specified profile_config.

    This function reads the profile configuration from the provided profile_config object and extracts the necessary
    parameters to create a botocore.config.Config object.
    It handles the signature version, s3, proxies, and proxies_config settings found in the .aws/config file.
    If a setting is not found, a default value is used based on the boto3 documentation and config is
    set into the boto_config.

    Parameters
    ----------
    boto_config: dict
        The config dictionary where the Boto Config will be set.

    profile : str
        The AWS profile name to use for the configuration.

    profile_config : dict
        The user config dict containing the profile configuration.
    """
    profile = remove_prefix(profile, 'profile ')

    # Set s3 config
    if 's3' in str(profile_config):
        s3_config = {
            "max_concurrent_requests": int(profile_config.get('s3.max_concurrent_requests', 10)),
            "max_queue_size": int(profile_config.get('s3.max_queue_size', 10)),
            "multipart_threshold": profile_config.get('s3.multipart_threshold', '8MB'),
            "multipart_chunksize": profile_config.get('s3.multipart_chunksize', '8MB'),
            "max_bandwidth": profile_config.get('s3.max_bandwidth'),
            "use_accelerate_endpoint": (
                True if profile_config.get('s3.use_accelerate_endpoint') == 'true' else False
            ),
            "addressing_style": profile_config.get('s3.addressing_style', 'auto'),
        }
        boto_config['config'].s3 = s3_config

    # Set Proxies configuration
    if 'proxy' in str(profile_config):
        proxy_config = {
            "host": profile_config.get('proxy.host'),
            "port": int(profile_config.get('proxy.port')),
            "username": profile_config.get('proxy.username'),
            "password": profile_config.get('proxy.password'),
        }
        boto_config['config'].proxies = proxy_config

        proxies_config = {
            "ca_bundle": profile_config.get('proxy.ca_bundle'),
            "client_cert": profile_config.get('proxy.client_cert'),
            "use_forwarding_for_https": (
                True if profile_config.get('proxy.use_forwarding_for_https') == 'true' else False
            )
        }
        boto_config['config'].proxies_config = proxies_config
    
    # Checks for retries config in profile config and sets it if not found to avoid throttling exception
    if constants.RETRY_ATTEMPTS_KEY in profile_config or constants.RETRY_MODE_CONFIG_KEY in profile_config:
        retries = {
            constants.RETRY_ATTEMPTS_KEY: int(profile_config.get(constants.RETRY_ATTEMPTS_KEY, 10)),
            constants.RETRY_MODE_BOTO_KEY: profile_config.get(constants.RETRY_MODE_CONFIG_KEY, 'standard')
        }
        debug(f"Retries parameters found in user profile. Using profile '{profile}' retries configuration", 2)
        boto_config['config'].retries = retries

    else:
        debug(
            "No retries configuration found in profile config. Generating default configuration for retries: mode: "
            f"{boto_config['config'].retries['mode']} - max_attempts: {boto_config['config'].retries['max_attempts']}",
            2)

    # Set signature version
    boto_config['config'].signature_version = profile_config.get('signature_version', 's3v4')


def remove_prefix(text: str, prefix: str) -> str:
    """Removes the prefix from the text if it exists. Otherwise, it returns the text unchanged.

    Parameters
    ----------
    text : str
        Text to remove the prefix from.
    prefix : str
        Prefix to be removed.

    Returns
    -------
    str
        Text without the prefix.
    """
    return text[len(prefix):] if text.startswith(prefix) else text


def handler(signal, frame):
    print("ERROR: SIGINT received.")
    sys.exit(2)


def debug(msg, msg_level):
    if debug_level >= msg_level:
        print('DEBUG: {debug_msg}'.format(debug_msg=msg))


def error(msg):
    print('ERROR: {error_msg}'.format(error_msg=msg))


def info(msg):
    print('INFO: {msg}'.format(msg=msg))


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
        if not re.match(r'^([a-z]{2}(-gov)?)-([a-z]+)-\d$', arg_region):
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
    if arg_string is None:
        return None

    # Validate if the argument is a number
    if not arg_string.isdigit():
        raise argparse.ArgumentTypeError("Invalid session duration specified. Value must be a valid number.")

    # Convert to integer and check range
    num_seconds = int(arg_string)
    if not (900 <= num_seconds <= 43200):
        raise argparse.ArgumentTypeError("Invalid session duration specified. Value must be between 900 and 43200.")

    return num_seconds


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


def args_valid_iam_role_arn(iam_role_arn):
    """Checks if the IAM role ARN specified is a valid parameter.

    Parameters
    ----------
    iam_role_arn : str
        The IAM role ARN to validate.

    Raises
    ------
    argparse.ArgumentTypeError
        If the ARN provided is not in the expected format.
    """
    pattern = r'^arn:(?P<Partition>[^:\n]*):(?P<Service>[^:\n]*):(?P<Region>[^:\n]*):(?P<AccountID>[^:\n]*):(?P<Ignore>(?P<ResourceType>[^:\/\n]*)[:\/])?(?P<Resource>.*)$'

    if not re.match(pattern, iam_role_arn):
        raise argparse.ArgumentTypeError("Invalid ARN Role specified. Value must be a valid ARN Role.")

    return iam_role_arn


def args_valid_sqs_name(sqs_name):
    """Checks if the SQS name specified is a valid parameter.

    Parameters
    ----------
    sqs_name : str
        The SQS name to validate.

    Raises
    ------
    argparse.ArgumentTypeError
        If the SQS name provided is not in the expected format.
    """
    pattern = r'^[a-zA-Z0-9-_]{1,80}$'

    if not re.match(pattern, sqs_name):
        raise argparse.ArgumentTypeError("Invalid SQS Name specified. Value must be up to 80 characters and the valid "
                                         "values are alphanumeric characters, hyphens (-), and underscores (_)")

    return sqs_name


def arg_validate_security_lake_auth_params(external_id: Optional[str], name: Optional[str], iam_role_arn: Optional[str]):
    """
    Validate the Securit Lake authentication arguments.

    Parameters
    ----------
    external_id : Optional[str]
        The name of the External ID to use.
    name: Optional[str]
        Name of the SQS Queue.
    iam_role_arn : Optional[str]
        IAM Role.
    """

    if iam_role_arn is None:
        error('Used a subscriber but no --iam_role_arn provided.')
        sys.exit(21)
    if name is None:
        error('Used a subscriber but no --queue provided.')
        sys.exit(21)
    if external_id is None:
        error('Used a subscriber but no --external_id provided.')
        sys.exit(21)


def get_aws_config_params() -> configparser.RawConfigParser:
    """Read and retrieve parameters from aws config file.

    Returns
    -------
    configparser.RawConfigParser
        The parsed configuration.
    """
    config = configparser.RawConfigParser()
    config.read(constants.DEFAULT_AWS_CONFIG_PATH)

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
                        type=args_valid_sqs_name, action='store')
    parser.add_argument('-O', '--aws_organization_id', dest='aws_organization_id',
                        help='AWS organization ID for logs', required=False)
    parser.add_argument('-c', '--aws_account_id', dest='aws_account_id',
                        help='AWS Account ID for logs', required=False,
                        type=arg_valid_accountid)
    parser.add_argument('-d', '--debug', action='store', dest='debug', default=0, help='Enable debug')
    # Beware, once you delete history it's gone.
    parser.add_argument('-R', '--remove', action='store_true', dest='deleteFile',
                        help='Remove processed files from the AWS S3 bucket', default=False)
    parser.add_argument('-p', '--aws_profile', dest='aws_profile', help='The name of credential profile to use',
                        default=None)
    parser.add_argument('-x', '--external_id', dest='external_id', help='The name of the External ID to use',
                        default=None)
    parser.add_argument('-i', '--iam_role_arn', dest='iam_role_arn',
                        help='ARN of IAM role to assume for access to S3 bucket',
                        type=args_valid_iam_role_arn,
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
                        help='If fail to parse a file, error out instead of skipping the file', default=False)
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
