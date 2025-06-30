#!/usr/bin/env python3
#
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

import logging
import sys
from argparse import ArgumentParser
from datetime import datetime, timedelta, timezone
from os.path import abspath, dirname
from socket import AF_UNIX, SOCK_DGRAM
from socket import error as socket_error
from socket import socket

from requests import RequestException, post

sys.path.insert(0, dirname(dirname(abspath(__file__))))

from utils import ANALYSISD, MAX_EVENT_SIZE

SOCKET_HEADER = '1:Azure:'

DATETIME_MASK = '%Y-%m-%dT%H:%M:%S.%fZ'

# Logger parameters
LOGGING_MSG_FORMAT = '%(asctime)s azure: %(levelname)s: %(message)s'
LOGGING_DATE_FORMAT = '%Y/%m/%d %H:%M:%S'
LOG_LEVELS = {0: logging.WARNING, 1: logging.INFO, 2: logging.DEBUG}

CREDENTIALS_URL = 'https://documentation.wazuh.com/current/azure/activity-services/prerequisites/credentials.html'
DEPRECATED_MESSAGE = (
    'The {name} authentication parameter was deprecated in {release}. '
    'Please use another authentication method instead. Check {url} for more information.'
)
URL_LOGGING = 'https://login.microsoftonline.com'

EXCEED_EPS_WAIT = 1


def set_logger(debug_level: int):
    """Set the logger configuration."""
    logging.basicConfig(
        level=LOG_LEVELS.get(debug_level, logging.INFO),
        format=LOGGING_MSG_FORMAT,
        datefmt=LOGGING_DATE_FORMAT,
    )
    logging.getLogger('azure').setLevel(LOG_LEVELS.get(debug_level, logging.WARNING))
    logging.getLogger('urllib3').setLevel(logging.ERROR)


def get_script_arguments():
    """Read and parse arguments."""
    parser = ArgumentParser()

    # only one must be present (log_analytics, graph or storage)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        '--log_analytics',
        action='store_true',
        required=False,
        help='Activates Log Analytics API call.',
    )
    group.add_argument(
        '--graph', action='store_true', required=False, help='Activates Graph API call.'
    )
    group.add_argument(
        '--storage',
        action='store_true',
        required=False,
        help='Activates Storage API call.',
    )

    # Log Analytics arguments #
    parser.add_argument(
        '--la_id',
        metavar='ID',
        type=str,
        required=False,
        help='Application ID for Log Analytics authentication. '
        f'{DEPRECATED_MESSAGE.format(name="la_id", release="4.4", url=CREDENTIALS_URL)}',
    )
    parser.add_argument(
        '--la_key',
        metavar='KEY',
        type=str,
        required=False,
        help='Application Key for Log Analytics authentication. '
        f'{DEPRECATED_MESSAGE.format(name="la_key", release="4.4", url=CREDENTIALS_URL)}',
    )
    parser.add_argument(
        '--la_auth_path',
        metavar='filepath',
        type=str,
        required=False,
        help='Path of the file containing the credentials for authentication.',
    )
    parser.add_argument(
        '--la_tenant_domain',
        metavar='domain',
        type=str,
        required=False,
        help='Tenant domain for Log Analytics.',
    )
    parser.add_argument(
        '--la_query',
        metavar='query',
        required=False,
        help='Query for Log Analytics.',
        type=arg_valid_la_query,
    )
    parser.add_argument(
        '--workspace',
        metavar='workspace',
        type=str,
        required=False,
        help='Workspace for Log Analytics.',
    )
    parser.add_argument(
        '--la_tag',
        metavar='tag',
        type=str,
        required=False,
        help='Tag that is added to the query result.',
    )
    parser.add_argument(
        '--la_time_offset',
        metavar='time',
        type=str,
        required=False,
        help='Time range for the request.',
    )

    # Graph arguments #
    parser.add_argument(
        '--graph_id',
        metavar='ID',
        type=str,
        required=False,
        help='Application ID for Graph authentication. '
        f'{DEPRECATED_MESSAGE.format(name="graph_id", release="4.4", url=CREDENTIALS_URL)}',
    )
    parser.add_argument(
        '--graph_key',
        metavar='KEY',
        type=str,
        required=False,
        help='Application KEY for Graph authentication. '
        f'{DEPRECATED_MESSAGE.format(name="graph_key", release="4.4", url=CREDENTIALS_URL)}',
    )
    parser.add_argument(
        '--graph_auth_path',
        metavar='filepath',
        type=str,
        required=False,
        help='Path of the file containing the credentials authentication.',
    )
    parser.add_argument(
        '--graph_tenant_domain',
        metavar='domain',
        type=str,
        required=False,
        help='Tenant domain for Graph.',
    )
    parser.add_argument(
        '--graph_query',
        metavar='query',
        required=False,
        type=arg_valid_graph_query,
        help='Query for Graph.',
    )
    parser.add_argument(
        '--graph_tag',
        metavar='tag',
        type=str,
        required=False,
        help='Tag that is added to the query result.',
    )
    parser.add_argument(
        '--graph_time_offset',
        metavar='time',
        type=str,
        required=False,
        help='Time range for the request.',
    )

    # Storage arguments #
    parser.add_argument(
        '--account_name',
        metavar='account',
        type=str,
        required=False,
        help='Storage account name for authentication. '
        f'{DEPRECATED_MESSAGE.format(name="account_name", release="4.4", url=CREDENTIALS_URL)}',
    )
    parser.add_argument(
        '--account_key',
        metavar='KEY',
        type=str,
        required=False,
        help='Storage account key for authentication. '
        f'{DEPRECATED_MESSAGE.format(name="account_key", release="4.4", url=CREDENTIALS_URL)}',
    )
    parser.add_argument(
        '--storage_auth_path',
        metavar='filepath',
        type=str,
        required=False,
        help='Path of the file containing the credentials authentication.',
    )
    parser.add_argument(
        '--container',
        metavar='container',
        required=False,
        type=arg_valid_container_name,
        help='Name of the container where searches the blobs.',
    )
    parser.add_argument(
        '--blobs',
        metavar='blobs',
        required=False,
        type=arg_valid_blob_extension,
        help='Extension of blobs. For example: "*.log"',
    )
    parser.add_argument(
        '--storage_tag',
        metavar='tag',
        type=str,
        required=False,
        help='Tag that is added to each blob request.',
    )
    parser.add_argument(
        '--json_file',
        action='store_true',
        required=False,
        help='Specifies that the blob is only composed of events in json file format. '
        'By default, the content of the blob is considered to be plain text.',
    )
    parser.add_argument(
        '--json_inline',
        action='store_true',
        required=False,
        help='Specifies that the blob is only composed of events in json inline format. '
        'By default, the content of the blob is considered to be plain text.',
    )
    parser.add_argument(
        '--storage_time_offset',
        metavar='time',
        type=str,
        required=False,
        help='Time range for the request.',
    )
    parser.add_argument(
        '-p',
        '--prefix',
        dest='prefix',
        help='The relative path to the logs',
        type=str,
        required=False,
    )

    # General parameters #
    parser.add_argument(
        '--reparse',
        action='store_true',
        dest='reparse',
        help='Parse the log, even if its been parsed before',
        default=False,
    )
    parser.add_argument(
        '-d',
        '--debug',
        action='store',
        type=int,
        dest='debug_level',
        default=0,
        help='Specify debug level. Admits values from 0 to 2.',
    )

    return parser.parse_args()


def arg_valid_container_name(arg_string):
    return arg_string.replace('"', '') if arg_string else arg_string


def arg_valid_graph_query(arg_string):
    if arg_string:
        if arg_string[0] == "'":
            arg_string = arg_string[1:]
        if arg_string[-1] == "'":
            arg_string = arg_string[:-1]
        return arg_string.replace('\\$', '$')


def arg_valid_la_query(arg_string):
    return arg_string.replace('\\!', '!') if arg_string else arg_string


def arg_valid_blob_extension(arg_string):
    return arg_string.replace('"', '').replace('*', '') if arg_string else arg_string


def read_auth_file(auth_path: str, fields: tuple):
    """Read the authentication file. Its contents must be in 'field = value' format.

    Parameters
    ----------
    auth_path : str
        Path to the authentication file.
    fields : tuple
        Tuple of 2 str field names expected to be in the authentication file.

    Returns
    -------
    tuple of str
        The field values for the requested authentication fields.
    """
    credentials = {}
    try:
        with open(auth_path, 'r') as auth_file:
            for line in auth_file:
                key, value = (
                    line.replace(' ', '').replace('\n', '').split('=', maxsplit=1)
                )
                if not value:
                    continue
                credentials[key] = value.replace('\n', '')
        if fields[0] not in credentials or fields[1] not in credentials:
            logging.error(
                f'Error: The authentication file does not contains the expected "{fields[0]}" '
                f'and "{fields[1]}" fields.'
            )
            sys.exit(1)
        return credentials[fields[0]], credentials[fields[1]]
    except ValueError:
        logging.error(
            'Error: The authentication file format is not valid. '
            'Make sure that it is composed of only 2 lines with "field = value" format.'
        )
        sys.exit(1)
    except OSError as e:
        logging.error(f'Error: The authentication file could not be opened: {e}')
        sys.exit(1)


def get_token(client_id: str, secret: str, domain: str, scope: str):
    """Get the authentication token for accessing a given resource in the specified domain.

    Parameters
    ----------
    client_id : str
        The client ID.
    secret : str
        The client secret.
    domain : str
        The tenant domain.
    scope : str
        The scope for the token requested.

    Returns
    -------
    str
        A valid token.
    """
    body = {
        'client_id': client_id,
        'client_secret': secret,
        'scope': scope,
        'grant_type': 'client_credentials',
    }
    auth_url = f'{URL_LOGGING}/{domain}/oauth2/v2.0/token'
    token_response = {}
    try:
        token_response = post(auth_url, data=body, timeout=10).json()
        return token_response['access_token']
    except (ValueError, KeyError):
        if token_response['error'] == 'unauthorized_client':
            err_msg = 'The application id provided is not valid.'
        elif token_response['error'] == 'invalid_client':
            err_msg = 'The application key provided is not valid.'
        elif (
            token_response['error'] == 'invalid_request'
            and 90002 in token_response['error_codes']
        ):
            err_msg = f'The "{domain}" tenant domain was not found.'
        else:
            err_msg = 'Couldn\'t get the token for authentication.'
        logging.error(f'Error: {err_msg}')

    except RequestException as e:
        logging.error(
            f'Error: An error occurred while trying to obtain the authentication token: {e}'
        )

    sys.exit(1)


class SocketConnection:
    _socket = socket(AF_UNIX, SOCK_DGRAM)
    _msg_template = '{header}{message}'

    def __init__(self):
        try:
            self._socket.connect(ANALYSISD)
        except socket_error as e:
            if e.errno == 111:
                logging.error('ERROR: Wazuh must be running.')
                sys.exit(1)

    def __enter__(self) -> "SocketConnection":
        return self

    def __exit__(self, type, value, traceback):
        self._socket.close()

    def send_message(self, message: str) -> None:
        """Send a message with a header to the analysisd queue.

        Parameters
        ----------
        message : str
            The message body to send to analysisd.
        """
        encoded_msg = self._msg_template.format(header=SOCKET_HEADER, message=message).encode(errors='replace')

        # Logs warning if event is bigger than max size
        if len(encoded_msg) > MAX_EVENT_SIZE:
            logging.warning(
                f'WARNING: Event size exceeds the maximum allowed limit of {MAX_EVENT_SIZE} bytes.'
            )

        try:
            self._socket.send(encoded_msg)
        except socket_error as e:
            if e.errno == 90:
                logging.error('ERROR: Message too long to send to Wazuh.  Skipping message...')
            else:
                logging.error(f'ERROR: Error sending message to wazuh: {e}')


def offset_to_datetime(offset: str):
    """Transform an offset value to a datetime object.

    Parameters
    ----------
    offset : str
        A positive number containing a suffix character that indicates its time unit,
        such as, s (seconds), m (minutes), h (hours), d (days), w (weeks), M (months).

    Returns
    -------
    datetime
        The result of subtracting the offset value from the current datetime.
    """
    offset = offset.replace(' ', '')
    value = int(offset[: len(offset) - 1])
    unit = offset[len(offset) - 1 :]

    if unit == 'h':
        return datetime.utcnow().replace(tzinfo=timezone.utc) - timedelta(hours=value)
    if unit == 'm':
        return datetime.utcnow().replace(tzinfo=timezone.utc) - timedelta(minutes=value)
    if unit == 'd':
        return datetime.utcnow().replace(tzinfo=timezone.utc) - timedelta(days=value)

    logging.error('Invalid offset format. Use "h", "m" or "d" time unit.')
    exit(1)


def get_max_eps_value() -> int:
    """Read the `wazuh_modules.max_eps` value from the internal_options.conf file

    Returns
    -------
    int
        The value of the max_eps configuration
    """

    max_eps_conf = ''
    with open('/var/ossec/etc/internal_options.conf', 'r') as file:
        for line in file.readlines():
            if line.startswith('wazuh_modules.max_eps'):
                max_eps_conf = line.strip()

    return int(max_eps_conf.split('=')[1])