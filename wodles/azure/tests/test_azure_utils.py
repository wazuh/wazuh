#!/usr/bin/env python3
#
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

import logging
import os
import socket
import sys
from os.path import abspath, dirname
from unittest.mock import MagicMock, patch

import pytest
from dateutil.parser import parse
from requests import RequestException

sys.path.insert(0, dirname(dirname(abspath(__file__))))

from azure_utils import (
    ANALYSISD,
    LOG_LEVELS,
    LOGGING_DATE_FORMAT,
    LOGGING_MSG_FORMAT,
    SOCKET_HEADER,
    URL_LOGGING,
    arg_valid_blob_extension,
    arg_valid_container_name,
    arg_valid_graph_query,
    arg_valid_la_query,
    get_script_arguments,
    get_token,
    offset_to_datetime,
    read_auth_file,
    SocketConnection,
    set_logger,
)

TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
TEST_AUTHENTICATION_PATH = os.path.join(TEST_DATA_PATH, 'authentication_files')


@pytest.mark.parametrize('debug_level', [0, 1, 2, 3])
@patch('azure_utils.logging.basicConfig')
def test_set_logger(mock_logging, debug_level):
    """Test set_logger sets the expected logging verbosity level."""
    set_logger(debug_level)
    mock_logging.assert_called_with(
        level=LOG_LEVELS.get(debug_level, logging.INFO),
        format=LOGGING_MSG_FORMAT,
        datefmt=LOGGING_DATE_FORMAT,
    )
    assert logging.getLogger('azure').level == LOG_LEVELS.get(debug_level, logging.WARNING).real
    assert logging.getLogger('urllib3').level == logging.ERROR.real


def test_get_script_arguments(capsys):
    """Test get_script_arguments shows no messages when the required parameters were provided."""
    with patch('sys.argv', ['main', '--graph']):
        get_script_arguments()
    stdout, stderr = capsys.readouterr()
    assert stdout == '', 'stdout was not empty'
    assert stderr == '', 'stderr was not empty'


@pytest.mark.parametrize(
    'args',
    [
        ['main'],
        ['main', '--graph', '--log_analytics'],
        ['main', '--graph', '--storage'],
        ['main', '--log_analytics', '--storage'],
    ],
)
def test_get_script_arguments_exclusive(capsys, args):
    """Test get_script_arguments shows an error message when the required parameters are not provided."""
    with patch('sys.argv', args), pytest.raises(SystemExit) as exception:
        get_script_arguments()
    stdout, stderr = capsys.readouterr()
    assert stdout == '', 'The output was not empty'
    assert stderr != '', 'No error message was found in the output'
    assert exception.value.code == 2


@pytest.mark.parametrize('arg_string', ['"string"', "'string'", None])
def test_arg_valid_container_name(arg_string):
    """Test arg_valid_container_name removes unwanted characters from the container name."""
    result = arg_valid_container_name(arg_string)
    if result:
        assert '"' not in result


@pytest.mark.parametrize('arg_string', ['"string"', "'string'", 'string\\$', "string 'test'", None])
def test_arg_valid_graph_query(arg_string):
    """Test arg_valid_graph_query removes unwanted characters from the graph query."""
    result = arg_valid_graph_query(arg_string)
    if result:
        assert result[0] != "'"
        assert result[-1] != "'"
        assert '\\$' not in result


@pytest.mark.parametrize('arg_string', ['string!', 'string\\!', '\\!string\\!', None])
def test_arg_valid_la_query(arg_string):
    """Test arg_valid_la_query removes unwanted characters from the log analytics query."""
    result = arg_valid_la_query(arg_string)
    if result:
        assert '\\!' not in result


@pytest.mark.parametrize('arg_string', ['"string"', '*', '"*"', None])
def test_arg_valid_blob_extension(arg_string):
    """Test arg_valid_blob_extension removes unwanted characters from the blob extension."""
    result = arg_valid_blob_extension(arg_string)
    if result:
        assert '"' not in result
        assert '*' not in result


@pytest.mark.parametrize(
    'file_name, fields',
    [
        ('valid_authentication_file', ('application_id', 'application_key')),
        ('valid_authentication_file_alt', ('application_key', 'application_id')),
        ('valid_authentication_file_extra_line', ('application_id', 'application_key')),
        ('valid_authentication_file_storage', ('account_name', 'account_key')),
    ],
)
def test_read_auth_file(file_name, fields):
    """Test read_auth_file correctly handles valid authentication files."""
    credentials = read_auth_file(auth_path=os.path.join(TEST_AUTHENTICATION_PATH, file_name), fields=fields)
    assert isinstance(credentials, tuple)
    for i in range(len(fields)):
        assert credentials[i] == f'{fields[i]}_value'


@pytest.mark.parametrize(
    'file_name',
    [
        'no_file',
        'empty_authentication_file',
        'invalid_authentication_file',
        'invalid_authentication_file_2',
        'invalid_authentication_file_3',
    ],
)
@patch('azure_utils.logging.error')
def test_read_auth_file_ko(mock_logging, file_name):
    """Test read_auth_file correctly handles invalid authentication files."""
    with pytest.raises(SystemExit) as err:
        read_auth_file(
            auth_path=os.path.join(TEST_AUTHENTICATION_PATH, file_name),
            fields=('field', 'field'),
        )
    assert err.value.code == 1
    mock_logging.assert_called_once()


@patch('azure_utils.post')
def test_get_token(mock_post):
    """Test get_token makes the expected token request and returns its value."""
    expected_token = 'token'
    client_id = 'client'
    secret = 'secret'
    scope = 'scope'
    domain = 'domain'
    body = {
        'client_id': client_id,
        'client_secret': secret,
        'scope': scope,
        'grant_type': 'client_credentials',
    }
    m = MagicMock()
    m.json.return_value = {'access_token': expected_token}
    mock_post.return_value = m
    token = get_token(client_id, secret, domain, scope)
    auth_url = f'{URL_LOGGING}/{domain}/oauth2/v2.0/token'
    mock_post.assert_called_with(auth_url, data=body, timeout=10)
    assert token == expected_token


@pytest.mark.parametrize(
    'exception, error_msg, error_codes',
    [
        (RequestException, None, None),
        (None, 'unauthorized_client', None),
        (None, 'invalid_client', None),
        (None, 'invalid_request', [0]),
        (None, 'invalid_request', [0, 90002]),
        (None, 'invalid', []),
        (None, '', []),
        (None, None, []),
    ],
)
@patch('azure_utils.logging.error')
@patch('azure_utils.post')
def test_get_token_ko(mock_post, mock_logging, exception, error_msg, error_codes):
    """Test get_token handles exceptions when the 'access_token' field is not present in the response."""
    m = MagicMock()
    m.json.return_value = {'error': error_msg, 'error_codes': error_codes}
    mock_post.return_value = m
    mock_post.side_effect = exception
    with pytest.raises(SystemExit) as err:
        get_token(client_id=None, secret=None, domain=None, scope=None)
    assert err.value.code == 1
    mock_logging.assert_called_once()


@patch('azure_utils.socket.connect')
def test_socket_connection_init(mock_connect):
    """Test SocketConnection correctly connect to the socket."""
    SocketConnection()

    mock_connect.assert_called_with(ANALYSISD)


@pytest.mark.parametrize('error_code', [111])
@patch('azure_utils.logging.error')
@patch('azure_utils.socket.connect')
def test_socket_connection_init_ko(mock_connect, mock_logging, error_code):
    """Test SocketConnection handle the socket exception."""
    s = socket.error()
    s.errno = error_code
    mock_connect.side_effect = s

    with pytest.raises(SystemExit) as err:
        SocketConnection()
    assert err.value.code == 1

    mock_logging.assert_called_once()


@patch('azure_utils.socket.close')
@patch('azure_utils.socket.send')
@patch('azure_utils.socket.connect')
def test_socket_connection_send_message(mock_connect, mock_send, mock_close):
    """Test send_message sends the messages to the Wazuh queue socket."""
    message = 'msg'

    with SocketConnection() as socket:
        socket.send_message(message)

    mock_connect.assert_called_with(ANALYSISD)
    mock_send.assert_called_with(f'{SOCKET_HEADER}{message}'.encode(errors='replace'))
    mock_close.assert_called_once()


@pytest.mark.parametrize('error_code', [90, 1])
@patch('azure_utils.logging.error')
@patch('azure_utils.socket.close')
@patch('azure_utils.socket.send')
@patch('azure_utils.socket.connect')
def test_socket_connection_send_message_ko(mock_connect, mock_send, mock_close, mock_logging, error_code):
    """Test send_message handle the socket exceptions."""
    s = socket.error()
    s.errno = error_code
    mock_send.side_effect = s

    with SocketConnection() as socket_conn:
        socket_conn.send_message('')

    mock_logging.assert_called_once()
    mock_close.assert_called_once()


@pytest.mark.parametrize(
    'offset, expected_date',
    [
        ('1d', '2022-12-30T12:00:00.000000Z'),
        ('1h', '2022-12-31T11:00:00.000000Z'),
        ('1m', '2022-12-31T11:59:00.000000Z'),
    ],
)
@patch('azure_utils.datetime')
def test_offset_to_datetime(mock_time, offset, expected_date):
    """Test offset_to_datetime returns the expected values for the offset provided."""
    mock_time.utcnow.return_value = parse('2022-12-31T12:00:00.000000Z')
    result = offset_to_datetime(offset)
    assert result == parse(expected_date)


@patch('azure_utils.logging.error')
@patch('azure_utils.datetime')
def test_offset_to_datetime_ko(mock_time, mock_logging):
    """Test offset_to_datetime handles the exception when an invalid offset format was provided."""
    with pytest.raises(SystemExit) as err:
        offset_to_datetime('1x')
    assert err.value.code == 1
    mock_logging.assert_called_once()
