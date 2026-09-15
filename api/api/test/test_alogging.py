# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
from copy import copy
from unittest.mock import patch, call, MagicMock

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from api import alogging
        from api.api_exception import APIError

REQUEST_HEADERS_TEST = {'authorization': 'Basic d2F6dWg6cGFzc3dvcmQxMjM='}  # wazuh:password123
AUTH_CONTEXT_TEST = {'auth_context': 'example'}
HASH_AUTH_CONTEXT_TEST = '020efd3b53c1baf338cf143fad7131c3'


@pytest.mark.parametrize('message, dkt', [
    (None, {'k1': 'v1'}),
    ('message_value', {'exc_info': 'traceback_value'}),
    ('message_value', {})
])
def test_wazuhjsonformatter(message, dkt):
    """Check wazuh json formatter is working as expected.

    Parameters
    ----------
    message : str
        Value used as a log record message.
    dkt : dict
        Dictionary used as a request or exception information.
    """
    with patch('api.alogging.logging.LogRecord') as mock_record:
        mock_record.message = message
        wjf = alogging.WazuhJsonFormatter()
        log_record = {}
        wjf.add_fields(log_record, mock_record, dkt)
        assert 'timestamp' in log_record
        assert 'data' in log_record
        assert 'levelname' in log_record
        tb = dkt.get('exc_info')
        if tb is not None:
            assert log_record['data']['payload'] == f'{message}. {tb}'
        elif message is None:
            assert log_record['data']['payload'] == dkt
        else:
            assert log_record['data']['payload'] == message
        assert isinstance(log_record, dict)


@pytest.mark.parametrize("size_input, expected_size", [
    ("1m", 1024 * 1024),
    ("1M", 1024 * 1024),
    ("1024k", 1024 * 1024),
    ("1024K", 1024 * 1024),
    ("5m", 5 * 1024 * 1024)
])
def test_api_logger_size(size_input, expected_size):
    """Assert `APILoggerSize` class returns the correct number of bytes depending on the given unit.

    Parameters
    ----------
    size_input : str
        Input for the class constructor.
    expected_size : int
        Expected number of bytes after translating the input.
    """
    assert alogging.APILoggerSize(size_input).size == expected_size


def test_api_logger_size_exceptions():
    """Assert `APILoggerSize` class returns the correct exceptions when the given size is not valid."""
    # Test invalid units
    with pytest.raises(APIError, match="2011.*expected format.*"):
        alogging.APILoggerSize("3435j")

    # Test min value
    with pytest.raises(APIError, match="2011.*Minimum value.*"):
        alogging.APILoggerSize("1k")


@pytest.mark.parametrize("path, hash_auth_context, body, loggerlevel", [
    ("/agents", '', {'bodyfield': 1}, 1),
    ("/agents", 'hashauthcontext', {'bodyfield': 1}, 21),
    ("/events", '', {'bodyfield': 1, 'events' : [{'a': 1, 'b': 2 }]}, 1),
    ("/events", 'hashauthcontext', {'bodyfield': 1, 'events' : [{'a': 1, 'b': 2 }]}, 22),
    ("/events", 'hashauthcontext', ['foo', 'bar'], 22),
    ("/events", 'hashauthcontext', 'foo', 22),
])
def test_custom_logging(path, hash_auth_context, body, loggerlevel):
    """Test custom access logging calls."""
    user, remote, method = ('wazuh', '1.1.1.1', 'POST')
    query, elapsed_time, status, headers =  {'pretty': True}, 1.01, 200, {'content-type': 'xml'}
    json_info = {
        'user': user,
        'ip': remote,
        'http_method': method,
        'uri': f'{method} {path}',
        'parameters': query,
        'body': body,
        'time': f'{elapsed_time:.3f}s',
        'status_code': status
    }

    log_info = f'{user} ({hash_auth_context}) {remote} "{method} {path}" ' if hash_auth_context \
                else f'{user} ({hash_auth_context}) {remote} "{method} {path}" '
    json_info.update({'hash_auth_context' : hash_auth_context} if hash_auth_context else {})
    with patch('api.alogging.logger') as log_info_mock:
        log_info_mock.info = MagicMock()
        log_info_mock.debug2 = MagicMock()
        log_info_mock.level = loggerlevel
        alogging.custom_logging(user=user, remote=remote, method=method, path=path, query=query,
                        body=copy(body), elapsed_time=elapsed_time, status=status,
                        hash_auth_context=hash_auth_context, headers=headers)

        if path == '/events' and loggerlevel >= 20:
            if isinstance(body, dict):
                events = body.get('events', [])
                body = {'events': len(events)}
                json_info['body'] = body
        log_info += f'with parameters {json.dumps(query)} and body'\
                    f' {json.dumps(body)} done in {elapsed_time:.3f}s: {status}'
        log_info_mock.info.has_calls([call(log_info, {'log_type': 'log'}),
                                      call(json_info, {'log_type': 'json'})])
        log_info_mock.debug2.assert_called_with(f'Receiving headers {headers}')


@pytest.mark.parametrize("value, expected", [
    ('plain', 'plain'),
    ('a\nb', 'a\\nb'),
    ('a\r\n\tb', 'a\\r\\n\\tb'),
    ('a\x1b[31mb\x00\x7f', 'a\\x1b[31mb\\x00\\x7f'),
    ('already\\nescaped', 'already\\nescaped'),
])
def test_escape_control_chars(value, expected):
    """Check every C0 control character and DEL is replaced by its escape sequence."""
    assert alogging.escape_control_chars(value) == expected


@pytest.mark.parametrize("user, path, expected_prefix", [
    ('wazuh\nFAKE 127.0.0.1 "GET /security/users"', '/agents',
     'wazuh\\nFAKE 127.0.0.1 "GET /security/users" 1.1.1.1 "GET /agents"'),
    ('wazuh', '/x\n2026/01/01 03:14:15 INFO: admin 10.0.0.5 "GET /agents',
     'wazuh 1.1.1.1 "GET /x\\n2026/01/01 03:14:15 INFO: admin 10.0.0.5 "GET /agents"'),
    (None, '/x\r\n\x1b[2J', 'None 1.1.1.1 "GET /x\\r\\n\\x1b[2J"'),
])
def test_custom_logging_escapes_control_chars(user, path, expected_prefix):
    """The plain-text access log entry stays on one line whatever the user and path carry."""
    with patch('api.alogging.logger') as logger_mock:
        logger_mock.level = 20
        alogging.custom_logging(user=user, remote='1.1.1.1', method='GET', path=path, query={}, body={},
                                elapsed_time=0.001, status=404)

    plain_line, json_record = (c[0][0] for c in logger_mock.info.call_args_list)
    assert plain_line == f'{expected_prefix} with parameters {{}} and body {{}} done in 0.001s: 404'
    assert not alogging.control_chars_pattern.search(plain_line)
    # The JSON record keeps the raw values; its formatter escapes them.
    assert json_record['user'] == user
    assert json_record['uri'] == f'GET {path}'
