# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
from copy import copy, deepcopy
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
                else f'{user} {remote} "{method} {path}" '
    json_info.update({'hash_auth_context' : hash_auth_context} if hash_auth_context else {})
    with patch('api.alogging.logger') as log_info_mock:
        log_info_mock.info = MagicMock()
        log_info_mock.debug2 = MagicMock()
        log_info_mock.level = loggerlevel
        alogging.custom_logging(user=user, remote=remote, method=method, path=path, query=query,
                        body=copy(body), elapsed_time=elapsed_time, status=status,
                        hash_auth_context=hash_auth_context, headers=headers)
        log_info += f'with parameters {json.dumps(query)} and body'\
                    f' {json.dumps(body)} done in {elapsed_time:.3f}s: {status}'
        log_info_mock.info.assert_has_calls([call(log_info, extra={'log_type': 'log'}),
                                      call(json_info, extra={'log_type': 'json'})])

        log_info_mock.debug2.assert_called_with(f'Receiving headers {headers}')


@pytest.mark.parametrize('name, sensitive', [
    # Exact names.
    ('password', True),
    ('Password', True),
    ('PASSWORD', True),
    ('passwd', True),
    ('pwd', True),
    ('key', True),
    ('token', True),
    ('secret', True),
    ('credentials', True),
    ('authorization', True),
    ('cookie', True),
    # `<prefix>_<name>` tails, in the three spellings a client may send them in.
    ('api_key', True),
    ('API_KEY', True),
    ('x-api-key', True),
    ('apiKey', True),
    ('private_key', True),
    ('client_secret', True),
    ('clientSecret', True),
    ('access_token', True),
    ('accessToken', True),
    ('refresh_token', True),
    ('old_password', True),
    ('proxy-authorization', True),
    ('set-cookie', True),
    # Names that merely contain a sensitive word. Masking these would make the log unreadable
    # without protecting anything, and they are what a plain substring test would get wrong.
    ('keyword', False),
    ('monkey', False),
    ('tokenizer', False),
    ('keys', False),
    ('passwords', False),
    ('secretary', False),
    ('username', False),
    ('id', False),
])
def test_is_sensitive_field(name, sensitive):
    """Check which field names `is_sensitive_field` designates as secret-bearing.

    Parameters
    ----------
    name : str
        Field or header name.
    sensitive : bool
        Whether the name is expected to be matched.
    """
    assert alogging.is_sensitive_field(name) is sensitive


@pytest.mark.parametrize('value, expected', [
    # The reported bug: a password one level down was logged verbatim.
    ({'nested': {'password': 'SuperSecret123'}, 'username': 'x'},
     {'nested': {'password': '****'}, 'username': 'x'}),
    # Any depth, not just one.
    ({'a': {'b': {'c': {'password': 'S'}}}},
     {'a': {'b': {'c': {'password': '****'}}}}),
    # Inside a list of objects, and inside a list nested in an object.
    ({'users': [{'password': 'S'}, {'password': 'T'}]},
     {'users': [{'password': '****'}, {'password': '****'}]}),
    ([{'token': 'S'}, {'safe': 1}],
     [{'token': '****'}, {'safe': 1}]),
    ({'a': [[{'secret': 'S'}]]},
     {'a': [[{'secret': '****'}]]}),
    # A sensitive key masks its whole value, not just a scalar one.
    ({'credentials': {'user': 'u', 'password': 'p'}},
     {'credentials': '****'}),
    ({'key': ['a', 'b']},
     {'key': '****'}),
    # `key` is masked with no path in play at all: the old `/agents` condition is gone.
    ({'id': '001', 'key': 'MDAxIGFnZW50...'},
     {'id': '001', 'key': '****'}),
    # Top level, the case that already worked.
    ({'username': 'x', 'password': 'S'},
     {'username': 'x', 'password': '****'}),
    # Nothing to mask.
    ({'username': 'x', 'keyword': 'k'},
     {'username': 'x', 'keyword': 'k'}),
    ({}, {}),
    ([], []),
    # A JSON body is not necessarily an object. None of these may raise.
    (None, None),
    ('password', 'password'),
    (0, 0),
    (False, False),
    (1.5, 1.5),
])
def test_redact_sensitive_fields(value, expected):
    """Check that `redact_sensitive_fields` masks every sensitive field at any depth.

    Parameters
    ----------
    value : any
        Parsed JSON value to redact.
    expected : any
        Expected result.
    """
    assert alogging.redact_sensitive_fields(value) == expected


def test_redact_sensitive_fields_does_not_mutate_input():
    """Check that the value handed to `redact_sensitive_fields` is left untouched.

    The body the access log redacts is the request's own cached `_json`, and `access_log` hashes
    the run_as authorization context after this call and expects it as it was received.
    """
    body = {'nested': {'password': 'SuperSecret123'}, 'users': [{'key': 'k'}]}
    original = deepcopy(body)

    redacted = alogging.redact_sensitive_fields(body)

    assert body == original
    assert redacted is not body
    assert redacted['nested'] is not body['nested']
    assert redacted['nested']['password'] == '****'


def test_redact_sensitive_fields_deeply_nested_body():
    """Check that a deeply nested body does not exhaust the stack.

    `tests/integration/test_api/test_miscs/test_recursion.py` asserts that a body 500 levels deep
    is answered with a 200, so `access_log` must be able to redact one at the default recursion
    limit. A recursive walker fails this at a fraction of the depth.
    """
    depth = 500
    body = {'password': 'SuperSecret123'}
    for _ in range(depth - 1):
        body = {'nested': body}

    redacted = alogging.redact_sensitive_fields(body)

    innermost = redacted
    for _ in range(depth - 1):
        innermost = innermost['nested']
    assert innermost == {'password': '****'}


def test_custom_logging_redacts_sensitive_fields():
    """Check that `custom_logging` masks the body, the query and the headers before writing them."""
    user, remote, method, path = ('wazuh', '1.1.1.1', 'POST', '/security/users')
    body = {'username': 'x', 'nested': {'password': 'SuperSecret123'}, 'key': 'agent_key'}
    query = {'pretty': True, 'password': 'q_secret'}
    elapsed_time, status = 1.01, 400
    expected_body = {'username': 'x', 'nested': {'password': '****'}, 'key': '****'}
    expected_query = {'pretty': True, 'password': '****'}

    with patch('api.alogging.logger') as log_mock:
        log_mock.info = MagicMock()
        log_mock.debug2 = MagicMock()
        alogging.custom_logging(user=user, remote=remote, method=method, path=path, query=query,
                                body=body, elapsed_time=elapsed_time, status=status,
                                headers=REQUEST_HEADERS_TEST)

    plain_call, json_call = log_mock.info.call_args_list
    assert 'SuperSecret123' not in plain_call.args[0]
    assert 'agent_key' not in plain_call.args[0]
    assert 'q_secret' not in plain_call.args[0]
    assert json.dumps(expected_body) in plain_call.args[0]
    assert json.dumps(expected_query) in plain_call.args[0]
    assert json_call.args[0]['body'] == expected_body
    assert json_call.args[0]['parameters'] == expected_query

    # The caller's objects are not rewritten on its behalf.
    assert body['nested']['password'] == 'SuperSecret123'
    assert query['password'] == 'q_secret'


def test_custom_logging_redacts_authorization_header():
    """Check that the `debug2` header line does not write the basic-auth credential out.

    `REQUEST_HEADERS_TEST` is `Basic d2F6dWg6cGFzc3dvcmQxMjM=`, which decodes to `wazuh:password123`.
    """
    with patch('api.alogging.logger') as log_mock:
        log_mock.info = MagicMock()
        log_mock.debug2 = MagicMock()
        alogging.custom_logging(user='wazuh', remote='1.1.1.1', method='GET', path='/agents',
                                query={}, body={}, elapsed_time=1.01, status=200,
                                headers=REQUEST_HEADERS_TEST)

    header_line = log_mock.debug2.call_args.args[0]
    assert 'd2F6dWg6cGFzc3dvcmQxMjM=' not in header_line
    assert header_line == f"Receiving headers {{'authorization': '****'}}"
