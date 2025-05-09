# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import uuid
from contextvars import ContextVar
from grp import getgrnam
from pwd import getpwnam
from unittest.mock import patch, mock_open

import pytest

from wazuh.core.common import find_wazuh_path, wazuh_uid, wazuh_gid, context_cached, reset_context_cache, \
    get_context_cache, get_installation_uid


@pytest.mark.parametrize('fake_path, expected', [
    ('/var/ossec/framework/python/lib/python3.7/site-packages/wazuh-3.10.0-py3.7.egg/wazuh', '/var/ossec'),
    ('/my/custom/path/framework/python/lib/python3.7/site-packages/wazuh-3.10.0-py3.7.egg/wazuh', '/my/custom/path'),
    ('/my/fake/path', '')
])
def test_find_wazuh_path(fake_path, expected):
    with patch('wazuh.core.common.__file__', new=fake_path):
        assert (find_wazuh_path.__wrapped__() == expected)


def test_find_wazuh_path_relative_path():
    with patch('os.path.abspath', return_value='~/framework'):
        assert (find_wazuh_path.__wrapped__() == '~')


def test_wazuh_uid():
    with patch('wazuh.core.common.getpwnam', return_value=getpwnam("root")):
        wazuh_uid()


def test_wazuh_gid():
    with patch('wazuh.core.common.getgrnam', return_value=getgrnam("root")):
        wazuh_gid()


def test_context_cached():
    """Verify that context_cached decorator correctly saves and returns saved value when called again."""

    test_context_cached.calls_to_foo = 0

    @context_cached('foobar')
    def foo(arg='bar', **data):
        test_context_cached.calls_to_foo += 1
        return arg

    # The result of function 'foo' is being cached and it has been called once
    assert foo() == 'bar' and test_context_cached.calls_to_foo == 1, '"bar" should be returned with 1 call to foo.'
    assert foo() == 'bar' and test_context_cached.calls_to_foo == 1, '"bar" should be returned with 1 call to foo.'
    assert isinstance(get_context_cache()[json.dumps({"key": "foobar", "args": [], "kwargs": {}})], ContextVar)

    # foo called with an argument
    assert foo('other_arg') == 'other_arg' and test_context_cached.calls_to_foo == 2, '"other_arg" should be ' \
                                                                                      'returned with 2 calls to foo. '
    assert isinstance(get_context_cache()[json.dumps({"key": "foobar", "args": ['other_arg'], "kwargs": {}})],
                      ContextVar)

    # foo called with the same argument as default, a new context var is created in the cache
    assert foo('bar') == 'bar' and test_context_cached.calls_to_foo == 3, '"bar" should be returned with 3 calls to ' \
                                                                          'foo. '
    assert isinstance(get_context_cache()[json.dumps({"key": "foobar", "args": ['bar'], "kwargs": {}})], ContextVar)

    # Reset cache and calls to foo
    reset_context_cache()
    test_context_cached.calls_to_foo = 0

    # foo called with kwargs, a new context var is created with kwargs not empty
    assert foo(data='bar') == 'bar' and test_context_cached.calls_to_foo == 1, '"bar" should be returned with 1 ' \
                                                                               'calls to foo. '
    assert isinstance(get_context_cache()[json.dumps({"key": "foobar", "args": [], "kwargs": {"data": "bar"}})],
                      ContextVar)


@patch('wazuh.core.logtest.create_wazuh_socket_message', side_effect=SystemExit)
def test_origin_module_context_var_framework(mock_create_socket_msg):
    """Test that the origin_module context variable is being set to framework."""
    from wazuh import logtest

    # side_effect used to avoid mocking the rest of functions
    with pytest.raises(SystemExit):
        logtest.run_logtest()

    assert mock_create_socket_msg.call_args[1]['origin']['module'] == 'framework'


@pytest.mark.asyncio
@patch('wazuh.core.logtest.create_wazuh_socket_message', side_effect=SystemExit)
@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.check_wazuh_status', side_effect=None)
async def test_origin_module_context_var_api(mock_check_wazuh_status, mock_create_socket_msg):
    """Test that the origin_module context variable is being set to API."""
    import logging
    from wazuh.core.cluster.dapi import dapi
    from wazuh import logtest

    # side_effect used to avoid mocking the rest of functions
    with pytest.raises(SystemExit):
        d = dapi.DistributedAPI(f=logtest.run_logtest, logger=logging.getLogger('wazuh'), is_async=True)
        await d.distribute_function()

    assert mock_create_socket_msg.call_args[1]['origin']['module'] == 'API'


@patch('wazuh.core.common.os.chmod')
@patch('wazuh.core.common.os.chown')
def test_get_installation_uid_creates_file(chown_mock, chmod_mock, tmp_path):
    """Test get_installation_uid creates the UID file if it doesn't exist."""

    test_path = tmp_path / 'installation_uid'
    with patch('wazuh.core.common.INSTALLATION_UID_PATH', str(test_path)):
        uid = get_installation_uid()

        uuid.UUID(uid)  # should not raise
        with open(test_path, 'r') as f:
            assert f.read().strip() == uid

        chown_mock.assert_called_once()
        chmod_mock.assert_called_once()


@patch('wazuh.core.common.os.path.exists', return_value=True)
@patch('builtins.open', new_callable=mock_open, read_data='test-uuid')
def test_get_installation_uid_reads_existing(mock_file, mock_exists):
    """Test get_installation_uid reads the UID if the file exists."""
    result = get_installation_uid()
    assert result == 'test-uuid'
