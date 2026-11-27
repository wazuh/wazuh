# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from grp import getgrnam
from pwd import getpwnam
from unittest.mock import call, patch, MagicMock

import pytest

from wazuh.core.common import find_conf_path, find_wazuh_path, wazuh_uid, wazuh_gid, context_cached, \
    reset_context_cache, drop_privileges, as_wazuh_user


@pytest.mark.parametrize('fake_path, expected', [
    ('/var/wazuh-manager/framework/python/lib/python3.7/site-packages/wazuh-3.10.0-py3.7.egg/wazuh', '/var/wazuh-manager'),
    ('/my/custom/path/framework/python/lib/python3.7/site-packages/wazuh-3.10.0-py3.7.egg/wazuh', '/my/custom/path'),
    ('/my/fake/path', '')
])
def test_find_wazuh_path(fake_path, expected):
    with patch('wazuh.core.common.__file__', new=fake_path):
        assert (find_wazuh_path.__wrapped__() == expected)


def test_find_wazuh_path_relative_path():
    with patch('os.path.abspath', return_value='~/framework'):
        assert (find_wazuh_path.__wrapped__() == '~')


def test_find_conf_path_installed(tmp_path):
    """An installed manager (no schema source under the home) uses the fixed configuration directory."""
    assert find_conf_path(str(tmp_path)) == '/etc/wazuh-manager'


def test_find_conf_path_repository_checkout(tmp_path):
    """A repository checkout keeps <repo>/etc, so tests never read a configuration installed on the host."""
    schema = tmp_path / 'src' / 'shared_modules' / 'manager_config' / 'schema' / 'wazuh-manager.schema.json'
    schema.parent.mkdir(parents=True)
    schema.write_text('{}')
    assert find_conf_path(str(tmp_path)) == os.path.join(str(tmp_path), 'etc')


def test_configuration_constants_are_under_conf_path():
    """Every configuration file constant is rooted at CONF_PATH."""
    from wazuh.core import common
    for constant in ('MANAGER_CONF', 'MANAGER_CONF_SCHEMA', 'INTERNAL_OPTIONS_CONF', 'CLIENT_KEYS', 'SHARED_PATH',
                     'AUTHD_PASS', 'CERTS_PATH', 'INDEXER_PLUGINS_PATH'):
        assert os.path.dirname(getattr(common, constant)) == common.CONF_PATH, constant
    assert not hasattr(common, 'WAZUH_LOCALTIME_PATH')


def test_wazuh_uid():
    with patch('wazuh.core.common.getpwnam', return_value=getpwnam("root")):
        wazuh_uid()


def test_wazuh_gid():
    with patch('wazuh.core.common.getgrnam', return_value=getgrnam("root")):
        wazuh_gid()


@pytest.mark.parametrize("euid, expected_calls", [
    (0, [call.setgroups([]), call.setgid(998), call.setuid(997)]),
    (1000, []),
])
def test_drop_privileges(euid, expected_calls):
    """Check that root drops its supplementary groups, then its group, then its user, and that
    anyone else keeps its identity."""
    calls = MagicMock()
    with patch('os.geteuid', return_value=euid), \
            patch('os.setgroups', calls.setgroups), \
            patch('os.setgid', calls.setgid), \
            patch('os.setuid', calls.setuid), \
            patch('wazuh.core.common.wazuh_gid', return_value=998), \
            patch('wazuh.core.common.wazuh_uid', return_value=997):
        drop_privileges()

    assert calls.mock_calls == expected_calls


@pytest.mark.parametrize("euid, expected_calls", [
    (0, [call.setgroups([]), call.setegid(998), call.seteuid(997), call.body(),
         call.seteuid(0), call.setegid(4), call.setgroups([0, 4])]),
    (1000, [call.body()]),
])
def test_as_wazuh_user(euid, expected_calls):
    """Check that root runs the block as the wazuh user and group and gets its own ids back, also when the block
    fails, and that anyone else runs it as itself."""
    calls = MagicMock()
    with patch('os.geteuid', return_value=euid), \
            patch('os.getegid', return_value=4), \
            patch('os.getgroups', return_value=[0, 4]), \
            patch('os.setgroups', calls.setgroups), \
            patch('os.setegid', calls.setegid), \
            patch('os.seteuid', calls.seteuid), \
            patch('wazuh.core.common.wazuh_gid', return_value=998), \
            patch('wazuh.core.common.wazuh_uid', return_value=997), \
            pytest.raises(OSError):
        with as_wazuh_user():
            calls.body()
            raise OSError('in the block')

    assert calls.mock_calls == expected_calls


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

    # foo called with an argument
    assert foo('other_arg') == 'other_arg' and test_context_cached.calls_to_foo == 2, '"other_arg" should be ' \
                                                                                      'returned with 2 calls to foo. '

    # foo called with the same argument as default, a new context var is created in the cache
    assert foo('bar') == 'bar' and test_context_cached.calls_to_foo == 3, '"bar" should be returned with 3 calls to ' \
                                                                          'foo. '

    # Reset cache and calls to foo
    reset_context_cache()
    test_context_cached.calls_to_foo = 0

    # foo called with kwargs, a new context var is created with kwargs not empty
    assert foo(data='bar') == 'bar' and test_context_cached.calls_to_foo == 1, '"bar" should be returned with 1 ' \
                                                                               'calls to foo. '


@patch('wazuh.core.stats.wazuh_socket.create_wazuh_socket_message', side_effect=SystemExit)
def test_origin_module_context_var_framework(mock_create_socket_msg):
    """Test that the origin_module context variable is being set to framework."""
    from wazuh.core import stats

    # side_effect used to avoid mocking the rest of functions
    with pytest.raises(SystemExit):
        stats.get_daemons_stats_socket(None)

    assert mock_create_socket_msg.call_args[1]['origin']['module'] == 'framework'


@pytest.mark.asyncio
@patch('wazuh.core.stats.wazuh_socket.create_wazuh_socket_message', side_effect=SystemExit)
@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.check_wazuh_status', side_effect=None)
async def test_origin_module_context_var_api(mock_check_wazuh_status, mock_create_socket_msg):
    """Test that the origin_module context variable is being set to API."""
    import logging
    from wazuh.core.cluster.dapi import dapi
    from wazuh import stats

    # side_effect used to avoid mocking the rest of functions
    with pytest.raises(SystemExit):
        d = dapi.DistributedAPI(f=stats.get_daemons_stats, logger=logging.getLogger('wazuh'), is_async=True)
        await d.distribute_function()

    assert mock_create_socket_msg.call_args[1]['origin']['module'] == 'API'
