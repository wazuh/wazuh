# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
from contextvars import ContextVar
from grp import getgrnam
from pwd import getpwnam
from unittest.mock import patch

import pytest

from wazuh.core.common import find_wazuh_path, wazuh_uid, wazuh_gid, async_context_cached, context_cached, \
    reset_context_cache, get_context_cache


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


async def test_async_context_cached():
    """Verify that async_context_cached decorator correctly saves and returns saved value when called again."""

    test_async_context_cached.calls_to_foo = 0

    @async_context_cached('foobar')
    async def foo(arg='bar', **data):
        test_async_context_cached.calls_to_foo += 1
        return arg

    # The result of function 'foo' is being cached and it has been called once
    assert await foo() == 'bar' and test_async_context_cached.calls_to_foo == 1
    assert await foo() == 'bar' and test_async_context_cached.calls_to_foo == 1
    assert isinstance(get_context_cache()[json.dumps({"key": "foobar", "args": [], "kwargs": {}})], ContextVar)

    # foo called with an argument
    assert await foo('other_arg') == 'other_arg' and test_async_context_cached.calls_to_foo == 2
    assert isinstance(get_context_cache()[json.dumps({"key": "foobar", "args": ['other_arg'], "kwargs": {}})],
                      ContextVar)

    # foo called with the same argument as default, a new context var is created in the cache
    assert await foo('bar') == 'bar' and test_async_context_cached.calls_to_foo == 3
    assert isinstance(get_context_cache()[json.dumps({"key": "foobar", "args": ['bar'], "kwargs": {}})], ContextVar)

    # Reset cache and calls to foo
    reset_context_cache()
    test_async_context_cached.calls_to_foo = 0

    # foo called with kwargs, a new context var is created with kwargs not empty
    assert await foo(data='bar') == 'bar' and test_async_context_cached.calls_to_foo == 1
    assert isinstance(get_context_cache()[json.dumps({"key": "foobar", "args": [], "kwargs": {"data": "bar"}})],
                      ContextVar)


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
