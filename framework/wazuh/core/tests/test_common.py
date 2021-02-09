import json
from contextvars import ContextVar
from grp import getgrnam
from pwd import getpwnam
from unittest.mock import patch

import pytest

from wazuh.core.common import find_wazuh_path, ossec_uid, ossec_gid, context_cached, reset_context_cache, \
    get_context_cache


@pytest.mark.parametrize('fake_path, expected', [
    ('/var/ossec/framework/python/lib/python3.7/site-packages/wazuh-3.10.0-py3.7.egg/wazuh', '/var/ossec'),
    ('/my/custom/path/framework/python/lib/python3.7/site-packages/wazuh-3.10.0-py3.7.egg/wazuh', '/my/custom/path'),
    ('/my/fake/path', '')
])
def test_find_wazuh_path(fake_path, expected):
    with patch('wazuh.core.common.__file__', new=fake_path):
        assert (find_wazuh_path() == expected)


def test_find_wazuh_path_relative_path():
    with patch('os.path.abspath', return_value='~/framework'):
        assert (find_wazuh_path() == '~')


def test_ossec_uid():
    with patch('wazuh.core.common.getpwnam', return_value=getpwnam("root")):
        ossec_uid()


def test_ossec_gid():
    with patch('wazuh.core.common.getgrnam', return_value=getgrnam("root")):
        ossec_gid()


def test_context_cached():
    """Verify that context_cached decorator correctly saves and returns saved value when called again."""

    test_context_cached.calls_to_foo = 0

    @context_cached('foobar')
    def foo(arg='bar', **data):
        test_context_cached.calls_to_foo += 1
        print(data)
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
