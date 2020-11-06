from unittest.mock import patch
import pytest
from wazuh.core.common import find_wazuh_path, ossec_uid, ossec_gid, context_cached, reset_context_cache
from grp import getgrnam
from pwd import getpwnam


@pytest.mark.parametrize('fake_path, expected', [
    ('/var/ossec/framework/python/lib/python3.7/site-packages/wazuh-3.10.0-py3.7.egg/wazuh', '/var/ossec'),
    ('/my/custom/path/framework/python/lib/python3.7/site-packages/wazuh-3.10.0-py3.7.egg/wazuh', '/my/custom/path'),
    ('/my/fake/path', '')
])
def test_find_wazuh_path(fake_path, expected):
    with patch('wazuh.core.common.__file__', new=fake_path):
        assert(find_wazuh_path() == expected)


def test_find_wazuh_path_relative_path():
    with patch('os.path.abspath', return_value='~/framework'):
        assert(find_wazuh_path() == '~')


def test_ossec_uid():
    with patch('wazuh.core.common.getpwnam', return_value=getpwnam("root")):
        ossec_uid()


def test_ossec_gid():
    with patch('wazuh.core.common.getgrnam', return_value=getgrnam("root")):
        ossec_gid()


def test_context_cached():
    """Verify that context_cached decorator correctly saves and returns saved value when called again"""
    @context_cached('foobar')
    def foo(arg='bar'):
        return arg

    assert foo() == 'bar', '"bar" should be returned.'
    assert foo('other_arg') != 'other_arg', '"bar" should be returned.'
    reset_context_cache()
    assert foo('other_arg_2') == 'other_arg_2', '"other_arg_2" should be returned.'
    assert foo() == 'other_arg_2', '"other_arg_2" should be returned.'
