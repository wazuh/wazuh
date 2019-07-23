from unittest.mock import patch
import pytest
from os import path, remove
from wazuh.common import find_wazuh_path, ossec_uid, ossec_gid
from grp import getgrnam
from pwd import getpwnam
from sys import modules
import json

@pytest.mark.parametrize('fake_path, expected', [
    ('/var/ossec/framework/python/lib/python3.7/site-packages/wazuh-3.10.0-py3.7.egg/wazuh', '/var/ossec'),
    ('/my/custom/path/framework/python/lib/python3.7/site-packages/wazuh-3.10.0-py3.7.egg/wazuh', '/my/custom/path'),
    ('/my/fake/path', '')
])
def test_find_wazuh_path(fake_path, expected):
    with patch('wazuh.common.__file__', new=fake_path):
        assert(find_wazuh_path() == expected)


def test_find_wazuh_path_relative_path():
    with patch('os.path.abspath', return_value='~/framework'):
        assert(find_wazuh_path() == '~')


def test_ossec_uid():
    with patch('wazuh.common.getpwnam', return_value=getpwnam("root")):
        ossec_uid()


def test_ossec_gid():
    with patch('wazuh.common.getgrnam', return_value=getgrnam("root")):
        ossec_gid()


def test_load_metadata_from_file():
    data = {
        'install_type': '',
        'installation_date': '',
        'wazuh_version': ''
    }
    with open(path.join('/var/ossec', 'wazuh.json'), 'w') as f:
        json.dump(data, f)

    del modules['wazuh.common']
    with patch('os.path.abspath', return_value='/var/ossec'):
        import wazuh.common

    remove(path.join('/var/ossec', 'wazuh.json'))