import os
import pytest
import subprocess
import sys
from unittest.mock import Mock, patch

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))
from utils import find_wazuh_path, call_wazuh_control, get_wazuh_info, get_wazuh_version


@pytest.mark.parametrize('path, expected', [
    ('/var/ossec/wodles/aws', '/var/ossec'),
    ('/my/custom/path/wodles/aws', '/my/custom/path'),
    ('/my/fake/path', '')
])
def test_find_wazuh_path(path, expected):
    """Validate that the Wazuh absolute path is returned successfully."""
    with patch('utils.__file__', new=path):
        assert (find_wazuh_path.__wrapped__() == expected)


def test_find_wazuh_path_relative_path():
    """Validate that the Wazuh relative path is returned successfully."""
    with patch('os.path.abspath', return_value='~/wodles'):
        assert (find_wazuh_path.__wrapped__() == '~')


@patch("subprocess.Popen")
@pytest.mark.parametrize('option', ['info', 'status'])
def test_call_wazuh_control(mock_popen, option):
    """Validate that the call_wazuh_control function works correctly."""
    b_output = b'output'
    process_mock = Mock()
    attrs = {'communicate.return_value': (b_output, b'error')}
    process_mock.configure_mock(**attrs)
    mock_popen.return_value = process_mock

    output = call_wazuh_control(option)
    assert output == b_output.decode()
    mock_popen.assert_called_once_with([os.path.join(find_wazuh_path(), "bin", "wazuh-control"), option], 
                                               stdout=subprocess.PIPE)


def test_call_wazuh_control_ko():
    """Validate that call_wazuh_control exists with a code 1 when there's a system error."""
    with pytest.raises(SystemExit) as sys_exit:
        with patch('subprocess.Popen', side_effect=OSError):
            call_wazuh_control('info')

    assert sys_exit.type == SystemExit
    assert sys_exit.value.code == 1


@pytest.mark.parametrize('field, wazuh_info, expected', [
    ('WAZUH_VERSION', 'WAZUH_VERSION="v5.0.0"\nWAZUH_REVISION="50000"\nWAZUH_TYPE="server"\n', 'v5.0.0'),
    ('WAZUH_REVISION', 'WAZUH_VERSION="v5.0.0"\nWAZUH_REVISION="50000"\nWAZUH_TYPE="server"\n', '50000'),
    ('WAZUH_TYPE', 'WAZUH_VERSION="v5.0.0"\nWAZUH_REVISION="50000"\nWAZUH_TYPE="server"\n', 'server'),
    (None, 'WAZUH_REVISION="50000"', 'WAZUH_REVISION="50000"'),
    ('WAZUH_TYPE', None, 'ERROR')
])
def test_get_wazuh_info(field, wazuh_info, expected):
    """Validate that get_wazuh_info returns the correct information."""
    with patch('utils.call_wazuh_control', return_value=wazuh_info):
        actual = get_wazuh_info(field)
        assert actual == expected


def test_get_wazuh_version():
    """Validate that get_wazuh_version returns the correct information."""
    wazuh_info = 'WAZUH_VERSION="v5.0.0"\nWAZUH_REVISION="50000"\nWAZUH_TYPE="server"\n'
    expected = 'v5.0.0'
    with patch('utils.call_wazuh_control', return_value=wazuh_info):
        version = get_wazuh_version()

    assert version == expected
