# Copyright (C) 2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""Unit tests for virustotal.py integration."""

import json
import os
import sys
from socket import AF_UNIX, SOCK_DGRAM, socket
from unittest.mock import call, mock_open, patch

import pytest
import requests
import virustotal as virustotal
from requests.exceptions import Timeout

# Exit error codes
ERR_NO_APIKEY = 1
ERR_BAD_ARGUMENTS = 2
ERR_BAD_MD5_SUM = 3
ERR_NO_RESPONSE_VT = 4
ERR_SOCKET_OPERATION = 5
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..'))  # Necessary to run PyTest

apikey_virustotal = ''

"""
    Mockup messages for testing
"""

alert_template = {
    'timestamp': '2023-02-23T00:00:00+00:00',
    'rule': {'level': 0, 'description': 'alert description', 'id': '', 'firedtimes': 1},
    'id': 'alert_id',
    'full_log': 'full log.',
    'decoder': {'name': 'decoder-name'},
    'location': 'wazuh-X',
    'agent': {'id': '001', 'name': 'The agent', 'ip': '1.1.1.1'},
}

msg_template = {
    'payload': {
        'summary': 'alert description',
        'timestamp': '2023-02-23T00:00:00+00:00',
        'source': 'v',
        'severity': 'info',
    },
    'routing_key': f'{apikey_virustotal}',
    'event_action': 'trigger',
    'client': 'Wazuh-X -- Alert generated',
    'client_url': 'https://monitoring.example.com',
    'agent': {'id': '001', 'name': 'The agent', 'ip': '1.1.1.1'},
}

alert_template_md5 = [
    {'syscheck': {'md5_after': ''}},
    {'syscheck': {'md5_after': 'no_md5_value'}},
    {'syscheck': {'md5_after': '5D41402abc4b2a76b9719d911017c592'}},
    {'syscheck': {'md5_after': '5d41402abc4b2a76b9719d911017c592a12d34'}},
    {'syscheck': {'md5_after': '5g41402abc4b2a76b9719d911017c592'}},
    {'syscheck': {'md5_after': True}},
    {'syscheck': {'md5_after': 123456789.234234234234}},
    {'syscheck': {'md5_after': None}},
    {
        'id': 'alert_id',
        'syscheck': {
            'path': '/path/to/file',
            'md5_after': '5d41402abc4b2a76b9719d911017c592',
            'sha1_after': 'sha1_value',
        },
    },
]

alert_output = {
    'virustotal': {
        'found': 0,
        'malicious': 0,
        'source': {
            'alert_id': 'alert_id',
            'file': '/path/to/file',
            'md5': '5d41402abc4b2a76b9719d911017c592',
            'sha1': 'sha1_value',
        },
    },
    'integration': 'virustotal',
}

sys_args_template = [
    '/var/ossec/integrations/virustotal.py',
    '/tmp/virustotal-XXXXXX-XXXXXXX.alert',
    f'{apikey_virustotal}',
    '',
    '>/dev/null 2>&1',
]

vt_response_data = {
    'attributes': {
        'last_analysis_stats': {'malicious': 2},
        'sha1': 'valid_sha1_value',
        'last_analysis_date': 'valid_date_value',
    }
}


def test_main_bad_arguments_exit():
    """Test that main function exits when wrong number of arguments are passed."""
    with patch('virustotal.open', mock_open()), pytest.raises(SystemExit) as pytest_wrapped_e:
        virustotal.main(sys_args_template[0:2])
    assert pytest_wrapped_e.value.code == ERR_BAD_ARGUMENTS


def test_main_exception():
    """Test exception handling in main when process_args raises an exception."""
    with patch('virustotal.open', mock_open()), pytest.raises(Exception), patch('virustotal.process_args') as process:
        process.side_effect = Exception
        virustotal.main(sys_args_template)


def test_main():
    """Test the correct execution of the main function."""
    with (
        patch('virustotal.open', mock_open()),
        patch('json.load', return_value=alert_template),
        patch('requests.post', return_value=requests.Response),
        patch('virustotal.process_args') as process,
    ):
        virustotal.main(sys_args_template)
        process.assert_called_once_with(sys_args_template)


@pytest.mark.parametrize(
    'side_effect, return_value',
    [
        (FileNotFoundError, ERR_FILE_NOT_FOUND),
        (json.decoder.JSONDecodeError('Expecting value', '', 0), ERR_INVALID_JSON),
    ],
)
def test_process_args_exit(side_effect, return_value):
    """Test the process_args function exit codes.

    Parameters
    ----------
    side_effect : Exception
        Exception to be raised when there is a failure inside the Load alert section try.
    return_value : int
        Value to be returned when sys.exit() is invoked.
    """
    with (
        patch('virustotal.open', mock_open()),
        patch('json.load') as json_load,
        pytest.raises(SystemExit) as pytest_wrapped_e,
    ):
        json_load.side_effect = side_effect
        virustotal.process_args(sys_args_template)
    assert pytest_wrapped_e.value.code == return_value


def test_process_args():
    """Test the correct execution of the process_args function."""
    with (
        patch('virustotal.open', mock_open()),
        patch('virustotal.get_json_alert') as alert_load,
        patch('virustotal.send_msg') as send_msg,
        patch('virustotal.request_virustotal_info', return_value=msg_template) as request_virustotal_info,
        patch('requests.post', return_value=requests.Response),
    ):
        alert_load.return_value = alert_template
        virustotal.process_args(sys_args_template)
        request_virustotal_info.assert_called_once_with(alert_template, sys_args_template[2])
        generated_msg = virustotal.request_virustotal_info(alert_template, sys_args_template[2])
        assert generated_msg == msg_template
        send_msg.assert_called_once_with(msg_template, msg_template['agent'])


def test_process_args_not_sending_message():
    """Test that the send_msg function is not executed due to empty message after request_virustotal_info."""
    with (
        patch('virustotal.open', mock_open()),
        patch('virustotal.get_json_alert') as alert_load,
        patch('virustotal.send_msg') as send_msg,
        patch('virustotal.request_virustotal_info', return_value=''),
        pytest.raises(Exception),
    ):
        alert_load.return_value = alert_template
        virustotal.process_args(sys_args_template)
        send_msg.assert_not_called()


def test_debug():
    """Test the correct execution of the debug function, writing the expected log when debug mode enabled."""
    with (
        patch('virustotal.debug_enabled', return_value=True),
        patch('virustotal.open', mock_open()) as open_mock,
        patch('virustotal.LOG_FILE', return_value='integrations.log') as log_file,
    ):
        virustotal.debug(str(msg_template))
        open_mock.assert_called_with(log_file, 'a')
        open_mock().write.assert_called_with(str(msg_template) + '\n')


def test_send_msg_raise_exception():
    """Test that the send_msg function will raise an exception when passed the wrong webhook url."""
    with patch('requests.post'), pytest.raises(SystemExit):
        virustotal.send_msg(msg_template, msg_template['agent'])


def test_send_msg():
    """Test that the send_msg function works as expected."""
    with patch('virustotal.SOCKET_ADDR', './socket.sock'):
        with socket(AF_UNIX, SOCK_DGRAM) as s:
            s.bind('./socket.sock')
            virustotal.send_msg(msg_template, sys_args_template[3])
            data = s.recvfrom(1024)
            assert data[0].decode() is not None
            s.close()
        os.remove('./socket.sock')


def test_request_virustotal_info_md5_after_check_fail_1():
    """Test that the md5_after field from alerts are valid md5 hash."""
    with patch('virustotal.debug') as debug:
        response = virustotal.request_virustotal_info(alert_template_md5[0], apikey_virustotal)
        debug.assert_called_once_with('# md5_after field in the alert is not a md5 hash checksum')
        assert response is None


def test_request_virustotal_info_md5_after_check_fail_2():
    """Test that the md5_after field from alerts are valid md5 hash."""
    with patch('virustotal.debug') as debug:
        response = virustotal.request_virustotal_info(alert_template_md5[1], apikey_virustotal)
        debug.assert_called_once_with('# md5_after field in the alert is not a md5 hash checksum')
        assert response is None


def test_request_virustotal_info_md5_after_check_fail_3():
    """Test that the md5_after field from alerts are valid md5 hash."""
    with patch('virustotal.debug') as debug:
        response = virustotal.request_virustotal_info(alert_template_md5[2], apikey_virustotal)
        debug.assert_called_once_with('# md5_after field in the alert is not a md5 hash checksum')
        assert response is None


def test_request_virustotal_info_md5_after_check_fail_4():
    """Test that the md5_after field from alerts are valid md5 hash."""
    with patch('virustotal.debug') as debug:
        response = virustotal.request_virustotal_info(alert_template_md5[3], apikey_virustotal)
        debug.assert_called_once_with('# md5_after field in the alert is not a md5 hash checksum')
        assert response is None


def test_request_virustotal_info_md5_after_check_fail_5():
    """Test that the md5_after field from alerts are valid md5 hash."""
    with patch('virustotal.debug') as debug:
        response = virustotal.request_virustotal_info(alert_template_md5[4], apikey_virustotal)
        debug.assert_called_once_with('# md5_after field in the alert is not a md5 hash checksum')
        assert response is None


def test_request_virustotal_info_md5_after_check_fail_6():
    """Test that the md5_after field from alerts are valid md5 hash."""
    with patch('virustotal.debug') as debug:
        response = virustotal.request_virustotal_info(alert_template_md5[5], apikey_virustotal)
        debug.assert_called_once_with('# md5_after field in the alert is not a md5 hash checksum')
        assert response is None


def test_request_virustotal_info_md5_after_check_fail_7():
    """Test that the md5_after field from alerts are valid md5 hash."""
    with patch('virustotal.debug') as debug:
        response = virustotal.request_virustotal_info(alert_template_md5[6], apikey_virustotal)
        debug.assert_called_once_with('# md5_after field in the alert is not a md5 hash checksum')
        assert response is None


def test_request_virustotal_info_md5_after_check_fail_8():
    """Test that the md5_after field from alerts are valid md5 hash."""
    with patch('virustotal.debug') as debug:
        response = virustotal.request_virustotal_info(alert_template_md5[7], apikey_virustotal)
        debug.assert_called_once_with('# md5_after field in the alert is not a md5 hash checksum')
        assert response is None


def test_request_virustotal_info_md5_after_check_ok():
    """Test that the md5_after field from alerts are valid md5 hash."""
    with patch('virustotal.query_api', return_value=vt_response_data), patch('virustotal.debug'):
        response = virustotal.request_virustotal_info(alert_template_md5[8], apikey_virustotal)

        assert response['virustotal']['found'] == 1
        assert response['virustotal']['malicious'] == 1
        assert (
            response['virustotal']['permalink']
            == 'https://www.virustotal.com/gui/file/5d41402abc4b2a76b9719d911017c592/detection'
        )
        assert response['virustotal']['positives'] == 2


def test_request_info_from_api_exception():
    """Test that the query_api function fails with no retries when an Exception happens."""
    with (
        patch('virustotal.query_api', side_effect=[Exception(), None]),
        patch('virustotal.debug'),
        pytest.raises(SystemExit) as pytest_wrapped_e,
    ):
        virustotal.request_info_from_api(alert_template_md5[8], {'virustotal': {}}, apikey_virustotal)
    assert pytest_wrapped_e.value.code == ERR_NO_RESPONSE_VT


def test_request_info_from_api_timeout_and_retries_expired():
    """Test that the query_api function fails with retries when an Timeout exception happens (retries expired)."""
    virustotal.retries = 2
    with (
        patch('virustotal.query_api', side_effect=[Timeout(), Timeout(), Timeout(), None]),
        patch('virustotal.send_msg'),
        patch('virustotal.debug'),
        pytest.raises(SystemExit) as pytest_wrapped_e,
    ):
        virustotal.request_info_from_api(alert_template_md5[8], {'virustotal': {}}, apikey_virustotal)
    assert pytest_wrapped_e.value.code == ERR_NO_RESPONSE_VT


def test_request_info_from_api_timeout_and_retries_not_expired():
    """Test that the query_api function fails with retries when an Timeout exception happens (retries not expired)."""
    virustotal.retries = 2
    with (
        patch('virustotal.query_api', side_effect=[Timeout(), Timeout(), alert_output]),
        patch('virustotal.debug') as debug,
    ):
        response = virustotal.request_info_from_api(alert_template_md5[8], {'virustotal': {}}, apikey_virustotal)
        debug.assert_has_calls(
            [
                call('# Error: Request timed out. Remaining retries: 2'),
                call('# Error: Request timed out. Remaining retries: 1'),
            ]
        )
    assert response == alert_output
