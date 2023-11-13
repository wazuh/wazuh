# Copyright (C) 2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""Unit tests for virustotal.py integration."""

import json
import os
import pytest
import sys
import requests
from requests.exceptions import Timeout
from socket import socket, AF_UNIX, SOCK_DGRAM
import virustotal as virustotal
import logging
from unittest.mock import patch, mock_open, MagicMock

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..')) #Necessary to run PyTest

apikey_virustotal = ""

"""
    Mockup messages for testing
"""

alert_template = {
    'timestamp': '2023-02-23T00:00:00+00:00',
    'rule': {
        'level': 0,
        'description': 'alert description',
        'id': '',
        'firedtimes': 1
    },
    'id': 'alert_id',
    'full_log': 'full log.',
    'decoder': {
        'name': 'decoder-name'
    },
    'location': 'wazuh-X',
    'agent':{
        'id':'001',
        'name':'The agent',
        'ip': '1.1.1.1'
    }
}

msg_template = {
    "payload": {
    "summary": "alert description",
    "timestamp": "2023-02-23T00:00:00+00:00",
    "source": "v",
    "severity": "info"
  },
  "routing_key": f"{apikey_virustotal}",
  "event_action": "trigger",
  "client": "Wazuh-X -- Alert generated",
  "client_url": "https://monitoring.example.com",
  'agent':{
        'id':'001',
        'name':'The agent',
        'ip': '1.1.1.1'
    }
}

alert_template_md5 = [
    {'syscheck':{
        'md5_after':''
    }},
    {'syscheck':{
        'md5_after':'no_md5_value'
    }},
    {'syscheck':{
        'md5_after':'5D41402abc4b2a76b9719d911017c592'
    }},
    {'syscheck':{
        'md5_after':'5d41402abc4b2a76b9719d911017c592a12d34'
    }},
    {'syscheck':{
        'md5_after':'5g41402abc4b2a76b9719d911017c592'
    }},
    {'syscheck':{
        'md5_after':True
    }},
    {'syscheck':{
        'md5_after':123456789.234234234234
    }},
    {'syscheck':{
        'md5_after':None
    }},
    {'id': 'alert_id',
    'syscheck':{
        'path':'/path/to/file',
        'md5_after':'5d41402abc4b2a76b9719d911017c592',
        "sha1_after": "sha1_value"
    }}
]

alert_output = {
    "virustotal": {
        "found": 0,
        "malicious": 0,
        "source": {
            "alert_id": "alert_id",
            "file": "/path/to/file",
            "md5": "5d41402abc4b2a76b9719d911017c592",
            "sha1": "sha1_value"
        }
    },
    "integration": "virustotal"
}

alerts_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data/alerts.json')
sys_args_template = ['/var/ossec/integrations/virustotal.py', alerts_file, apikey_virustotal, '']


def test_main_bad_arguments_exit():
    """Test that main function exits when wrong number of arguments are passed."""
    with patch("virustotal.open", mock_open()), pytest.raises(SystemExit) as pytest_wrapped_e:
        virustotal.main(sys_args_template[0:2])
    assert pytest_wrapped_e.value.code == virustotal.ERR_INVALID_ARGUMENTS

def test_main_exception():
    """Test exception handling in main when process_args raises an exception."""
    with patch("virustotal.open", mock_open()), pytest.raises(Exception),patch('virustotal.process_args') as process:
        process.side_effect = Exception
        virustotal.main(sys_args_template)

def test_main():
    """Test the correct execution of the main function."""
    with patch("virustotal.open", mock_open()), patch('json.load', return_value=alert_template),\
        patch('requests.post', return_value=requests.Response), patch('virustotal.process_args') as process:
        virustotal.main(sys_args_template)
        process.assert_called_once_with(sys_args_template)

@pytest.mark.parametrize('side_effect, return_value', [
    (FileNotFoundError, virustotal.ERR_FILE_NOT_FOUND),
    (json.decoder.JSONDecodeError("Expecting value", "", 0), virustotal.ERR_INVALID_JSON)
])
def test_process_args_exit(side_effect, return_value):
    """Test the process_args function exit codes.

    Parameters
    ----------
    side_effect : Exception
        Exception to be raised when there is a failure inside the Load alert section try.
    return_value : int
        Value to be returned when sys.exit() is invoked.
    """
    with patch("virustotal.open", mock_open()), \
            patch('json.load') as json_load, \
            pytest.raises(SystemExit) as pytest_wrapped_e:
        json_load.side_effect = side_effect
        virustotal.process_args(sys_args_template)
    assert pytest_wrapped_e.value.code == return_value

def test_process_args():
    """Test the correct execution of the process_args function."""
    with patch("virustotal.open", mock_open()), \
            patch('virustotal.get_json_alert') as alert_load,\
            patch('virustotal.send_msg') as send_msg, \
            patch('virustotal.generate_msg', return_value=msg_template) as generate_msg, \
            patch('requests.post', return_value=requests.Response):
        alert_load.return_value = alert_template
        virustotal.process_args(sys_args_template)
        generate_msg.assert_called_once_with(alert_template, sys_args_template[2])
        generated_msg = virustotal.generate_msg(alert_template, sys_args_template[2])
        assert generated_msg == msg_template
        send_msg.assert_called_once_with(msg_template, msg_template['agent'])

def test_process_args_not_sending_message():
    """Test that the send_msg function is not executed due to empty message after generate_msg."""
    with patch("virustotal.open", mock_open()), \
            patch('virustotal.get_json_alert') as alert_load,\
            patch('virustotal.send_msg') as send_msg, \
            patch('virustotal.generate_msg', return_value=''), \
            pytest.raises(Exception):
        alert_load.return_value = alert_template
        virustotal.process_args(sys_args_template)
        send_msg.assert_not_called()

def test_send_msg_raise_exception():
    """Test that the send_msg function will raise an exception when passed the wrong webhook url."""
    with patch('requests.post'), \
        pytest.raises(SystemExit):
        virustotal.send_msg(msg_template,msg_template['agent'])

def test_send_msg():
    """Test that the send_msg function works as expected."""
    with patch('virustotal.SOCKET_ADDR',"./socket.sock"):
        with socket(AF_UNIX, SOCK_DGRAM) as s:
            s.bind("./socket.sock")
            virustotal.send_msg(msg_template, sys_args_template[3])
            data = s.recvfrom(1024)
            assert data[0].decode() != None
            s.close()
        os.remove('./socket.sock')

def test_generate_msg_md5_after_check_fails():
    """Test that the md5_after field from alerts are valid md5 hash."""
    expected_exception = 'md5_after field in the alert is not a md5 hash checksum'
    for alert in alert_template_md5[:7]:
        with pytest.raises(Exception, match=expected_exception):
            virustotal.generate_msg(alert, apikey_virustotal)

def test_generate_msg_md5_after_check_ok():
    """Test that the md5_after field from alerts are valid md5 hash."""
    with patch('virustotal.query_api'), patch('virustotal.in_database', return_value=False):
        response = virustotal.generate_msg(alert_template_md5[8],apikey_virustotal)
        assert response == alert_output

def test_logger(caplog):
    """Test the correct execution of the logger."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    with patch('requests.post', return_value=mock_response), patch('virustotal.send_msg'), patch('virustotal.generate_msg'):
        with caplog.at_level(logging.DEBUG, logger='virustotal'):
            args = sys_args_template[:]
            args.append('info')
            virustotal.main(args)

    # Assert console log correctness
    assert caplog.records[0].message == 'Running VirusTotal script'
    assert caplog.records[1].message == f'Alerts file location: {sys_args_template[1]}'
    assert caplog.records[2].message == f'Processing alert with ID alert_id'
    assert caplog.records[-1].levelname == 'INFO'
    assert "DEBUG" not in caplog.text
    # Assert the log file is created and is not empty
    assert os.path.exists(virustotal.LOG_FILE)
    assert os.path.getsize(virustotal.LOG_FILE) > 0
