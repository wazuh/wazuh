# Copyright (C) 2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""Unit tests for virustotal.py integration."""

from dotenv import load_dotenv
import json
import os
import pytest
import requests
from socket import socket, AF_UNIX, SOCK_DGRAM
import sys
import virustotal as virustotal
from unittest.mock import patch, mock_open


sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..')) #Necessary to run PyTest
try:
    load_dotenv()
    apikey_virustotal = os.getenv('APIKEY_VT')
    if not apikey_virustotal:
        raise KeyError
except KeyError:
    print("No environment variable 'APIKEY_VT' found. Define your virustotal apikey before run this test")
    sys.exit(1)
    
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

options_template = {
    'client': 'Wazuh-X -- Alert generated'
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

sys_args_template = ['/var/ossec/integrations/virustotal.py', '/tmp/virustotal-XXXXXX-XXXXXXX.alert', f'{apikey_virustotal}', '', '>/dev/null 2>&1','/tmp/virustotal-XXXXXX-XXXXXXX.options']
               

def test_main_bad_arguments_exit():
    """Test that main function exits when wrong number of arguments are passed."""
    with patch("virustotal.open", mock_open()), pytest.raises(SystemExit) as pytest_wrapped_e:
        virustotal.main(sys_args_template[0:2])
    assert pytest_wrapped_e.value.code == 2
    
def test_main_exception():
    """Test exception handling in main when process_args raises an exception."""
    with patch("virustotal.open", mock_open()), pytest.raises(Exception),patch('virustotal.process_args') as process:
        process.side_effect = Exception
        virustotal.main(sys_args_template)
        
def test_main():
    """Test the correct execution of the main function."""
    with patch("virustotal.open", mock_open()), patch('json.load', return_value=alert_template),\
        patch('json.load', return_value=options_template),\
        patch('requests.post', return_value=requests.Response), patch('virustotal.process_args') as process:
        virustotal.main(sys_args_template)
        process.assert_called_once_with(sys_args_template)
        
@pytest.mark.parametrize('side_effect, return_value', [
    (FileNotFoundError, 3),
    (json.decoder.JSONDecodeError("Expecting value", "", 0), 4)
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
            patch('virustotal.get_json_options') as options_load,\
            patch('virustotal.send_msg') as send_msg, \
            patch('virustotal.generate_msg', return_value=msg_template) as generate_msg, \
            patch('requests.post', return_value=requests.Response):
        alert_load.return_value = alert_template
        options_load.return_value = options_template
        virustotal.process_args(sys_args_template)
        generate_msg.assert_called_once_with(alert_template,options_template,sys_args_template[2])
        generated_msg = virustotal.generate_msg(alert_template,options_template,sys_args_template[2])
        assert generated_msg==msg_template
        send_msg.assert_called_once_with(msg_template,msg_template['agent'])
        
def test_process_args_not_sending_message():
    """Test that the send_msg function is not executed due to empty message after generate_msg."""
    with patch("virustotal.open", mock_open()), \
            patch('virustotal.get_json_alert') as alert_load,\
            patch('virustotal.get_json_options') as options_load,\
            patch('virustotal.send_msg') as send_msg, \
            patch('virustotal.generate_msg', return_value=''), \
            pytest.raises(Exception):
        alert_load.return_value = alert_template
        options_load.return_value = options_template
        virustotal.process_args(sys_args_template)
        send_msg.assert_not_called()
        
def test_debug():
    """Test the correct execution of the debug function, writing the expected log when debug mode enabled."""
    with patch('virustotal.debug_enabled', return_value=True), \
            patch("virustotal.open", mock_open()) as open_mock, \
            patch('virustotal.LOG_FILE', return_value='integrations.log') as log_file:
        virustotal.debug(msg_template)
        open_mock.assert_called_with(log_file, 'a')
        open_mock().write.assert_called_with(f"{virustotal.now}: {msg_template}\n")


def test_send_msg_raise_exception():
    """Test that the send_msg function will raise an exception when passed the wrong webhook url."""
    with patch('requests.post'), \
        pytest.raises(SystemExit):
        virustotal.send_msg(msg_template,msg_template['agent'])


def test_send_msg():
    """Test that the send_msg function works as expected."""
    headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
    with patch('virustotal.SOCKET_ADDR',"./socket.sock"):
        with socket(AF_UNIX, SOCK_DGRAM) as s:
            s.bind("./socket.sock")
            virustotal.send_msg(msg_template, sys_args_template[3])
            data = s.recvfrom(1024)
            assert data[0].decode() != None
            s.close()
        os.remove('./socket.sock')