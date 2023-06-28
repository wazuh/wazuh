# Copyright (C) 2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""Unit tests for virustotal.py integration."""

import os
import pytest
import sys
import virustotal as virustotal
from unittest.mock import patch

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..')) #Necessary to run PyTest

apikey_virustotal = ""

"""
    Mockup messages for testing
"""

alert_template = [
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

sys_args_template = ['/var/ossec/integrations/virustotal.py', '/tmp/virustotal-XXXXXX-XXXXXXX.alert', f'{apikey_virustotal}', '', '>/dev/null 2>&1']

def test_request_virustotal_info_md5_after_check_fail_1():
    """Test that the md5_after field from alerts are valid md5 hash."""
    with patch('virustotal.debug') as debug:
        response = virustotal.request_virustotal_info(alert_template[0],apikey_virustotal)
        debug.assert_called_once_with("# md5_after field in the alert is not a md5 hash checksum")
        assert response == None

def test_request_virustotal_info_md5_after_check_fail_2():
    """Test that the md5_after field from alerts are valid md5 hash."""
    with patch('virustotal.debug') as debug:
        response = virustotal.request_virustotal_info(alert_template[1],apikey_virustotal)
        debug.assert_called_once_with("# md5_after field in the alert is not a md5 hash checksum")
        assert response == None

def test_request_virustotal_info_md5_after_check_fail_3():
    """Test that the md5_after field from alerts are valid md5 hash."""
    with patch('virustotal.debug') as debug:
        response = virustotal.request_virustotal_info(alert_template[2],apikey_virustotal)
        debug.assert_called_once_with("# md5_after field in the alert is not a md5 hash checksum")
        assert response == None

def test_request_virustotal_info_md5_after_check_fail_4():
    """Test that the md5_after field from alerts are valid md5 hash."""
    with patch('virustotal.debug') as debug:
        response = virustotal.request_virustotal_info(alert_template[3],apikey_virustotal)
        debug.assert_called_once_with("# md5_after field in the alert is not a md5 hash checksum")
        assert response == None

def test_request_virustotal_info_md5_after_check_fail_5():
    """Test that the md5_after field from alerts are valid md5 hash."""
    with patch('virustotal.debug') as debug:
        response = virustotal.request_virustotal_info(alert_template[4],apikey_virustotal)
        debug.assert_called_once_with("# md5_after field in the alert is not a md5 hash checksum")
        assert response == None

def test_request_virustotal_info_md5_after_check_fail_6():
    """Test that the md5_after field from alerts are valid md5 hash."""
    with patch('virustotal.debug') as debug:
        response = virustotal.request_virustotal_info(alert_template[5],apikey_virustotal)
        debug.assert_called_once_with("# md5_after field in the alert is not a md5 hash checksum")
        assert response == None

def test_request_virustotal_info_md5_after_check_fail_7():
    """Test that the md5_after field from alerts are valid md5 hash."""
    with patch('virustotal.debug') as debug:
        response = virustotal.request_virustotal_info(alert_template[6],apikey_virustotal)
        debug.assert_called_once_with("# md5_after field in the alert is not a md5 hash checksum")
        assert response == None

def test_request_virustotal_info_md5_after_check_fail_8():
    """Test that the md5_after field from alerts are valid md5 hash."""
    with patch('virustotal.debug') as debug:
        response = virustotal.request_virustotal_info(alert_template[7],apikey_virustotal)
        debug.assert_called_once_with("# md5_after field in the alert is not a md5 hash checksum")
        assert response == None

def test_request_virustotal_info_md5_after_check_ok():
    """Test that the md5_after field from alerts are valid md5 hash."""
    with patch('virustotal.query_api'), patch('virustotal.in_database', return_value=False), patch('virustotal.debug') as debug:
        response = virustotal.request_virustotal_info(alert_template[8],apikey_virustotal)
        assert response == alert_output
