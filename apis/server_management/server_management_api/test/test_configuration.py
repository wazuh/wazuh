# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch

from server_management_api import configuration


@patch('os.chmod')
@patch('builtins.open')
def test_generate_private_key(mock_open, mock_chmod):
    """Verify that genetare_private_key returns expected key and 'open' method is called with expected parameters."""
    result_key = configuration.generate_private_key('test_path.crt', 65537, 2048)

    assert result_key.key_size == 2048
    mock_open.assert_called_once_with('test_path.crt', 'wb')
    mock_chmod.assert_called_once()


@patch('os.chmod')
@patch('builtins.open')
def test_generate_self_signed_certificate(mock_open, mock_chmod):
    """Verify that genetare_private_key returns expected key and 'open' method is called with expected parameters."""
    result_key = configuration.generate_private_key('test_path.crt', 65537, 2048)
    configuration.generate_self_signed_certificate(result_key, 'test_path.crt')

    assert mock_open.call_count == 2, 'Not expected number of calls'
    assert mock_chmod.call_count == 2, 'Not expected number of calls'
