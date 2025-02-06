# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import PropertyMock, patch

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from wazuh.core import wlogging


@patch('logging.addLevelName')
@patch('logging.Logger.addHandler')
def test_wazuh_logger_setup_logger(mock_add_handler, mock_add_level_name):
    """Test if method setup_logger of WazuhLogger setups the logger attribute properly."""
    w_logger = wlogging.WazuhLogger(tag='%(test)s %(test)s: %(test)s',
                                        debug_level=[0, 'test'])
    w_logger.setup_logger()

    mock_add_handler.assert_called()
    mock_add_level_name.assert_called()


@patch.object(wlogging.WazuhLogger, 'tag', create=True, new_callable=PropertyMock)
@patch.object(wlogging.WazuhLogger, 'logger', create=True, new_callable=PropertyMock)
@patch.object(wlogging.WazuhLogger, 'debug_level', create=True, new_callable=PropertyMock)
@patch.object(wlogging.WazuhLogger, 'logger_name', create=True, new_callable=PropertyMock)
@patch.object(wlogging.WazuhLogger, 'custom_formatter', create=True, new_callable=PropertyMock)
@patch('logging.Formatter')
def test_wazuh_logger__init__(mock_lformatter, mock_formatter, mock_logger_name, mock_debug_level,
                              mock_logger, mock_tag):
    """Test if WazuhLogger __init__ method initialize all attributes properly."""
    wlogging.WazuhLogger(tag=mock_tag, debug_level=mock_debug_level,
                         logger_name=mock_logger_name, custom_formatter=mock_formatter)
    for x in [mock_formatter, mock_logger_name, mock_debug_level, mock_logger]:
        x.assert_called()


@pytest.mark.parametrize('attribute, expected_exception, expected_value', [
    ('level', None, 0),
    ('doesnt_exists', AttributeError, None)
])
def test_wazuh_logger_getattr(attribute, expected_exception, expected_value):
    """Test if WazuhLogger __getattr__ method works properly."""
    # To bypass the checking of the existence of a valid Wazuh install
    w_logger = wlogging.WazuhLogger(tag='%(test)s %(test)s: %(test)s',
                                        debug_level=[0, 'test'], logger_name='test')
    w_logger.setup_logger()

    if expected_exception is None:
        assert w_logger.__getattr__(attribute) == expected_value
    else:
        with pytest.raises(expected_exception):
            w_logger.__getattr__('doesnt_exists')


def test_customfilter():
    """Test if CustomFilter class works properly.
    """
    class MockedRecord():
        def __init__(self, log_type):
            if log_type:
                self.log_type = log_type
    # Return True
    for value in ['test', None]:
        cf = wlogging.CustomFilter(value)
        assert cf.filter(MockedRecord(value))

    # Return False
    cf = wlogging.CustomFilter('testA')
    assert not cf.filter(MockedRecord('testB'))


@pytest.mark.parametrize('value, expected', [
    ('Example log', True),
    ('Wazuh Internal Error', False),
    ('WazuhInternalError', False),
    ('WazuhError', True),
    ('InternalError', True)
])
def test_cli_custom_filter(value, expected):
    """Test if CLIFilter class works properly.
    """
    class MockedRecord:
        def __init__(self, msg):
            self.msg = msg

        def getMessage(self):
            return self.msg

    cf = wlogging.CLIFilter()
    assert cf.filter(MockedRecord(value)) == expected
