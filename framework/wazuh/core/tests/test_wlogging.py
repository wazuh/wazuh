# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import calendar
from datetime import date
from unittest.mock import patch, ANY, PropertyMock
import tempfile
import pytest
from os.path import join
import gzip

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from wazuh.core import wlogging


def test_custom_file_rotating_handler_do_rollover():
    """Test if method doRollover of CustomFileRotatingHandler works properly."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        test_str = 'test string'
        log_file = join(tmp_dir, 'test.log')
        with open(log_file, 'w') as f:
            f.write(test_str)

        fh = wlogging.CustomFileRotatingHandler(filename=log_file)
        fh.doRollover()
        today = date.today()
        backup_file = join(tmp_dir, 'test', str(today.year),
                           today.strftime("%b"),
                           f"test.log-{today.day:02d}.gz")

        with gzip.open(backup_file, 'r') as backup:
            assert backup.read().decode() == test_str


@pytest.mark.parametrize('rotated_file', ['test.log.2021-08-03', 'test.log.2019-07-04'])
@patch('wazuh.core.utils.mkdir_with_mode')
def test_custom_file_rotating_handler_compute_archives_directory(mock_mkdir, rotated_file):
    """Test if method computeArchivesDirectory of CustomFileRotatingHandler works properly.

    Parameters
    ----------
    mock_mkdir : mock
        Mock of mkdir method.
    rotated_file : str
        Test log file used to compute the directory.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        log_file = join(tmp_dir, 'test.log')
        with open(log_file, 'w') as _:
            pass

        fh = wlogging.CustomFileRotatingHandler(filename=log_file)
        year, month, day = rotated_file.split('-')
        year = year.split('.')[2]
        month = calendar.month_abbr[int(month)]
        log_path = join(tmp_dir, 'test', year, month)
        expected_name = join(log_path, f"test.log-{int(day):02d}.gz")
        computed_name = fh.computeArchivesDirectory(rotated_file)

        assert expected_name == computed_name
        mock_mkdir.assert_called_with(log_path, 0o750)


@patch('logging.addLevelName')
@patch('logging.Logger.addHandler')
@patch('wazuh.core.wlogging.CustomFileRotatingHandler')
def test_wazuh_logger_setup_logger(mock_fh, mock_add_handler, mock_add_level_name):
    """Test if method setup_logger of WazuhLogger setups the logger attribute properly.

    Parameters
    ----------
    mock_fh: MagicMock
        Mock of CustomFileRotatingHandler to check if it was correctly instantiated.
    mock_add_handler: MagicMock
        Mock of Logger method addHandler to check if the logger has a valid file handler.
    mock_add_level_name: MagicMock
        Mock of logging addLevelName function to check if an additional debug level has been added.
    """
    tmp_dir = tempfile.TemporaryDirectory()
    # To bypass the checking of the existence of a valid Wazuh install
    with patch('os.path.join'):
        w_logger = wlogging.WazuhLogger(foreground_mode=True, log_path=tmp_dir,
                                        tag='%(test)s %(test)s: %(test)s',
                                        debug_level=[0, 'test'])
    w_logger.setup_logger()
    mock_fh.assert_called_with(filename=ANY, when='midnight')
    mock_add_handler.assert_called()
    mock_add_level_name.assert_called()


@patch.object(wlogging.WazuhLogger, 'log_path', create=True, new_callable=PropertyMock)
@patch.object(wlogging.WazuhLogger, 'tag', create=True, new_callable=PropertyMock)
@patch.object(wlogging.WazuhLogger, 'logger', create=True, new_callable=PropertyMock)
@patch.object(wlogging.WazuhLogger, 'foreground_mode', create=True, new_callable=PropertyMock)
@patch.object(wlogging.WazuhLogger, 'debug_level', create=True, new_callable=PropertyMock)
@patch.object(wlogging.WazuhLogger, 'logger_name', create=True, new_callable=PropertyMock)
@patch.object(wlogging.WazuhLogger, 'custom_formatter', create=True, new_callable=PropertyMock)
@patch('logging.Formatter')
def test_wazuh_logger__init__(mock_lformatter, mock_formatter, mock_logger_name, mock_debug_level, mock_foreground_mode,
                              mock_logger, mock_tag, mock_log_path):
    """Test if WazuhLogger __init__ method initialize all attributes properly.

    Parameters
    ----------
    mock_formatter: PropertyMock
        Mock custom_formatter attribute.
    mock_logger_name: PropertyMock
        Mock name for the logger.
    mock_debug_level: PropertyMock
        Mock log level.
    mock_foreground_mode: PropertyMock
        Mock foreground mode.
    mock_logger: PropertyMock
        Mock logger attribute.
    mock_tag: PropertyMock
        Mock tag attribute.
    mock_log_path: Property
        Mock path for the log.
    """
    # To bypass the checking of the existence of a valid Wazuh install
    with patch('os.path.join'):
        wlogging.WazuhLogger(foreground_mode=mock_foreground_mode, log_path=mock_log_path, tag=mock_tag,
                             debug_level=mock_debug_level, logger_name=mock_logger_name,
                             custom_formatter=mock_formatter)
    for x in [mock_formatter, mock_logger_name, mock_debug_level, mock_foreground_mode,
              mock_logger, mock_log_path]:
        x.assert_called()


@pytest.mark.parametrize('attribute, expected_exception, expected_value', [
    ('level', None, 0),
    ('foreground_mode', None, True),
    ('doesnt_exists', AttributeError, None)
])
@patch('wazuh.core.wlogging.CustomFileRotatingHandler')
def test_wazuh_logger_getattr(mock_fh, attribute, expected_exception, expected_value):
    """Test if WazuhLogger __getattr__ method works properly.

    Parameters
    ----------
    expected_value:
        Expected result of the __getattr__(attribute) call.
    mock_fh: MagicMock
        Mock of CustomFileRotatingHandler function.
    attribute: str
        Attribute to search for with __getattr__.
    expected_exception: None or Exception
        Exception expected to be raised.
    """
    tmp_dir = tempfile.TemporaryDirectory
    # To bypass the checking of the existence of a valid Wazuh install
    with patch('os.path.join'):
        w_logger = wlogging.WazuhLogger(foreground_mode=True, log_path=tmp_dir, tag='%(test)s %(test)s: %(test)s',
                                        debug_level=[0, 'test'], logger_name='test')
    w_logger.setup_logger()

    if expected_exception is None:
        assert w_logger.__getattr__(attribute) == expected_value
    else:
        with pytest.raises(expected_exception):
            w_logger.__getattr__('doesnt_exists')


def test_customfilter():
    """
    Test if CustomFilter class works properly.
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
