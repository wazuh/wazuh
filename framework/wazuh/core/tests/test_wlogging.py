# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import calendar
import gzip
import re
import tempfile
from datetime import date
from os.path import join, exists
from random import randint
from unittest.mock import patch, PropertyMock

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from wazuh.core import wlogging


def test_timebasedfilerotatinghandler_dorollover():
    """Test if method doRollover of TimeBasedFileRotatingHandler works properly."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        test_str = 'test string'
        log_file = join(tmp_dir, 'test.log')
        with open(log_file, 'w') as f:
            f.write(test_str)

        fh = wlogging.TimeBasedFileRotatingHandler(filename=log_file)
        fh.doRollover()
        today = date.today()
        backup_file = join(tmp_dir, 'test', str(today.year),
                           today.strftime("%b"),
                           f"test.log-{today.day:02d}.gz")

        with gzip.open(backup_file, 'r') as backup:
            assert backup.read().decode() == test_str


@pytest.mark.parametrize('rotated_file', ['test.log.2021-08-03', 'test.log.2019-07-04'])
@patch('wazuh.core.utils.mkdir_with_mode')
def test_timebasedfilerotatinghandler_compute_log_directory(mock_mkdir, rotated_file):
    """Test if method compute_log_directory of TimeBasedFileRotatingHandler works properly.

    Parameters
    ----------
    rotated_file : str
        Test log file used to compute the directory.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        log_file = join(tmp_dir, 'test.log')
        with open(log_file, 'w') as _:
            pass

        fh = wlogging.TimeBasedFileRotatingHandler(filename=log_file)
        year, month, day = rotated_file.split('-')
        year = year.split('.')[2]
        month = calendar.month_abbr[int(month)]
        log_path = join(tmp_dir, 'test', year, month)
        expected_name = join(log_path, f"test.log-{int(day):02d}.gz")
        computed_name = fh.compute_log_directory(rotated_file)

        assert expected_name == computed_name
        mock_mkdir.assert_called_with(log_path, 0o750)


def test_sizebasedfilerotatinghandler_dorollover():
    """Test if method doRollover of SizeBasedFileRotatingHandler works properly."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        test_str = 'test string'
        log_file = join(tmp_dir, 'test.log')

        fh = wlogging.SizeBasedFileRotatingHandler(filename=log_file, maxBytes=1, backupCount=1)

        with open(log_file, 'w') as f:
            f.write(test_str)

        fh.doRollover()
        today = date.today()
        backup_file = join(tmp_dir, 'test', str(today.year),
                           today.strftime("%b"),
                           f"test.log-{today.day:02d}_1.gz")

        with gzip.open(backup_file, 'r') as backup:
            assert backup.read().decode() == test_str


@patch('wazuh.core.utils.mkdir_with_mode')
def test_sizebasedfilerotatinghandler_compute_log_directory(mock_mkdir):
    """Test if method compute_log_directory of SizeBasedFileRotatingHandler works properly."""
    previous_rotated_logs = randint(2, 15)

    def _mock_exists(path):
        path_regex = re.match(r".+_(\d+)\.gz", path)
        if path_regex is None:
            return exists(path)
        else:
            return False if int(path_regex.group(1)) > previous_rotated_logs else True

    with tempfile.TemporaryDirectory() as tmp_dir:
        log_file = join(tmp_dir, 'test.log')
        with open(log_file, 'w') as _:
            pass

        fh = wlogging.SizeBasedFileRotatingHandler(filename=log_file, maxBytes=1, backupCount=1)
        today = date.today()
        year, month, day = today.year, today.month, today.day
        month = calendar.month_abbr[int(month)]

        log_path = join(tmp_dir, 'test', str(year), month)

        # Expect the first rotated log
        expected_name = join(log_path, f"test.log-{int(day):02d}_1.gz")
        computed_name = fh.compute_log_directory()

        assert expected_name == computed_name
        mock_mkdir.assert_called_with(log_path, 0o750)

        # Expect the 4th rotated log
        with patch("wazuh.core.wlogging.os.path.exists", new=_mock_exists):
            expected_name = join(log_path, f"test.log-{int(day):02d}_{previous_rotated_logs + 1}.gz")
            computed_name = fh.compute_log_directory()

            assert expected_name == computed_name
            mock_mkdir.assert_called_with(log_path, 0o750)


@pytest.mark.parametrize('max_size', [0, 500])
@patch('logging.addLevelName')
@patch('logging.Logger.addHandler')
@patch('wazuh.core.wlogging.SizeBasedFileRotatingHandler')
@patch('wazuh.core.wlogging.TimeBasedFileRotatingHandler')
def test_wazuh_logger_setup_logger(mock_time_handler, mock_size_handler, mock_add_handler, mock_add_level_name,
                                   max_size):
    """Test if method setup_logger of WazuhLogger setups the logger attribute properly.

    Parameters
    ----------
    max_size : int
        `max_size` input value.
    """
    tmp_dir = tempfile.TemporaryDirectory()
    # To bypass the checking of the existence of a valid Wazuh install
    # Check time handler
    with patch('os.path.join', return_value=tmp_dir.name):
        w_logger = wlogging.WazuhLogger(foreground_mode=True, log_path=tmp_dir.name,
                                        tag='%(test)s %(test)s: %(test)s',
                                        debug_level=[0, 'test'], max_size=max_size)
    w_logger.setup_logger()
    if max_size == 0:
        mock_time_handler.assert_called_once_with(filename=tmp_dir.name, when='midnight')
        assert not mock_size_handler.called, "Size handler should not be called when using time based rotation"
    else:
        mock_size_handler.assert_called_with(filename=tmp_dir.name, maxBytes=max_size, backupCount=1)
        assert not mock_time_handler.called, "Time handler should not be called when using size based rotation"

    mock_add_handler.assert_called()
    mock_add_level_name.assert_called()


@patch.object(wlogging.WazuhLogger, 'log_path', create=True, new_callable=PropertyMock)
@patch.object(wlogging.WazuhLogger, 'tag', create=True, new_callable=PropertyMock)
@patch.object(wlogging.WazuhLogger, 'logger', create=True, new_callable=PropertyMock)
@patch.object(wlogging.WazuhLogger, 'foreground_mode', create=True, new_callable=PropertyMock)
@patch.object(wlogging.WazuhLogger, 'debug_level', create=True, new_callable=PropertyMock)
@patch.object(wlogging.WazuhLogger, 'logger_name', create=True, new_callable=PropertyMock)
@patch.object(wlogging.WazuhLogger, 'custom_formatter', create=True, new_callable=PropertyMock)
@patch.object(wlogging.WazuhLogger, 'max_size', create=True, new_callable=PropertyMock)
@patch('logging.Formatter')
def test_wazuh_logger__init__(mock_lformatter, mock_max_size, mock_formatter, mock_logger_name, mock_debug_level,
                              mock_foreground_mode, mock_logger, mock_tag, mock_log_path):
    """Test if WazuhLogger __init__ method initialize all attributes properly."""
    # To bypass the checking of the existence of a valid Wazuh install
    with patch('os.path.join'):
        wlogging.WazuhLogger(foreground_mode=mock_foreground_mode, log_path=mock_log_path, tag=mock_tag,
                             debug_level=mock_debug_level, logger_name=mock_logger_name,
                             custom_formatter=mock_formatter, max_size=mock_max_size)
    for x in [mock_formatter, mock_logger_name, mock_debug_level, mock_foreground_mode,
              mock_logger, mock_log_path]:
        x.assert_called()


@pytest.mark.parametrize('attribute, expected_exception, expected_value', [
    ('level', None, 0),
    ('foreground_mode', None, True),
    ('doesnt_exists', AttributeError, None)
])
@patch('wazuh.core.wlogging.SizeBasedFileRotatingHandler')
@patch('wazuh.core.wlogging.TimeBasedFileRotatingHandler')
def test_wazuh_logger_getattr(mock_time_handler, mock_size_handler, attribute, expected_exception, expected_value):
    """Test if WazuhLogger __getattr__ method works properly."""
    tmp_dir = tempfile.TemporaryDirectory()
    # To bypass the checking of the existence of a valid Wazuh install
    with patch('os.path.join'):
        w_logger = wlogging.WazuhLogger(foreground_mode=True, log_path=tmp_dir.name, tag='%(test)s %(test)s: %(test)s',
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


@pytest.mark.parametrize('value, expected', [
    ('Example log', True),
    ('Wazuh Internal Error', False),
    ('WazuhInternalError', False),
    ('WazuhError', True),
    ('InternalError', True)
])
def test_cli_custom_filter(value, expected):
    """
    Test if CLIFilter class works properly.
    """
    class MockedRecord:
        def __init__(self, msg):
            self.msg = msg

        def getMessage(self):
            return self.msg

    cf = wlogging.CLIFilter()
    assert cf.filter(MockedRecord(value)) == expected
