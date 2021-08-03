# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import calendar
import datetime
from unittest.mock import patch, ANY
import tempfile
import pytest
import os
import gzip

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from wazuh.core import wlogging, common


def test_CustomFileRotatingHandler_doRollover():
    """Test if method doRollover of CustomFileRotatingHandler works properly."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        test_str = 'test string'
        log_file = os.path.join(tmp_dir, 'test.log')
        with open(log_file, 'w') as f:
            f.write(test_str)

        fh = wlogging.CustomFileRotatingHandler(filename=log_file)
        fh.doRollover()
        today = datetime.date.today()
        backup_file = os.path.join(tmp_dir, 'test', str(today.year),
                                   today.strftime("%b"),
                                   f"test-{today.day:02d}.log.gz")

        with gzip.open(backup_file, 'r') as backup:
            assert backup.read().decode() == test_str


@pytest.mark.parametrize('rotated_file', ['test.log.2021-08-03', 'test.log.2019-07-04'])
@patch('wazuh.core.utils.mkdir_with_mode')
def test_computeArchivesDirectory(mock_mkdir, rotated_file):
    """Test if method computeArchivesDirectory of CustomFileRotatingHandler works properly.

    Parameters
    ----------
    mock_mkdir : mock
        Mock of mkdir method.
    rotated_file : str
        Test log file used to compute the directory.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        log_file = os.path.join(tmp_dir, 'test.log')
        with open(log_file, 'w') as _:
            pass

        fh = wlogging.CustomFileRotatingHandler(filename=log_file)
        year, month, day = rotated_file.split('-')
        year = year.split('.')[2]
        month = calendar.month_abbr[int(month)]
        log_path = os.path.join(tmp_dir, 'test', year, month)
        expected_name = os.path.join(log_path, f"test-{int(day):02d}.log.gz")
        computed_name = fh.computeArchivesDirectory(rotated_file)

        assert expected_name == computed_name
        mock_mkdir.assert_called_with(log_path, 0o750)
