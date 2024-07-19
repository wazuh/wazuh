# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import logging
import os
import sys
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))  # noqa: E501
import tools


def test_get_script_arguments(capsys):
    """Test get_script_arguments shows no messages when the required parameters were provided."""
    with patch("sys.argv", ['main', '--integration_type', 'any', '--credentials_file', 'any']):
        tools.get_script_arguments()
    stdout, stderr = capsys.readouterr()
    assert stdout == "", 'stdout was not empty'
    assert stderr == "", 'stderr was not empty'


@pytest.mark.parametrize('args', [
    ['main'],
    ['main', '--integration_type', 'any'],
    ['main', '--credentials_file', 'any'],
])
def test_get_script_arguments_required(capsys, args):
    """Test get_script_arguments shows an error message when the required parameters are not provided."""
    with patch("sys.argv", args), pytest.raises(SystemExit) as exception:
        tools.get_script_arguments()
    stdout, stderr = capsys.readouterr()
    assert stdout == "", 'The output was not empty'
    assert stderr != "", 'No error message was found in the output'
    assert exception.value.code == 2


@pytest.mark.parametrize('level, expected_logging_level', [
    (0, logging.WARNING),
    (1, logging.INFO),
    (2, logging.DEBUG)
])
@patch('tools.logging.getLogger')
def test_get_stdout_logger(mock_logger, level, expected_logging_level):
    """Test the get_stdout_logger function created a logger object with the expected logging level value."""
    with patch('tools.logger') as mock_l:
        mock_l.setLevel = MagicMock()
        tools.get_stdout_logger(name='test', level=level)
        mock_l.setLevel.assert_called_with(expected_logging_level)


def test_arg_valid_date():
    """Test arg_valid_dates raises an error when a date parameter doesn't have a valid format."""
    with pytest.raises(argparse.ArgumentTypeError):
        tools.arg_valid_date('invalid_date')
