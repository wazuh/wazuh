# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""Unit tests for gcloud module."""
import argparse
from os.path import join, dirname, realpath
import sys
import pytest
from unittest.mock import patch

# Local imports
sys.path.append(join(dirname(realpath(__file__)), '..'))  # noqa: E501 # noqa: E501
from gcloud import get_script_arguments
from tools import arg_valid_date

def test_get_script_arguments(capsys):
    """Test get_script_arguments shows no messages when the required parameters were provided."""
    with patch("sys.argv", ['main', '--integration_type', 'any', '--credentials_file', 'any']):
        get_script_arguments()
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
        get_script_arguments()
    stdout, stderr = capsys.readouterr()
    assert stdout == "", 'The output was not empty'
    assert stderr != "", 'No error message was found in the output'
    assert exception.value.code == 2


def test_arg_valid_date():
    """Test arg_valid_dates raises an error when a date parameter doesn't have a valid format."""
    with pytest.raises(argparse.ArgumentTypeError):
        arg_valid_date('invalid_date')
