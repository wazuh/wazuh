import argparse
import os
import sys
from unittest.mock import patch

import pytest

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))  # noqa: E501
from wodles.gcloud.tools import get_script_arguments, arg_valid_date


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
