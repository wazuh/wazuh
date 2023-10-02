import argparse
import logging
import os
import sys
import pytest
from unittest.mock import patch

# Local imports
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))  # noqa: E501
from gcloud.tools import get_script_arguments
from gcp_logger import GCPLogStrategy


@pytest.fixture(scope='module')
def gcp_strategy():
    return GCPLogStrategy()


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


@pytest.mark.parametrize("log_level, log_method, expected_message", [
    (logging.INFO, 'info', 'Test info message'),
    (logging.DEBUG, 'debug', 'Test debug message'),
    (logging.WARNING, 'warning', 'Test warning message'),
    (logging.ERROR, 'error', 'Test error message'),
    (logging.CRITICAL, 'critical', 'Test critical message'),
])
def test_log_methods(gcp_strategy, caplog, log_level, log_method, expected_message):
    with caplog.at_level(log_level, logger='TestGCPLogStrategy'):
        with patch.object(gcp_strategy, 'logger', logging.getLogger('TestGCPLogStrategy')):
            getattr(gcp_strategy, log_method)(expected_message)
    assert expected_message in caplog.text
