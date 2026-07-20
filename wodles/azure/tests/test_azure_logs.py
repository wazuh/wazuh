# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

# run test: python3 -m pytest azure/tests/test_azure_logs.py -v --log-cli-level=DEBUG

import logging
import os
import runpy
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))  # noqa: E501

AZURE_LOGS_PATH = os.path.realpath(
    os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'azure-logs.py')
)

logger = logging.getLogger(__name__)


def _run(mock_args, db_integrity=True):
    """Execute azure-logs.py as __main__ with all entry-point dependencies mocked."""
    with patch('azure_utils.get_script_arguments', return_value=mock_args), \
         patch('azure_utils.set_logger'), \
         patch('db.orm.check_database_integrity', return_value=db_integrity), \
         patch('azure_services.analytics.start_log_analytics') as mock_la, \
         patch('azure_services.graph.start_graph') as mock_graph, \
         patch('azure_services.storage.start_storage') as mock_storage:
        runpy.run_path(AZURE_LOGS_PATH, run_name='__main__')
        return mock_la, mock_graph, mock_storage


def test_exits_when_database_integrity_check_fails():
    mock_args = MagicMock(log_analytics=None, graph=None, storage=None)
    with patch('azure_utils.get_script_arguments', return_value=mock_args), \
         patch('azure_utils.set_logger'), \
         patch('db.orm.check_database_integrity', return_value=False):
        with pytest.raises(SystemExit) as exc_info:
            runpy.run_path(AZURE_LOGS_PATH, run_name='__main__')
    logger.info(f"SystemExit code when DB integrity fails => {exc_info.value.code}")
    assert exc_info.value.code == 1


def test_calls_start_log_analytics_when_flag_set():
    mock_args = MagicMock(log_analytics=True, graph=None, storage=None)
    mock_la, mock_graph, mock_storage = _run(mock_args)
    logger.info(f"start_log_analytics called => {mock_la.called}")
    mock_la.assert_called_once_with(mock_args)
    mock_graph.assert_not_called()
    mock_storage.assert_not_called()


def test_calls_start_graph_when_flag_set():
    mock_args = MagicMock(log_analytics=None, graph=True, storage=None)
    mock_la, mock_graph, mock_storage = _run(mock_args)
    logger.info(f"start_graph called => {mock_graph.called}")
    mock_graph.assert_called_once_with(mock_args)
    mock_la.assert_not_called()
    mock_storage.assert_not_called()


def test_calls_start_storage_when_flag_set():
    mock_args = MagicMock(log_analytics=None, graph=None, storage=True)
    mock_la, mock_graph, mock_storage = _run(mock_args)
    logger.info(f"start_storage called => {mock_storage.called}")
    mock_storage.assert_called_once_with(mock_args)
    mock_la.assert_not_called()
    mock_graph.assert_not_called()


def test_exits_when_no_valid_api_specified():
    mock_args = MagicMock(log_analytics=None, graph=None, storage=None)
    with patch('azure_utils.get_script_arguments', return_value=mock_args), \
         patch('azure_utils.set_logger'), \
         patch('db.orm.check_database_integrity', return_value=True), \
         patch('azure_services.analytics.start_log_analytics'), \
         patch('azure_services.graph.start_graph'), \
         patch('azure_services.storage.start_storage'):
        with pytest.raises(SystemExit) as exc_info:
            runpy.run_path(AZURE_LOGS_PATH, run_name='__main__')
    logger.info(f"SystemExit code when no API specified => {exc_info.value.code}")
    assert exc_info.value.code == 1
