#!/usr/bin/env python
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from json import dumps
from unittest.mock import patch, MagicMock, call

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from wazuh.core.agent_tasks import (
            core_restart_agents,
            core_reload_agents,
            create_restart_tasks,
            create_reload_tasks,
            TASK_CHUNK_SIZE
        )


class TestCoreRestartAgents:
    """Test cases for core_restart_agents function."""

    @patch('wazuh.core.agent_tasks.WazuhSocket')
    def test_core_restart_agents_success(self, mock_socket_class):
        """Test successful restart task creation for multiple agents."""
        # Arrange
        agents = ['001', '002', '003']
        request_time = 1234567890

        # Mock socket responses for each agent
        mock_socket_instance = MagicMock()
        mock_socket_class.return_value = mock_socket_instance

        responses = [
            dumps({"error": 0, "message": "Task created", "task_id": "restart_001_1234567890"}),
            dumps({"error": 0, "message": "Task created", "task_id": "restart_002_1234567890"}),
            dumps({"error": 0, "message": "Task created", "task_id": "restart_003_1234567890"})
        ]
        mock_socket_instance.receive.side_effect = [
            MagicMock(decode=lambda: responses[0]),
            MagicMock(decode=lambda: responses[1]),
            MagicMock(decode=lambda: responses[2])
        ]

        # Act
        result = core_restart_agents(agents, request_time)

        # Assert
        assert result['data'] == [
            {"agent": "001", "error": 0, "message": "Task created", "task_id": "restart_001_1234567890"},
            {"agent": "002", "error": 0, "message": "Task created", "task_id": "restart_002_1234567890"},
            {"agent": "003", "error": 0, "message": "Task created", "task_id": "restart_003_1234567890"}
        ]

        # Verify socket calls
        assert mock_socket_instance.send.call_count == 3
        assert mock_socket_instance.receive.call_count == 3
        assert mock_socket_instance.close.call_count == 3

        # Verify message format
        expected_msg_001 = dumps({
            "action": "create_task",
            "agent_id": "001",
            "task_type": "agent_restart",
            "create_time": request_time,
            "payload": {}
        })
        mock_socket_instance.send.assert_any_call(expected_msg_001.encode())

    @patch('wazuh.core.agent_tasks.WazuhSocket')
    def test_core_restart_agents_with_error(self, mock_socket_class):
        """Test restart task creation when some agents fail."""
        # Arrange
        agents = ['001', '002']
        request_time = 1234567890

        mock_socket_instance = MagicMock()
        mock_socket_class.return_value = mock_socket_instance

        responses = [
            dumps({"error": 0, "message": "Task created", "task_id": "restart_001_1234567890"}),
            dumps({"error": 1, "message": "Agent not found"})
        ]
        mock_socket_instance.receive.side_effect = [
            MagicMock(decode=lambda: responses[0]),
            MagicMock(decode=lambda: responses[1])
        ]

        # Act
        result = core_restart_agents(agents, request_time)

        # Assert
        assert len(result['data']) == 2
        assert result['data'][0]['error'] == 0
        assert result['data'][1]['error'] == 1
        assert result['data'][1]['message'] == "Agent not found"

    @patch('wazuh.core.agent_tasks.WazuhSocket')
    def test_core_restart_agents_socket_exception(self, mock_socket_class):
        """Test restart task creation when socket communication fails."""
        # Arrange
        agents = ['001']
        request_time = 1234567890

        mock_socket_instance = MagicMock()
        mock_socket_class.return_value = mock_socket_instance
        mock_socket_instance.send.side_effect = Exception("Connection refused")

        # Act
        result = core_restart_agents(agents, request_time)

        # Assert
        assert len(result['data']) == 1
        assert result['data'][0]['agent'] == '001'
        assert result['data'][0]['error'] == 4  # Task manager communication error
        assert "Connection refused" in result['data'][0]['message']

    @patch('wazuh.core.agent_tasks.WazuhSocket')
    def test_core_restart_agents_empty_list(self, mock_socket_class):
        """Test restart task creation with empty agent list."""
        # Arrange
        agents = []
        request_time = 1234567890

        # Act
        result = core_restart_agents(agents, request_time)

        # Assert
        assert result['data'] == []
        mock_socket_class.assert_not_called()


class TestCoreReloadAgents:
    """Test cases for core_reload_agents function."""

    @patch('wazuh.core.agent_tasks.WazuhSocket')
    def test_core_reload_agents_success(self, mock_socket_class):
        """Test successful reload task creation for multiple agents."""
        # Arrange
        agents = ['001', '002']
        request_time = 1234567890

        mock_socket_instance = MagicMock()
        mock_socket_class.return_value = mock_socket_instance

        responses = [
            dumps({"error": 0, "message": "Task created", "task_id": "reload_001_1234567890"}),
            dumps({"error": 0, "message": "Task created", "task_id": "reload_002_1234567890"})
        ]
        mock_socket_instance.receive.side_effect = [
            MagicMock(decode=lambda: responses[0]),
            MagicMock(decode=lambda: responses[1])
        ]

        # Act
        result = core_reload_agents(agents, request_time)

        # Assert
        assert len(result['data']) == 2
        assert result['data'][0]['task_id'] == "reload_001_1234567890"
        assert result['data'][1]['task_id'] == "reload_002_1234567890"

        # Verify message format
        expected_msg_001 = dumps({
            "action": "create_task",
            "agent_id": "001",
            "task_type": "agent_reload",
            "create_time": request_time,
            "payload": {}
        })
        mock_socket_instance.send.assert_any_call(expected_msg_001.encode())

    @patch('wazuh.core.agent_tasks.WazuhSocket')
    def test_core_reload_agents_with_error(self, mock_socket_class):
        """Test reload task creation when agent task fails."""
        # Arrange
        agents = ['001']
        request_time = 1234567890

        mock_socket_instance = MagicMock()
        mock_socket_class.return_value = mock_socket_instance

        response = dumps({"error": 2, "message": "Invalid agent version"})
        mock_socket_instance.receive.return_value = MagicMock(decode=lambda: response)

        # Act
        result = core_reload_agents(agents, request_time)

        # Assert
        assert result['data'][0]['error'] == 2
        assert result['data'][0]['message'] == "Invalid agent version"


class TestCreateRestartTasks:
    """Test cases for create_restart_tasks wrapper function."""

    @patch('wazuh.core.agent_tasks.core_restart_agents')
    def test_create_restart_tasks_single_chunk(self, mock_core_restart):
        """Test restart tasks creation with agents fitting in single chunk."""
        # Arrange
        agents = ['001', '002', '003']
        request_time = 1234567890
        chunk_size = 500

        mock_core_restart.return_value = {
            "data": [
                {"agent": "001", "error": 0},
                {"agent": "002", "error": 0},
                {"agent": "003", "error": 0}
            ]
        }

        # Act
        result = create_restart_tasks(agents, chunk_size, request_time)

        # Assert
        assert len(result) == 1
        mock_core_restart.assert_called_once_with(
            agents_chunk=agents,
            request_time=request_time
        )

    @patch('wazuh.core.agent_tasks.core_restart_agents')
    def test_create_restart_tasks_multiple_chunks(self, mock_core_restart):
        """Test restart tasks creation with agents split into multiple chunks."""
        # Arrange
        agents = [f'{i:03d}' for i in range(1, 6)]  # ['001', '002', '003', '004', '005']
        request_time = 1234567890
        chunk_size = 2

        mock_core_restart.side_effect = [
            {"data": [{"agent": "001", "error": 0}, {"agent": "002", "error": 0}]},
            {"data": [{"agent": "003", "error": 0}, {"agent": "004", "error": 0}]},
            {"data": [{"agent": "005", "error": 0}]}
        ]

        # Act
        result = create_restart_tasks(agents, chunk_size, request_time)

        # Assert
        assert len(result) == 3
        assert mock_core_restart.call_count == 3

    @patch('wazuh.core.agent_tasks.core_restart_agents')
    def test_create_restart_tasks_retry_on_error(self, mock_core_restart):
        """Test restart tasks creation retries with smaller chunks on communication error."""
        # Arrange
        agents = ['001', '002', '003', '004']
        request_time = 1234567890
        chunk_size = 4

        # First call fails with error code 4 (communication error)
        # Should retry with chunk_size = 2
        mock_core_restart.side_effect = [
            {"data": [{"agent": "001", "error": 4}, {"agent": "002", "error": 4},
                      {"agent": "003", "error": 4}, {"agent": "004", "error": 4}]},
            {"data": [{"agent": "001", "error": 0}, {"agent": "002", "error": 0}]},
            {"data": [{"agent": "003", "error": 0}, {"agent": "004", "error": 0}]}
        ]

        # Act
        result = create_restart_tasks(agents, chunk_size, request_time)

        # Assert
        assert len(result) == 2
        # First call with chunk_size 4, then retries with chunk_size 2
        assert mock_core_restart.call_count == 3

    @patch('wazuh.core.agent_tasks.core_restart_agents')
    def test_create_restart_tasks_no_retry_with_chunk_size_1(self, mock_core_restart):
        """Test restart tasks creation does not retry when chunk size is already 1."""
        # Arrange
        agents = ['001']
        request_time = 1234567890
        chunk_size = 1

        mock_core_restart.return_value = {"data": [{"agent": "001", "error": 4}]}

        # Act
        result = create_restart_tasks(agents, chunk_size, request_time)

        # Assert
        assert len(result) == 1
        assert result[0]['data'][0]['error'] == 4
        mock_core_restart.assert_called_once()


class TestCreateReloadTasks:
    """Test cases for create_reload_tasks wrapper function."""

    @patch('wazuh.core.agent_tasks.core_reload_agents')
    def test_create_reload_tasks_single_chunk(self, mock_core_reload):
        """Test reload tasks creation with agents fitting in single chunk."""
        # Arrange
        agents = ['001', '002']
        request_time = 1234567890
        chunk_size = 500

        mock_core_reload.return_value = {
            "data": [
                {"agent": "001", "error": 0},
                {"agent": "002", "error": 0}
            ]
        }

        # Act
        result = create_reload_tasks(agents, chunk_size, request_time)

        # Assert
        assert len(result) == 1
        mock_core_reload.assert_called_once_with(
            agents_chunk=agents,
            request_time=request_time
        )

    @patch('wazuh.core.agent_tasks.core_reload_agents')
    def test_create_reload_tasks_retry_on_error(self, mock_core_reload):
        """Test reload tasks creation retries with smaller chunks on communication error."""
        # Arrange
        agents = ['001', '002']
        request_time = 1234567890
        chunk_size = 2

        mock_core_reload.side_effect = [
            {"data": [{"agent": "001", "error": 4}, {"agent": "002", "error": 4}]},
            {"data": [{"agent": "001", "error": 0}]},
            {"data": [{"agent": "002", "error": 0}]}
        ]

        # Act
        result = create_reload_tasks(agents, chunk_size, request_time)

        # Assert
        assert len(result) == 2
        assert mock_core_reload.call_count == 3


class TestTaskChunkSize:
    """Test cases for TASK_CHUNK_SIZE constant."""

    def test_task_chunk_size_value(self):
        """Test that TASK_CHUNK_SIZE has the expected value."""
        assert TASK_CHUNK_SIZE == 500
