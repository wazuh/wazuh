#!/usr/bin/env python
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch, MagicMock

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from wazuh.core.agent_tasks import (
            core_restart_agents,
            core_reload_agents,
            create_restart_tasks,
            create_reload_tasks,
            TASK_CHUNK_SIZE
        )


def _client_returning(outcomes):
    """Build a patched TaskManagerHTTPClient whose create_tasks() answers with `outcomes`.

    The functions under test use the client as a context manager, so the mock has to answer
    __enter__ rather than being the client itself.
    """
    client = MagicMock()
    client.create_tasks.return_value = outcomes

    context = MagicMock()
    context.__enter__.return_value = client
    context.__exit__.return_value = False

    return context, client


class TestCoreRestartAgents:
    """Test cases for core_restart_agents function."""

    @patch('wazuh.core.agent_tasks.TaskManagerHTTPClient')
    def test_core_restart_agents_success(self, mock_client_class):
        """A chunk of agents is created in ONE request, and every agent gets its task id back."""
        agents = ['001', '002', '003']
        request_time = 1234567890

        context, client = _client_returning([
            {'agent_id': '001', 'task_id': 'task-001', 'created': True},
            {'agent_id': '002', 'task_id': 'task-002', 'created': True},
            {'agent_id': '003', 'task_id': 'task-003', 'created': True},
        ])
        mock_client_class.return_value = context

        result = core_restart_agents(agents, request_time)

        assert result['data'] == [
            {'agent': '001', 'error': 0, 'message': '', 'task_id': 'task-001'},
            {'agent': '002', 'error': 0, 'message': '', 'task_id': 'task-002'},
            {'agent': '003', 'error': 0, 'message': '', 'task_id': 'task-003'},
        ]

        # The point of the bulk route: one call for the whole chunk, not one per agent.
        client.create_tasks.assert_called_once()

        sent = client.create_tasks.call_args[0][0]
        assert sent == [
            {'agent_id': '001', 'task_type': 'agent_restart', 'create_time': request_time, 'payload': {}},
            {'agent_id': '002', 'task_type': 'agent_restart', 'create_time': request_time, 'payload': {}},
            {'agent_id': '003', 'task_type': 'agent_restart', 'create_time': request_time, 'payload': {}},
        ]

    @patch('wazuh.core.agent_tasks.TaskManagerHTTPClient')
    def test_core_restart_agents_missing_result(self, mock_client_class):
        """An agent the Task Manager did not answer for is reported, not assumed successful."""
        agents = ['001', '002']
        request_time = 1234567890

        context, _ = _client_returning([{'agent_id': '001', 'task_id': 'task-001', 'created': True}])
        mock_client_class.return_value = context

        result = core_restart_agents(agents, request_time)

        assert len(result['data']) == 2
        assert result['data'][0]['error'] == 0
        assert result['data'][1]['agent'] == '002'
        assert result['data'][1]['error'] == 4
        assert 'did not report a result' in result['data'][1]['message']

    @patch('wazuh.core.agent_tasks.TaskManagerHTTPClient')
    def test_core_restart_agents_request_exception(self, mock_client_class):
        """A failed request fails EVERY agent in the chunk: the batch is written or it is not."""
        agents = ['001', '002']
        request_time = 1234567890

        mock_client_class.side_effect = Exception('Connection refused')

        result = core_restart_agents(agents, request_time)

        assert len(result['data']) == 2
        for item, agent_id in zip(result['data'], agents):
            assert item['agent'] == agent_id
            assert item['error'] == 4  # Task manager communication error
            assert 'Connection refused' in item['message']

    @patch('wazuh.core.agent_tasks.TaskManagerHTTPClient')
    def test_core_restart_agents_empty_list(self, mock_client_class):
        """No agents, no results -- but the request still goes out unconditionally today."""
        context, client = _client_returning([])
        mock_client_class.return_value = context

        result = core_restart_agents([], 1234567890)

        assert result['data'] == []


class TestCoreReloadAgents:
    """Test cases for core_reload_agents function."""

    @patch('wazuh.core.agent_tasks.TaskManagerHTTPClient')
    def test_core_reload_agents_success(self, mock_client_class):
        """Reload differs from restart only in the task type written into every entry."""
        agents = ['001', '002']
        request_time = 1234567890

        context, client = _client_returning([
            {'agent_id': '001', 'task_id': 'task-001', 'created': True},
            {'agent_id': '002', 'task_id': 'task-002', 'created': True},
        ])
        mock_client_class.return_value = context

        result = core_reload_agents(agents, request_time)

        assert len(result['data']) == 2
        assert result['data'][0]['task_id'] == 'task-001'
        assert result['data'][1]['task_id'] == 'task-002'

        sent = client.create_tasks.call_args[0][0]
        assert [entry['task_type'] for entry in sent] == ['agent_reload', 'agent_reload']

    @patch('wazuh.core.agent_tasks.TaskManagerHTTPClient')
    def test_core_reload_agents_request_exception(self, mock_client_class):
        """A refusal from the Task Manager is reported per agent rather than raised."""
        agents = ['001']

        context, client = _client_returning(None)
        client.create_tasks.side_effect = Exception('Invalid agent version')
        mock_client_class.return_value = context

        result = core_reload_agents(agents, 1234567890)

        assert result['data'][0]['agent'] == '001'
        assert result['data'][0]['error'] == 4
        assert 'Invalid agent version' in result['data'][0]['message']


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
