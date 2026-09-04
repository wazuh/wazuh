#!/usr/bin/env python
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import MagicMock, patch

import httpx
import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from wazuh.core.agent import UPGRADE_TIMEOUT, core_upgrade_agents
        from wazuh.core.exception import WazuhError
        from wazuh.core.task_http import TASK_MANAGER_ERROR, TaskManagerHTTPClient, _shed_envelope


def _patched_client():
    """Build a patched TaskManagerHTTPClient used as a context manager.

    core_upgrade_agents() enters the client, so the mock has to answer __enter__ rather than being
    the client itself.
    """
    client = MagicMock()
    client.upgrade_agents.return_value = {'error': 0, 'data': [], 'message': 'Success'}
    client.upgrade_agents_custom.return_value = {'error': 0, 'data': [], 'message': 'Success'}

    context = MagicMock()
    context.__enter__.return_value = client
    context.__exit__.return_value = False

    return context, client


class TestCoreUpgradeAgents:
    """The manager-side upgrade path now speaks HTTP on the Task Manager socket."""

    @patch('wazuh.core.agent.TaskManagerHTTPClient')
    def test_repository_upgrade_uses_the_upgrade_route(self, mock_client_class):
        context, client = _patched_client()
        mock_client_class.return_value = context

        core_upgrade_agents(agents_chunk=[1, 2], command='upgrade', request_time=1756800000)

        client.upgrade_agents.assert_called_once()
        client.upgrade_agents_custom.assert_not_called()

    @patch('wazuh.core.agent.TaskManagerHTTPClient')
    def test_custom_upgrade_uses_the_custom_route(self, mock_client_class):
        context, client = _patched_client()
        mock_client_class.return_value = context

        core_upgrade_agents(
            agents_chunk=[1],
            command='upgrade_custom',
            file_path='/var/upgrade/wazuh_agent_v5.0.0_linux_x86_64.wpk',
            request_time=1756800000,
        )

        client.upgrade_agents_custom.assert_called_once()
        client.upgrade_agents.assert_not_called()

    @patch('wazuh.core.agent.TaskManagerHTTPClient')
    def test_waits_longer_than_the_clients_default(self, mock_client_class):
        """A cold upgrade fetches a repository index and a 50-100 MB WPK.

        The client's 10 s default would abandon the request while the manager was still doing
        exactly what it was asked to, and the module's own batch deadline is what must expire first.
        """
        context, _ = _patched_client()
        mock_client_class.return_value = context

        core_upgrade_agents(agents_chunk=[1], command='upgrade', request_time=1756800000)

        mock_client_class.assert_called_once_with(timeout=UPGRADE_TIMEOUT)

    @patch('wazuh.core.agent.TaskManagerHTTPClient')
    def test_unset_parameters_are_omitted_not_sent_as_null(self, mock_client_class):
        """The module reads a present key of the wrong type as a parse error.

        Sending ``"version": null`` would therefore fail the whole request rather than being
        ignored, so anything the caller did not set has to be left out entirely.
        """
        context, client = _patched_client()
        mock_client_class.return_value = context

        core_upgrade_agents(agents_chunk=[7], command='upgrade', request_time=1756800000)

        parameters = client.upgrade_agents.call_args[0][0]
        assert 'version' not in parameters
        assert 'wpk_repo' not in parameters
        assert 'package_type' not in parameters
        assert 'file_path' not in parameters
        assert 'installer' not in parameters

        # What the caller DID set survives, including the two booleans -- which are False, not None,
        # and so must not be dropped by the same filter.
        assert parameters['agents'] == [7]
        assert parameters['request_time'] == 1756800000
        assert parameters['force_upgrade'] is False
        assert parameters['use_http'] is False

    @patch('wazuh.core.agent.TaskManagerHTTPClient')
    def test_passes_every_set_parameter_through(self, mock_client_class):
        context, client = _patched_client()
        mock_client_class.return_value = context

        core_upgrade_agents(
            agents_chunk=[1],
            command='upgrade',
            wpk_repo='repo.example/wpk/',
            version='5.0.0',
            force=True,
            use_http=True,
            package_type='deb',
            request_time=1756800000,
        )

        parameters = client.upgrade_agents.call_args[0][0]
        assert parameters['wpk_repo'] == 'repo.example/wpk/'
        # Normalised to the 'v'-prefixed form the module compares against.
        assert parameters['version'] == 'v5.0.0'
        assert parameters['force_upgrade'] is True
        assert parameters['use_http'] is True
        assert parameters['package_type'] == 'deb'


class TestSheddingIsRetryable:
    """A refused request must look retryable, whoever refused it."""

    def test_the_shed_envelope_matches_the_modules_own(self):
        envelope = _shed_envelope({'agents': [4, 5]})

        assert envelope['error'] == 0
        assert envelope['message'] == 'Success'
        assert [entry['agent'] for entry in envelope['data']] == [4, 5]
        # Error 4 is what create_upgrade_tasks() reacts to by halving the chunk and retrying.
        assert all(entry['error'] == TASK_MANAGER_ERROR for entry in envelope['data'])

    def test_a_transport_503_becomes_a_retryable_envelope(self):
        """The module sheds with 200 + error 4 on purpose, so the caller retries.

        A 503 from the transport means the same thing, but would otherwise raise WazuhError(2019)
        and lose the whole chunk instead of retrying it smaller.
        """
        with patch('wazuh.core.task_http.httpx.Client') as mock_client_class:
            response = MagicMock(spec=httpx.Response)
            response.status_code = 503
            mock_client_class.return_value.post.return_value = response

            client = TaskManagerHTTPClient()
            result = client.upgrade_agents({'agents': [4, 5], 'request_time': 1756800000})

        assert [entry['error'] for entry in result['data']] == [TASK_MANAGER_ERROR] * 2

    def test_other_errors_still_raise(self):
        """Only 503 is treated as backpressure; a 400 is a real problem the caller must see."""
        with patch('wazuh.core.task_http.httpx.Client') as mock_client_class:
            response = MagicMock(spec=httpx.Response)
            response.status_code = 400
            response.is_error = True
            response.text = 'bad request'
            mock_client_class.return_value.post.return_value = response

            client = TaskManagerHTTPClient()
            with pytest.raises(WazuhError, match='.*2019.*'):
                client.upgrade_agents({'agents': [4], 'request_time': 1756800000})

    def test_the_non_upgrade_routes_do_not_swallow_a_503(self):
        """create_task() has no caller that knows how to retry, so it must still raise."""
        with patch('wazuh.core.task_http.httpx.Client') as mock_client_class:
            response = MagicMock(spec=httpx.Response)
            response.status_code = 503
            response.is_error = True
            response.text = 'unavailable'
            mock_client_class.return_value.post.return_value = response

            client = TaskManagerHTTPClient()
            with pytest.raises(WazuhError, match='.*2019.*'):
                client.create_task('001', 'agent_restart', 1756800000, {})
