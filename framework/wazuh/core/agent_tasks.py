# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Task-based agent control commands module.

This module provides functions to create tasks for agent control operations (restart, reload)
using the Task Manager. It replaces synchronous socket-based commands with asynchronous task
creation.
"""

import logging

from wazuh.core.task_http import TASK_CHUNK_SIZE, TaskManagerHTTPClient

#: Task manager communication error, as reported per agent in the results below.
TASK_MANAGER_ERROR = 4

logger = logging.getLogger('wazuh')

__all__ = [
    'TASK_CHUNK_SIZE',
    'core_restart_agents',
    'core_reload_agents',
    'create_restart_tasks',
    'create_reload_tasks',
]


def _create_agent_tasks(agents_chunk: list, task_type: str, request_time: int = None) -> dict:
    """Create one task per agent, in a single request.

    One request for the whole chunk, not one per agent. The Task Manager writes the batch in a
    single database transaction, so a fleet-wide restart costs one connection and one commit where
    it used to cost one of each per agent.

    A failure is reported per agent rather than raised, because the caller aggregates results across
    chunks and a partial answer is more useful than none. The Task Manager validates every entry
    before writing any of them, so a malformed entry rejects the whole chunk rather than leaving
    half of it written.

    Parameters
    ----------
    agents_chunk : list
        List of agent IDs.
    task_type : str
        Task type to create for each agent.
    request_time : int
        Unix timestamp from the API request, mixed into the deterministic task ID so the same
        logical request produces the same ID on any cluster node.

    Returns
    -------
    dict
        Format: ``{"data": [{"agent": "001", "error": 0, "task_id": "..."}, ...]}``
    """
    tasks = [
        {
            'agent_id': agent_id,
            'task_type': task_type,
            'create_time': request_time,
            'payload': {},
        }
        for agent_id in agents_chunk
    ]

    try:
        with TaskManagerHTTPClient() as client:
            outcomes = client.create_tasks(tasks)
    except Exception as exc:
        return {
            'data': [
                {'agent': agent_id, 'error': TASK_MANAGER_ERROR, 'message': str(exc)}
                for agent_id in agents_chunk
            ]
        }

    results = []
    by_agent = {outcome.get('agent_id'): outcome for outcome in outcomes}

    for agent_id in agents_chunk:
        outcome = by_agent.get(agent_id)

        if outcome is None:
            # The Task Manager answered without a result for this agent. Reported rather than
            # assumed successful: the caller uses these results to tell an operator what happened.
            results.append(
                {
                    'agent': agent_id,
                    'error': TASK_MANAGER_ERROR,
                    'message': 'The task manager did not report a result for this agent',
                }
            )
            continue

        result_item = {'agent': agent_id, 'error': 0, 'message': ''}

        if 'task_id' in outcome:
            result_item['task_id'] = outcome['task_id']
            logger.debug(f"Created {task_type} task {outcome['task_id']} for agent {agent_id}")

        results.append(result_item)

    return {'data': results}


def core_restart_agents(agents_chunk: list, request_time: int = None) -> dict:
    """Create a restart task for every agent in the chunk.

    Parameters
    ----------
    agents_chunk : list
        List of agent IDs.
    request_time : int
        Unix timestamp from the API request, for deterministic task IDs across cluster nodes.

    Returns
    -------
    dict
        Format: ``{"data": [{"agent": "001", "error": 0, "task_id": "..."}, ...]}``
    """
    return _create_agent_tasks(agents_chunk, 'agent_restart', request_time)


def core_reload_agents(agents_chunk: list, request_time: int = None) -> dict:
    """Create a reload task for every agent in the chunk.

    Parameters
    ----------
    agents_chunk : list
        List of agent IDs.
    request_time : int
        Unix timestamp from the API request, for deterministic task IDs across cluster nodes.

    Returns
    -------
    dict
        Format: ``{"data": [{"agent": "001", "error": 0, "task_id": "..."}, ...]}``
    """
    return _create_agent_tasks(agents_chunk, 'agent_reload', request_time)


def _create_tasks_in_chunks(create_chunk, eligible_agents: list, chunk_size: int, request_time: int) -> list:
    """Walk a fleet in chunks, halving the chunk on a Task Manager communication error.

    The halving is preserved from the socket-per-agent implementation this replaced, where a large
    chunk really could exhaust the manager's connection budget. Over the bulk HTTP route a whole
    chunk now travels in one request, so the usual cause of ``TASK_MANAGER_ERROR`` -- the module
    being down -- will not be cured by asking again in smaller pieces. It is kept because the
    contract callers rely on has not changed, and because a size-related refusal is still possible.

    Parameters
    ----------
    create_chunk : callable
        ``core_restart_agents`` or ``core_reload_agents``.
    eligible_agents : list
        List of eligible agent IDs.
    chunk_size : int
        Number of agents to send in one request.
    request_time : int
        Unix timestamp from the API request, for deterministic task IDs across cluster nodes.

    Returns
    -------
    list
        One result dict per chunk.
    """
    result = []
    agents_chunks = [
        eligible_agents[x : x + chunk_size] for x in range(0, len(eligible_agents), chunk_size)
    ]

    for chunk in agents_chunks:
        response = create_chunk(agents_chunk=chunk, request_time=request_time)

        if any(item['error'] == TASK_MANAGER_ERROR for item in response['data']) and chunk_size != 1:
            # Restarts the whole walk, not just this chunk: chunks already created are idempotent,
            # because the task id is derived from the agent and the request time rather than
            # generated, so re-creating one collides with the row that is already there.
            return _create_tasks_in_chunks(create_chunk, eligible_agents, chunk_size // 2, request_time)

        result.append(response)

    return result


def create_restart_tasks(eligible_agents: list, chunk_size: int, request_time: int) -> list:
    """Create restart tasks for a fleet, in chunks.

    Parameters
    ----------
    eligible_agents : list
        List of eligible agent IDs.
    chunk_size : int
        Number of agents to send in one request.
    request_time : int
        Unix timestamp from the API request, for deterministic task IDs across cluster nodes.

    Returns
    -------
    list
        Restart task creation results, one dict per chunk.
    """
    return _create_tasks_in_chunks(core_restart_agents, eligible_agents, chunk_size, request_time)


def create_reload_tasks(eligible_agents: list, chunk_size: int, request_time: int) -> list:
    """Create reload tasks for a fleet, in chunks.

    Parameters
    ----------
    eligible_agents : list
        List of eligible agent IDs.
    chunk_size : int
        Number of agents to send in one request.
    request_time : int
        Unix timestamp from the API request, for deterministic task IDs across cluster nodes.

    Returns
    -------
    list
        Reload task creation results, one dict per chunk.
    """
    return _create_tasks_in_chunks(core_reload_agents, eligible_agents, chunk_size, request_time)
