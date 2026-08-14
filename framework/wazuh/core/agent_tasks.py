# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Task-based agent control commands module.

This module provides functions to create tasks for agent control operations (restart, reload)
using the Task Manager. It replaces synchronous socket-based commands with asynchronous task creation.
"""

import logging
from json import dumps, loads

from wazuh.core import common
from wazuh.core.wazuh_socket import WazuhSocket


TASK_CHUNK_SIZE = 500
logger = logging.getLogger('wazuh')


def core_restart_agents(agents_chunk: list, request_time: int = None) -> dict:
    """Send command to task module to create restart tasks.

    Parameters
    ----------
    agents_chunk : list
        List of agents ID's.
    request_time : int
        Unix timestamp from API request for deterministic task ID generation across cluster nodes.

    Returns
    -------
    dict
        Message received from the socket (Task module) with aggregated results
        Format: {"data": [{"agent": "001", "error": 0, "message": "..."}, ...]}
    """
    results = []

    # Create individual task for each agent
    for agent_id in agents_chunk:
        msg = {
            "action": "create_task",
            "agent_id": agent_id,
            "task_type": "agent_restart",
            "create_time": request_time,
            "payload": {}
        }

        try:
            # Send restart task creation request to task manager via TASKS_SOCKET
            s = WazuhSocket(common.TASKS_SOCKET)
            s.send(dumps(msg).encode())

            # Receive task creation response
            response = loads(s.receive().decode())
            s.close()

            # Add agent info to results
            result_item = {
                "agent": agent_id,
                "error": response.get("error", 0),
                "message": response.get("message", ""),
            }

            # Include task info if available
            if "task_id" in response:
                result_item["task_id"] = response["task_id"]
                # Log successful task creation
                task_type = msg.get("task_type", "unknown")
                task_id = response.get("task_id")
                logger.debug(f"Created {task_type} task {task_id} for agent {agent_id}")
            if "create_time" in response:
                result_item["create_time"] = response["create_time"]

            results.append(result_item)

        except Exception as e:
            # Handle socket communication errors
            results.append({
                "agent": agent_id,
                "error": 4,  # Task manager communication error
                "message": str(e),
            })

    return {"data": results}


def core_reload_agents(agents_chunk: list, request_time: int = None) -> dict:
    """Send command to task module to create reload tasks.

    Parameters
    ----------
    agents_chunk : list
        List of agents ID's.
    request_time : int
        Unix timestamp from API request for deterministic task ID generation across cluster nodes.

    Returns
    -------
    dict
        Message received from the socket (Task module) with aggregated results
        Format: {"data": [{"agent": "001", "error": 0, "message": "..."}, ...]}
    """
    results = []

    # Create individual task for each agent
    for agent_id in agents_chunk:
        msg = {
            "action": "create_task",
            "agent_id": agent_id,
            "task_type": "agent_reload",
            "create_time": request_time,
            "payload": {}
        }

        try:
            # Send reload task creation request to task manager via TASKS_SOCKET
            s = WazuhSocket(common.TASKS_SOCKET)
            s.send(dumps(msg).encode())

            # Receive task creation response
            response = loads(s.receive().decode())
            s.close()

            # Add agent info to results
            result_item = {
                "agent": agent_id,
                "error": response.get("error", 0),
                "message": response.get("message", ""),
            }

            # Include task info if available
            if "task_id" in response:
                result_item["task_id"] = response["task_id"]
                # Log successful task creation
                task_type = msg.get("task_type", "unknown")
                task_id = response.get("task_id")
                logger.debug(f"Created {task_type} task {task_id} for agent {agent_id}")
            if "create_time" in response:
                result_item["create_time"] = response["create_time"]

            results.append(result_item)

        except Exception as e:
            # Handle socket communication errors
            results.append({
                "agent": agent_id,
                "error": 4,  # Task manager communication error
                "message": str(e),
            })

    return {"data": results}


def create_restart_tasks(eligible_agents: list, chunk_size: int, request_time: int) -> list:
    """Recursive function to create agent restart tasks.

    If a task manager communication error is in the response (error code 4),
    the chunk size is split in half and retried.

    Parameters
    ----------
    eligible_agents : list
        List of eligible agent IDs.
    chunk_size : int
        Number of agents to send to the task socket at once.
    request_time : int
        Unix timestamp from API request for deterministic task ID generation.

    Returns
    -------
    list
        Restart task creation results.
    """
    result = []
    agents_chunks = [
        eligible_agents[x : x + chunk_size]
        for x in range(0, len(eligible_agents), chunk_size)
    ]

    for chunk in agents_chunks:
        response = core_restart_agents(agents_chunk=chunk, request_time=request_time)

        # Retry with smaller chunk if task manager communication error
        if any(item["error"] == 4 for item in response["data"]) and chunk_size != 1:
            return create_restart_tasks(eligible_agents, chunk_size // 2, request_time)

        result.append(response)

    return result


def create_reload_tasks(eligible_agents: list, chunk_size: int, request_time: int) -> list:
    """Recursive function to create agent reload tasks.

    If a task manager communication error is in the response (error code 4),
    the chunk size is split in half and retried.

    Parameters
    ----------
    eligible_agents : list
        List of eligible agent IDs.
    chunk_size : int
        Number of agents to send to the task socket at once.
    request_time : int
        Unix timestamp from API request for deterministic task ID generation.

    Returns
    -------
    list
        Reload task creation results.
    """
    result = []
    agents_chunks = [
        eligible_agents[x : x + chunk_size]
        for x in range(0, len(eligible_agents), chunk_size)
    ]

    for chunk in agents_chunks:
        response = core_reload_agents(agents_chunk=chunk, request_time=request_time)

        # Retry with smaller chunk if task manager communication error
        if any(item["error"] == 4 for item in response["data"]) and chunk_size != 1:
            return create_reload_tasks(eligible_agents, chunk_size // 2, request_time)

        result.append(response)

    return result
