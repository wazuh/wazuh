# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

"""HTTP client for the Task Manager unix socket.

The Task Manager used to speak a bespoke JSON dialect framed with a four-byte length prefix, which
is why it had an entry in ``wazuh_socket.py``'s protocol registry. It now serves HTTP/1.1 over the
same socket, like wazuh-db and the engine, so this client follows the same shape as
``engine_http.py`` and ``wdb_http.py``.
"""

import httpx

from wazuh.core import common
from wazuh.core.exception import WazuhError, WazuhInternalError

#: Largest number of agent tasks sent in one bulk request. The Task Manager writes a whole batch in
#: a single database transaction, so this bounds the request body rather than the work.
TASK_CHUNK_SIZE = 500


class TaskManagerHTTPClient:
    """Synchronous HTTP client for the Task Manager unix socket."""

    API_URL = 'http://localhost'

    def __init__(self, timeout: float = 10):
        self.socket_path = str(common.TASKS_SOCKET)
        try:
            transport = httpx.HTTPTransport(uds=self.socket_path)
            self._client = httpx.Client(transport=transport, timeout=timeout)
        except Exception as exc:
            raise WazuhInternalError(2018, extra_message=str(exc)) from exc

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def close(self) -> None:
        """Close the Task Manager HTTP client."""
        self._client.close()

    def _post(self, route: str, body: dict) -> dict:
        """Send one request and return its parsed response.

        Parameters
        ----------
        route : str
            Path on the Task Manager socket.
        body : dict
            Request body.

        Returns
        -------
        dict
            The parsed response.

        Raises
        ------
        WazuhInternalError
            The Task Manager could not be reached, or did not answer in time.
        WazuhError
            The Task Manager refused the request.
        """
        try:
            response = self._client.post(
                url=f'{self.API_URL}{route}',
                json=body,
                headers={'Content-Type': 'application/json'},
            )
        except httpx.TimeoutException as exc:
            raise WazuhInternalError(2020, extra_message=str(exc))
        except httpx.ConnectError as exc:
            raise WazuhInternalError(2021, extra_message=str(exc))
        except httpx.RequestError as exc:
            raise WazuhError(2013, extra_message=str(exc))

        if response.is_error:
            raise WazuhError(2019, extra_message=response.text)

        try:
            return response.json()
        except ValueError as exc:
            raise WazuhInternalError(2022, extra_message=f'Invalid JSON in Task Manager response: {exc}')

    def create_task(self, agent_id: str, task_type: str, create_time: int, payload: dict,
                    source_id: str = None) -> dict:
        """Store one agent task.

        Parameters
        ----------
        agent_id : str
            Agent identifier.
        task_type : str
            One of the agent task types the Task Manager accepts.
        create_time : int
            Unix timestamp. Mixed into the deterministic task id, so the same logical request
            produces the same id on any cluster node.
        payload : dict
            Free-form body, interpreted by the agent.
        source_id : str
            Optional. Mixed into the task id as well; Active Response passes its document id.

        Returns
        -------
        dict
            ``{'task_id': ...}``.
        """
        body = {
            'agent_id': agent_id,
            'task_type': task_type,
            'create_time': create_time,
            'payload': payload,
        }
        if source_id is not None:
            body['source_id'] = source_id

        return self._post('/v1/tasks', body)

    def create_tasks(self, tasks: list) -> list:
        """Store many agent tasks in ONE request.

        This is why the per-agent loop is gone: restarting a fleet used to open one socket
        connection per agent inside a chunk of 500, and is now one request and one transaction.

        Parameters
        ----------
        tasks : list
            Each entry is a dict as accepted by :meth:`create_task`.

        Returns
        -------
        list
            One result per input, in order: ``{'agent_id': ..., 'task_id': ..., 'created': bool}``.
        """
        response = self._post('/v1/tasks/bulk', {'tasks': tasks})
        return response.get('results', [])
