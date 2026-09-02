# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

"""HTTP-over-UDS client for the Task Manager, and a stub of the consumer it calls.

Both live here rather than in the tests because every test needs at least one of them, and because
the stub consumer is the only way to exercise the parts of the queue that matter: a route that
stalls, that answers 409, or that is simply not listening is what drives the retry, the deferral and
the dead-letter paths.
"""

import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler
from socketserver import ThreadingMixIn, UnixStreamServer

import httpx


class TaskManagerClient:
    """Talks to the Task Manager the way its production clients do."""

    def __init__(self, socket_path: str, timeout: float = 10.0):
        self.socket_path = socket_path
        self._client = httpx.Client(transport=httpx.HTTPTransport(uds=socket_path), timeout=timeout)

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def post(self, route: str, body: dict) -> httpx.Response:
        return self._client.post(f'http://localhost{route}', json=body,
                                 headers={'Content-Type': 'application/json'})

    # ---- agent tasks -------------------------------------------------------------------------

    def create_agent_task(self, agent_id: str, task_type: str = 'agent_restart',
                          payload: dict = None, create_time: int = None, source_id: str = None):
        body = {
            'agent_id': agent_id,
            'task_type': task_type,
            'create_time': create_time if create_time is not None else int(time.time()),
            'payload': payload if payload is not None else {},
        }
        if source_id is not None:
            body['source_id'] = source_id
        return self.post('/v1/tasks', body)

    def create_agent_tasks(self, tasks: list):
        return self.post('/v1/tasks/bulk', {'tasks': tasks})

    def take_pending(self, agent_id: str):
        return self.post('/v1/tasks/pending', {'agent_id': agent_id})

    # ---- manager tasks -----------------------------------------------------------------------

    def create_manager_task(self, task_id: str, task_type: str, payload: dict = None,
                            agent_id: str = None, **extra):
        body = {'task_id': task_id, 'task_type': task_type,
                'payload': payload if payload is not None else {}}
        if agent_id is not None:
            body['agent_id'] = agent_id
        body.update(extra)
        return self.post('/v1/manager-tasks', body)

    def get_manager_task(self, task_id: str):
        return self.post('/v1/manager-tasks/get', {'task_id': task_id})

    def list_manager_tasks(self, task_type: str, status: str = None, last_task_id: str = None,
                           limit: int = None):
        body = {'task_type': task_type}
        if status is not None:
            body['status'] = status
        if last_task_id is not None:
            body['last_task_id'] = last_task_id
        if limit is not None:
            body['limit'] = limit
        return self.post('/v1/manager-tasks/list', body)

    def count_manager_tasks(self, task_type: str, status: str):
        return self.post('/v1/manager-tasks/count', {'task_type': task_type, 'status': status})

    def health(self):
        return self._client.get('http://localhost/v1/health')

    # ---- polling helpers ---------------------------------------------------------------------

    def wait_for_status(self, task_id: str, status: str, timeout: float = 30.0) -> dict:
        """Poll one manager task until it reaches `status`.

        Returns the row. Raises AssertionError with the row it last saw, which is what makes a
        failure here readable -- "expected completed, last saw pending with 3 attempts and
        last_error 'consumer not listening'" says what happened.
        """
        deadline = time.time() + timeout
        last = None
        while time.time() < deadline:
            response = self.get_manager_task(task_id)
            if response.status_code == 200:
                last = response.json()['task']
                if last['status'] == status:
                    return last
            time.sleep(0.1)

        raise AssertionError(
            f"task {task_id} did not reach '{status}' within {timeout}s; last seen: {last}")


class _StubHandler(BaseHTTPRequestHandler):
    """One request. What it answers is decided by the owning StubConsumer."""

    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass  # the harness captures the module's log, not this stub's

    def do_POST(self):  # noqa: N802 -- BaseHTTPRequestHandler's naming
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length) if length else b''

        consumer = self.server.consumer
        consumer.record(self.path, body)

        status, payload, stall = consumer.next_response()

        if stall:
            # Held open past the caller's deadline, which is how a timeout outcome is produced
            # without waiting out a production-length one.
            time.sleep(stall)

        encoded = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


class _ThreadingUnixServer(ThreadingMixIn, UnixStreamServer):
    daemon_threads = True

    def get_request(self):
        # UnixStreamServer hands back an empty client address, which BaseHTTPRequestHandler tries
        # to index when it formats a log line. A placeholder keeps it from raising.
        request, _ = super().get_request()
        return request, ('localhost', 0)


class StubConsumer:
    """A stand-in for inventory-sync, whose answers each test scripts.

    This is the piece that makes the interesting cases reachable: a consumer that is absent, that is
    busy, that fails, or that takes longer than the caller's deadline. Without it the queue could
    only ever be tested on its happy path.
    """

    def __init__(self, socket_path: str):
        self.socket_path = socket_path
        self._server = None
        self._thread = None
        self._lock = threading.Lock()
        self._responses = []
        self._default = (200, {'status': 'ok'}, 0)
        self.requests = []

    def start(self):
        self._server = _ThreadingUnixServer(self.socket_path, _StubHandler)
        self._server.consumer = self
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def record(self, path: str, body: bytes):
        with self._lock:
            self.requests.append({'path': path, 'body': json.loads(body) if body else None})

    def queue_response(self, status: int, payload: dict = None, stall: float = 0):
        """Queue one answer. Requests past the queue take the default."""
        with self._lock:
            self._responses.append((status, payload if payload is not None else {}, stall))

    def set_default(self, status: int, payload: dict = None, stall: float = 0):
        with self._lock:
            self._default = (status, payload if payload is not None else {}, stall)

    def next_response(self):
        with self._lock:
            if self._responses:
                return self._responses.pop(0)
            return self._default

    def request_count(self, path: str = None) -> int:
        with self._lock:
            if path is None:
                return len(self.requests)
            return sum(1 for r in self.requests if r['path'] == path)


def wait_for_socket(path: str, timeout: float = 20.0):
    """Block until `path` accepts a connection."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                probe.connect(path)
            return
        except (FileNotFoundError, ConnectionRefusedError, OSError):
            time.sleep(0.05)

    raise TimeoutError(f'{path} did not accept a connection within {timeout}s')
