'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Validate HTTP-over-UNIX-stream log collection: logcollector connects to a UNIX stream socket,
       issues an HTTP GET, and streams chunked response lines as log events. Also exercises the
       reconnect path when the server closes the connection.

components:
    - logcollector

suite: read

targets:
    - agent

daemons:
    - wazuh-logcollector

os_platform:
    - linux

tags:
    - logcollector_read
'''

import os
import socket
import tempfile
import threading
import time
import pytest

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.logcollector import utils as logcollector_utils
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.utils import callbacks

from utils import build_tc_config, wait_for_path_state


pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.tier(level=0)]

socket_path = os.path.join(tempfile.gettempdir(), 'wazuh-itest-http-unix.sock')

test_configuration = build_tc_config([
    [
        [
            {'location': {'value': socket_path}},
            {'log_format': {'value': 'http-unix'}},
            {'endpoint': {'value': '/events'}},
            {'reconnect_interval': {'value': '2'}}
        ]
    ]
])

test_metadata = [{'socket_path': socket_path}]

local_internal_options = {
    'logcollector.debug': '2',
    'logcollector.vcheck_files': '1'
}

daemons_handler_configuration = {'all_daemons': True}


class HTTPUnixServer:
    '''Minimal HTTP/1.1 chunked-response server bound to a UNIX stream socket.

    Each call to publish_line() emits one chunk = one line + newline.
    close_connection() forces the active client to receive EOF, exercising
    the logcollector reconnect path.
    '''

    def __init__(self, path: str):
        self.path = path
        self._lines: list[str] = []
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._server: socket.socket | None = None
        self._client: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = False
        self._kill_active = False

    def start(self) -> None:
        if os.path.exists(self.path):
            os.unlink(self.path)
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(self.path)
        self._server.listen(1)
        self._server.settimeout(0.5)
        os.chmod(self.path, 0o666)
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop = True
        with self._cond:
            self._cond.notify_all()
        if self._thread:
            self._thread.join(timeout=5)
        try:
            if self._server:
                self._server.close()
        except OSError:
            pass
        try:
            if os.path.exists(self.path):
                os.unlink(self.path)
        except OSError:
            pass

    def publish_line(self, line: str) -> None:
        with self._cond:
            self._lines.append(line)
            self._cond.notify_all()

    def close_connection(self) -> None:
        '''Force the current client connection closed so the next reconnect cycle exercises the loop.'''
        with self._cond:
            self._kill_active = True
            self._cond.notify_all()

    def _run(self) -> None:
        while not self._stop:
            try:
                client, _ = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                return

            self._client = client
            try:
                self._serve(client)
            finally:
                try:
                    client.close()
                except OSError:
                    pass
                self._client = None

    def _serve(self, client: socket.socket) -> None:
        client.settimeout(2.0)
        # Drain the request line + headers (read until \r\n\r\n)
        buf = b''
        try:
            while b'\r\n\r\n' not in buf:
                chunk = client.recv(1024)
                if not chunk:
                    return
                buf += chunk
        except socket.timeout:
            return

        # Send response status + chunked-encoding headers
        try:
            client.sendall(
                b'HTTP/1.1 200 OK\r\n'
                b'Content-Type: application/json\r\n'
                b'Transfer-Encoding: chunked\r\n'
                b'\r\n'
            )
        except OSError:
            return

        client.settimeout(None)
        # Stream chunks until stopped or asked to close
        while not self._stop:
            with self._cond:
                while not self._lines and not self._stop and not self._kill_active:
                    self._cond.wait(timeout=1.0)
                if self._kill_active:
                    self._kill_active = False
                    return
                if self._stop:
                    return
                pending = self._lines[:]
                self._lines.clear()

            for line in pending:
                payload = (line + '\n').encode()
                size_line = f'{len(payload):x}\r\n'.encode()
                try:
                    client.sendall(size_line + payload + b'\r\n')
                except OSError:
                    return


@pytest.fixture
def http_unix_server(test_metadata):
    '''Start the mock HTTP server BEFORE logcollector starts so the connect succeeds on first try.'''
    server = HTTPUnixServer(test_metadata['socket_path'])
    server.start()
    yield server
    server.stop()


@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=['http-unix-read-basic'])
def test_read_http_unix_basic(test_configuration, test_metadata, http_unix_server, truncate_monitored_files,
                              configure_local_internal_options, remove_all_localfiles_wazuh_config,
                              set_wazuh_configuration, daemons_handler, wait_for_logcollector_start):
    '''End-to-end: lines published over chunked HTTP arrive as log events, reconnect works after server-side close.'''
    logcollector_utils.check_logcollector_socket()

    wait_for_path_state(test_metadata['socket_path'])

    monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)

    # Stream one event and verify it gets read
    http_unix_server.publish_line('first http-unix event')
    monitor.start(
        callback=callbacks.generate_callback(r".*Reading http-unix message: 'first http-unix event'"),
        timeout=15
    )
    assert monitor.callback_result is not None, 'The first http-unix message was not processed.'

    # Force the server-side connection closed; logcollector should reconnect after reconnect_interval
    http_unix_server.close_connection()
    time.sleep(3)  # ~reconnect_interval + small margin so the worker re-establishes the connection

    http_unix_server.publish_line('after reconnect event')
    monitor.start(
        callback=callbacks.generate_callback(r".*Reading http-unix message: 'after reconnect event'"),
        timeout=15
    )
    assert monitor.callback_result is not None, 'The reader did not recover after server-side close.'
