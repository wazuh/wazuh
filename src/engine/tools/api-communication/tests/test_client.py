# SPDX-License-Identifier: AGPL-3.0-or-later
"""APIClient against a Unix-socket HTTP server that answers like the engine's API server.

The server answers some requests itself, before any endpoint handler runs (unknown path, wrong method, busy, body
too large, a handler that threw); those answers must reach the caller as errors, never as responses to parse. An
endpoint handler's own error answer (a protobuf JSON with a "status" field) keeps reaching the caller as before.
"""
import http.server
import os
import socketserver
import tempfile
import threading

import pytest

from api_communication.client import APIClient
from api_communication.proto import geo_pb2

# One canned answer per test: (status, content type, body).
_answer = {}


class _Handler(http.server.BaseHTTPRequestHandler):
    def _reply(self):
        length = int(self.headers.get('Content-Length', 0))
        if length:
            self.rfile.read(length)
        status, content_type, body = _answer['value']
        payload = body.encode()
        self.send_response(status)
        if content_type:
            self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(payload)

    do_GET = _reply
    do_POST = _reply
    do_DELETE = _reply

    def address_string(self):
        return 'uds'

    def log_message(self, *args):
        pass


class _UnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


@pytest.fixture(scope='module')
def client():
    directory = tempfile.mkdtemp(prefix='api_client_test_')
    path = os.path.join(directory, 'api.sock')
    server = _UnixHTTPServer(path, _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield APIClient(path)
    server.shutdown()
    server.server_close()
    os.unlink(path)
    os.rmdir(directory)


def _send_recv(client):
    return client.send_recv(geo_pb2.DbList_Request())


def _jsend(client):
    return client.jsend({}, geo_pb2.DbList_Request())


CALLS = [pytest.param(_send_recv, id='send_recv'), pytest.param(_jsend, id='jsend')]

JSON = 'application/json'


@pytest.mark.parametrize('call', CALLS)
@pytest.mark.parametrize(
    'answer, expected_error',
    [
        pytest.param((404, JSON, '{"error":"Unknown endpoint","code":404}'), 'Error 404: Unknown endpoint',
                     id='unknown-path-404'),
        pytest.param((405, JSON, '{"error":"Method not allowed for this endpoint","code":405}'),
                     'Error 405: Method not allowed for this endpoint', id='wrong-method-405'),
        pytest.param((503, JSON, '{"error":"Server busy","code":503}'), 'Error 503: Server busy', id='busy-503'),
        pytest.param((503, JSON, '{"error":"Server shutting down","code":503}'), 'Error 503: Server shutting down',
                     id='stopping-503'),
        pytest.param((504, JSON, '{"error":"Handler did not respond in time","code":504}'),
                     'Error 504: Handler did not respond in time', id='timeout-504'),
        pytest.param((413, 'text/plain', 'Payload too large. Max allowed: 1024 bytes (1 KiB).'),
                     'Payload too large. Max allowed: 1024 bytes (1 KiB).', id='too-large-413'),
        pytest.param((500, 'text/plain', 'Internal server error'), 'Error 500: Internal server error',
                     id='handler-threw-500'),
        pytest.param((502, None, ''), 'Error 502 while sending request', id='empty-body'),
    ],
)
def test_server_answers_are_errors(client, call, answer, expected_error):
    _answer['value'] = answer
    error, response = call(client)
    assert error == expected_error
    assert response == {}


def test_send_recv_returns_a_handler_error_answer_as_before(client):
    # An endpoint handler's own error is a protobuf JSON with "status": the caller reads it from the response.
    _answer['value'] = (400, JSON, '{"status":"ERROR","error":"Missing /name"}')
    error, response = _send_recv(client)
    assert error is None
    assert response == {'status': 'ERROR', 'error': 'Missing /name'}


def test_jsend_reports_a_handler_error_answer_as_before(client):
    _answer['value'] = (400, JSON, '{"status":"ERROR","error":"Missing /name"}')
    error, response = _jsend(client)
    assert error == 'Missing /name'
    assert response == {}


@pytest.mark.parametrize('call', CALLS)
def test_success_is_returned(client, call):
    _answer['value'] = (200, JSON, '{"status":"OK"}')
    error, response = call(client)
    assert error is None
    assert response == {'status': 'OK'}
