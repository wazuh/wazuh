# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

"""A stub WPK repository, and a count of what the module asked it for.

The counting is the point. Every claim this subsystem makes about being cheap — one `versions`
fetch and one download for a whole fleet, rather than one of each per agent — is a claim about how
many times the repository was touched, and only the repository can answer that. A unit test can
assert the code takes the branch it expects; it cannot assert that five hundred agents produced one
HTTP request.

TCP rather than a Unix socket, because the module fetches a real URL here — this is the one
connection in the whole module that leaves the machine in production.
"""

import hashlib
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class StubWpkRepository:
    """Serves `versions` files and WPK bodies, and records every request."""

    def __init__(self):
        self._routes = {}
        self._counts = {}
        self._lock = threading.Lock()
        self._server = None
        self._thread = None

    # ---- scripting -------------------------------------------------------------------------

    def publish(self, path: str, body: bytes, status: int = 200):
        """Serve `body` at `path`. `path` includes the leading slash."""
        with self._lock:
            self._routes[path] = (status, body)

    def publish_wpk(self, directory: str, version: str, filename: str, body: bytes):
        """Publish a WPK and the `versions` entry that points at it.

        The digest is computed from the body rather than passed in, so a test cannot accidentally
        assert against a hash of something it is not actually serving.
        """
        digest = hashlib.sha1(body).hexdigest()
        self.publish(f'{directory}versions', f'{version} {digest}\n'.encode())
        self.publish(f'{directory}{filename}', body)
        return digest

    def fail(self, path: str, status: int = 404):
        with self._lock:
            self._routes[path] = (status, b'')

    # ---- observation -----------------------------------------------------------------------

    def count(self, path: str) -> int:
        with self._lock:
            return self._counts.get(path, 0)

    def total(self) -> int:
        with self._lock:
            return sum(self._counts.values())

    def reset_counts(self):
        with self._lock:
            self._counts.clear()

    # ---- lifecycle -------------------------------------------------------------------------

    @property
    def base_url(self) -> str:
        host, port = self._server.server_address
        # Without the scheme the module would prepend https:// and the handshake would fail; these
        # tests are about the repository logic, not about TLS.
        return f'http://{host}:{port}/'

    def start(self):
        repository = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler's spelling
                with repository._lock:
                    repository._counts[self.path] = repository._counts.get(self.path, 0) + 1
                    entry = repository._routes.get(self.path)

                if entry is None:
                    self.send_response(404)
                    self.end_headers()
                    return

                status, body = entry
                self.send_response(status)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                if body:
                    self.wfile.write(body)

            def log_message(self, *_args):
                """Silence the default stderr access log; the counts are the record."""

        self._server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
