"""HTTP/1.1-over-UDS client for the inventory_sync_server QA suite.

Speaks the exact bytes remoted puts on the wire: AF_UNIX stream, Content-Length
delimited, one request per connection (Connection: close). Standard library only.
"""

import http.client
import socket


class UnixHTTPConnection(http.client.HTTPConnection):
    """http.client over an AF_UNIX stream socket."""

    def __init__(self, socket_path, timeout=30):
        super().__init__("localhost", timeout=timeout)
        self._socket_path = socket_path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._socket_path)
        self.sock = sock


class Response:
    """Status, headers (lower-cased names) and raw body of one exchange."""

    def __init__(self, status, headers, body):
        self.status = status
        self.headers = {name.lower(): value for name, value in headers}
        self.body = body

    def __repr__(self):
        return f"Response(status={self.status}, body={self.body[:200]!r})"


class ServerClient:
    """One method per route the server exposes."""

    def __init__(self, socket_path, timeout=30):
        self.socket_path = socket_path
        self.timeout = timeout

    def _request(self, method, path, body=b"", agent_id=None, content_type="application/octet-stream",
                 timeout=None):
        connection = UnixHTTPConnection(self.socket_path, timeout=timeout or self.timeout)
        try:
            headers = {"Host": "localhost", "Connection": "close"}
            if content_type:
                headers["Content-Type"] = content_type
            if agent_id is not None:
                # What remoted sets from the identity it authenticated over AES-CMAC.
                headers["X-Wazuh-Agent-Id"] = agent_id
            connection.request(method, path, body=body, headers=headers)
            raw = connection.getresponse()
            return Response(raw.status, raw.getheaders(), raw.read())
        finally:
            connection.close()

    def health(self):
        return self._request("GET", "/", content_type=None)

    def metrics(self):
        return self._request("GET", "/metrics", content_type=None)

    def post_stateful(self, session_bytes, agent_id, timeout=None):
        """One whole synchronization session; the response IS the result."""
        return self._request("POST", "/stateful", body=session_bytes, agent_id=agent_id, timeout=timeout)

    def delete_agent(self, agent_id):
        return self._request("DELETE", "/agents", agent_id=agent_id)

    def post_delete_agent_alias(self, agent_id):
        """The POST alias C callers use (uhttp only speaks POST)."""
        return self._request("POST", "/agents/delete", agent_id=agent_id)
