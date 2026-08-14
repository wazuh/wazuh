"""HTTP/1.1-over-UDS client for the inventory_sync_server QA suite.

Speaks the exact bytes remoted puts on the wire: AF_UNIX stream, Content-Length
delimited, one request per connection (Connection: close). Standard library only.
"""

import http.client
import json
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
            headers = {
                "Host": "localhost",
                "Connection": "close",
                "Content-Length": str(len(body)),
            }
            if content_type:
                headers["Content-Type"] = content_type
            if agent_id is not None:
                # What remoted sets from the identity it authenticated over AES-CMAC.
                headers["X-Wazuh-Agent-Id"] = agent_id

            # Head and body go out in ONE write, deliberately -- do not go back to
            # http.client's connection.request(), which sends them as two separate
            # sendall() calls. The server decides 404/405/411/413/503 at
            # headers-complete and closes WITHOUT draining the body (see the INTEROP
            # NOTE in asioUdsHttpServer.cpp: draining a refused body would let a peer
            # dictate how long the server spends on it). With two writes, that close
            # can beat the body write and the peer gets EPIPE instead of the status;
            # with one write a body this size is already in the socket buffer, so the
            # status is always readable. This is also what the C++ transport tests do
            # (peerRequest()/sendRaw() in udsHttpServer_test.cpp).
            connection.connect()
            head = f"{method} {path} HTTP/1.1\r\n" + "".join(f"{name}: {value}\r\n"
                                                             for name, value in headers.items())
            connection.sock.sendall(head.encode("ascii") + b"\r\n" + body)

            raw = http.client.HTTPResponse(connection.sock, method=method)
            raw.begin()
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

    def post_config(self, report, agent_id):
        """An agent's reported configuration -> one wazuh-agent-config document."""
        return self._request("POST", "/config", body=json.dumps(report).encode(),
                             agent_id=agent_id, content_type="application/json")

    def post_stats(self, report, agent_id):
        """An agent's reported statistics -> one wazuh-agent-stats document."""
        return self._request("POST", "/stats", body=json.dumps(report).encode(),
                             agent_id=agent_id, content_type="application/json")

    def delete_agent(self, agent_id):
        return self._request("DELETE", "/agents", agent_id=agent_id)

    def post_delete_agent_alias(self, agent_id):
        """The POST alias C callers use (uhttp only speaks POST)."""
        return self._request("POST", "/agents/delete", agent_id=agent_id)
