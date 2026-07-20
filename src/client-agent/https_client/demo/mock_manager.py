#!/usr/bin/env python3
# Wazuh agent HTTPS client — demo mock manager.
# Copyright (C) 2015, Wazuh Inc.
#
# A tiny TLS "manager" that speaks the proposed #37732/#37733 contract just
# enough to watch the REAL https_client module communicate: it verifies the
# AES-CMAC of every request (via the openssl CLI, so it is an independent
# implementation), then answers /control, /stateless and /stateful. Every
# request is logged so the conversation is visible. A /stateful session that
# is larger than the legacy 64 KB DGRAM cap gets spotlighted, since arriving
# whole in one signed POST is exactly what the new STREAM intake makes possible.
#
# Not production code; a demo harness only.

import argparse
import json
import ssl
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

START = time.time()

# The legacy module->agentd IPC is a DGRAM socket capped at OS_MAXSTR
# (src/shared/include/defs.h), and agent_sync_protocol chunks a sync payload
# at MAX_BATCH_PAYLOAD before sending. The new STREAM intake removes that
# ceiling, so a whole multi-MB session now crosses as ONE signed /stateful POST.
OS_MAXSTR = 65536
MAX_BATCH_PAYLOAD = 60 * 1024


def stamp():
    return f"[+{(time.time() - START) * 1000:7.0f} ms]"


def log(msg):
    print(f"{stamp()} [mock] {msg}", flush=True)


def human_size(n):
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.2f} MB"


def cmac_hex(key_hex, message):
    """AES-CMAC(key, message) as lowercase hex, via the openssl CLI."""
    out = subprocess.run(
        ["openssl", "mac", "-macopt", "cipher:AES-128-CBC",
         "-macopt", f"hexkey:{key_hex}", "CMAC"],
        input=message, capture_output=True, check=True,
    )
    return out.stdout.decode().strip().lower()


class Handler(BaseHTTPRequestHandler):
    key_hex = "000102030405060708090a0b0c0d0e0f"
    notify_count = 0

    def log_message(self, *_):  # silence the default noisy logging
        pass

    def _verify(self, target, body):
        auth = self.headers.get("Authorization", "")
        version = self.headers.get("protocol-version", "")
        if not auth.startswith("Wazuh ") or version != "1":
            return None, "missing/!=1 protocol-version or Authorization"
        try:
            agent_id, ts, mac = auth[len("Wazuh "):].split(":", 2)
        except ValueError:
            return None, "malformed Authorization"
        canonical = (b"WAZUH-REQUEST\n1\nPOST\n" + target.encode() + b"\n"
                     + agent_id.encode() + b"\n" + ts.encode() + b"\n" + body)
        expected = cmac_hex(Handler.key_hex, canonical)
        if expected != mac.lower():
            return None, f"CMAC mismatch (got {mac[:12]}.., want {expected[:12]}..)"
        return (agent_id, ts, mac), None

    def _reply(self, code, payload=None, headers=None):
        body = b"" if payload is None else json.dumps(payload).encode()
        self.send_response(code)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        target = self.path

        identity, err = self._verify(target, body)
        if err:
            log(f"POST {target:<11} -> 401  ({err})")
            self._reply(401, {"error": "unauthorized"})
            return

        agent_id, ts, mac = identity
        preview = body[:70].decode("latin-1").replace("\n", "\\n")
        log(f"POST {target:<11} <- id={agent_id} ts={ts} mac={mac[:10]}.. "
            f"auth OK ({len(body)} B) body='{preview}'")

        if target == "/control":
            self._handle_control(body)
        elif target == "/stateless":
            self._reply(200)
            log(f"     {target:<11} -> 200  (events accepted)")
        elif target == "/stateful":
            self._handle_stateful(body)
        else:
            self._reply(404)

    def _handle_control(self, body):
        try:
            phase = json.loads(body.decode()).get("phase", "?")
        except (ValueError, UnicodeDecodeError):
            phase = "?"

        if phase == "startup":
            handshake = {"limits": {"eps": 0}, "cluster_name": "demo",
                         "cluster_node": "node01", "agent_groups": ["default"],
                         "merged_sum": "d41d8cd98f00b204e9800998ecf8427e"}
            self._reply(200, handshake)
            log(f"     /control    -> 200  STARTUP accepted, sent handshake JSON")
        elif phase == "notify":
            Handler.notify_count += 1
            tasks = []
            if Handler.notify_count == 1:
                # Hand the agent one task on the first Notify so we can watch
                # it dispatch (and dedupe if re-sent).
                tasks = [{"task_id": "018f9a-0001", "type": "active_response",
                          "priority": 1, "payload": {"command": "restart-wazuh"},
                          "created": int(time.time())}]
            response = {"state": {"limits": {"eps": 0}, "merged_sum":
                                  "d41d8cd98f00b204e9800998ecf8427e"},
                        "tasks": tasks, "timestamp": int(time.time())}
            self._reply(200, response)
            log(f"     /control    -> 200  NOTIFY #{Handler.notify_count}, "
                f"tasks={[t['task_id'] for t in tasks]}")
        elif phase == "response":
            self._reply(200)
            log(f"     /control    -> 200  RESPONSE (task results) acked")
        else:
            self._reply(400)

    def _handle_stateful(self, body):
        session = self.headers.get("X-Session-Id", "?")
        module, payload_start = self._parse_session_header(body)
        items = max(0, len(body) - payload_start)
        self._reply(200, {"status": "success", "sessionId": session,
                          "itemsProcessed": items})
        log(f"     /stateful   -> 200  session={session} "
            f"module={module} itemsProcessed={items}")
        if len(body) > OS_MAXSTR:
            self._announce_large_session(body, payload_start)

    def _parse_session_header(self, body):
        """Return (module, payload_start) from a 'FULLSESSION:<module>:' prefix."""
        if not body.startswith(b"FULLSESSION:"):
            return "?", 0
        colon = body.find(b":", len("FULLSESSION:"))
        if colon < 0:
            return "?", 0
        return body[len("FULLSESSION:"):colon].decode("latin-1"), colon + 1

    def _announce_large_session(self, body, payload_start):
        size = len(body)
        chunks = -(-size // MAX_BATCH_PAYLOAD)  # ceil
        intact = body.count(b"D", payload_start) == size - payload_start
        log("──[ LARGE SESSION ]── streamed whole over the new intake socket ──")
        log(f"     {human_size(size)} ({size} B) arrived as ONE CMAC-signed POST")
        log(f"     = {size / OS_MAXSTR:.0f}x the 64 KB OS_MAXSTR DGRAM cap; the legacy")
        log(f"       chunked path would need {chunks} x 60 KB datagrams reassembled")
        log(f"     payload byte-exact after streaming: {'yes' if intact else 'NO'}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=27860)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--key-hex", default="000102030405060708090a0b0c0d0e0f")
    args = parser.parse_args()

    Handler.key_hex = args.key_hex
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    log(f"HTTPS manager on https://127.0.0.1:{args.port} "
        f"(agent key {args.key_hex[:8]}..)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    sys.exit(main())
