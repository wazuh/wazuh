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
import hashlib
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
    """AES-CMAC(key, message) as lowercase hex, via the openssl CLI. The
    cipher follows the key length (16/24/32 bytes -> AES-128/192/256), the
    same rule as the manager's client.keys resolver."""
    cipher = {32: "AES-128-CBC", 48: "AES-192-CBC", 64: "AES-256-CBC"}[len(key_hex)]
    out = subprocess.run(
        ["openssl", "mac", "-macopt", f"cipher:{cipher}",
         "-macopt", f"hexkey:{key_hex}", "CMAC"],
        input=message, capture_output=True, check=True,
    )
    return out.stdout.decode().strip().lower()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # chunked /download needs 1.1
    key_hex = "000102030405060708090a0b0c0d0e0f"
    notify_count = 0

    # Timeline (driven by the notify counter): the config flips first (the
    # client detects the new config_hash and pulls it via /download), the
    # settings flip later (the client re-sends startup for fresh limits).
    CONFIG_FLIP_AT = 3
    SETTINGS_FLIP_AT = 5

    # /stateless payload cap: a bigger body gets 413, so the client must split
    # and resend smaller (#37835). Small here so the burst in sustained mode
    # triggers it visibly.
    STATELESS_MAX_BODY = 2048

    # Credential rotation (#37828): after this notify the mock verifies ONLY
    # against ROTATED_KEY, so the agent's old key starts getting 401 and must
    # re-enroll. The demo driver swaps to ROTATED_KEY via hc_set_agent_key.
    ROTATE_KEY_AT = 7
    ROTATED_KEY = "0f0e0d0c0b0a09080706050403020100"

    # Exact startup-response bytes, kept verbatim: settings_hash is the SHA256
    # of precisely what goes on the wire (#37733 5.1.1).
    #
    # Every field the bridge's parser marks required has to be here: it takes
    # the limits all-or-nothing, and a partial block is silently discarded.
    # syscheckd then waits on limits that never arrive (fim_initialize()'s
    # fetch_document_limits_from_agentd() loop) and never finishes starting.
    STARTUP_V1 = json.dumps(
        {"limits": {"fim": {"file": 100000, "registry_key": 100000,
                            "registry_value": 100000},
                    "syscollector": {"hotfixes": 10000, "packages": 50000,
                                     "processes": 10000, "ports": 10000,
                                     "network_iface": 10000, "network_protocol": 10000,
                                     "network_address": 10000, "hardware": 10000,
                                     "os_info": 10000, "users": 10000,
                                     "groups": 10000, "services": 10000,
                                     "browser_extensions": 10000},
                    "sca": {"checks": 10000}},
         "cluster": {"name": "demo"},
         "agent": {"groups": ["default"]}}).encode()
    STARTUP_V2 = json.dumps(
        {"limits": {"fim": {"file": 200000, "registry_key": 100000,
                            "registry_value": 100000},
                    "syscollector": {"hotfixes": 10000, "packages": 50000,
                                     "processes": 10000, "ports": 10000,
                                     "network_iface": 10000, "network_protocol": 10000,
                                     "network_address": 10000, "hardware": 10000,
                                     "os_info": 10000, "users": 10000,
                                     "groups": 10000, "services": 10000,
                                     "browser_extensions": 10000},
                    "sca": {"checks": 20000}},
         "cluster": {"name": "demo"},
         "agent": {"groups": ["default"]}}).encode()

    # merged.mg v1 is empty: its SHA-256 (e3b0c442...) equals the hash the
    # demo driver seeds, so the agent starts in sync and the flip is visible.
    CONFIG_V1 = b""
    CONFIG_V2 = (b"# merged.mg v2, regenerated by the mock manager\n"
                 b"<agent_config>\n  <labels><label key=\"env\">demo</label></labels>\n"
                 b"</agent_config>\n")

    @classmethod
    def _startup_body(cls):
        return cls.STARTUP_V2 if cls.notify_count >= cls.SETTINGS_FLIP_AT else cls.STARTUP_V1

    @classmethod
    def _config_blob(cls):
        return cls.CONFIG_V2 if cls.notify_count >= cls.CONFIG_FLIP_AT else cls.CONFIG_V1

    def _log_tls_once(self):
        """Print what the handshake actually negotiated, once per connection.

        This is the observable half of <ssl><certificate>/<key>: the agent's config
        is only proven to have a runtime effect if the manager can see the client
        cert it presented. The negotiated suite is logged alongside it so the TLS
        version in use is visible, not because this demo restricts it (#38163).
        """
        if getattr(self, "_tls_logged", False):
            return
        self._tls_logged = True
        conn = self.connection
        cipher = conn.cipher() if hasattr(conn, "cipher") else None
        peer = conn.getpeercert() if hasattr(conn, "getpeercert") else None
        if cipher:
            log(f"TLS  cipher={cipher[0]} proto={cipher[1]}")
        if peer:
            subject = dict(x[0] for x in peer.get("subject", ()))
            log(f"TLS  client cert presented: subject={subject}")
        elif getattr(self.server, "requires_client_cert", False):
            log("TLS  client cert REQUIRED but none presented")

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
        active_key = (Handler.ROTATED_KEY
                      if Handler.notify_count >= Handler.ROTATE_KEY_AT
                      else Handler.key_hex)
        expected = cmac_hex(active_key, canonical)
        if expected != mac.lower():
            return None, f"CMAC mismatch (got {mac[:12]}.., want {expected[:12]}.. - rotated?)"
        return (agent_id, ts, mac), None

    def _reply(self, code, payload=None, headers=None):
        body = b"" if payload is None else json.dumps(payload).encode()
        self._reply_raw(code, body, headers=headers)

    def _reply_raw(self, code, body, content_type="application/json", headers=None):
        self.send_response(code)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _reply_chunked(self, blob, content_type="application/octet-stream"):
        # Hand-rolled chunked transfer (#37733 5.2.3): size line in hex, the
        # chunk, CRLF; a zero-size chunk terminates.
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        chunk_size = 16 * 1024
        for offset in range(0, len(blob), chunk_size):
            piece = blob[offset:offset + chunk_size]
            self.wfile.write(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
        self.wfile.write(b"0\r\n\r\n")

    def do_POST(self):
        self._log_tls_once()
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
            self._handle_stateless(body)
        elif target == "/stateful":
            self._handle_stateful(body)
        elif target == "/download":
            self._handle_download(body)
        elif target in ("/stats", "/config"):
            self._handle_report(target, body)
        else:
            self._reply(404)

    def _handle_control(self, body):
        try:
            msg_type = json.loads(body.decode()).get("type", "?")
        except (ValueError, UnicodeDecodeError):
            msg_type = "?"

        if msg_type == "startup":
            self._control_startup()
        elif msg_type == "notify":
            self._control_notify()
        elif msg_type == "shutdown":
            self._reply(200, {})
            log("     /control    -> 200  SHUTDOWN received - marking agent disconnected")
        else:
            self._reply(400)
            log(f"     /control    -> 400  (unknown type '{msg_type}')")

    def _control_startup(self):
        # 5.1.1: exact stored bytes (their SHA256 is the settings_hash).
        body = self._startup_body()
        version = "v2" if body is Handler.STARTUP_V2 else "v1"
        self._reply_raw(200, body)
        log(f"     /control    -> 200  STARTUP accepted ({version} settings)")

    def _control_notify(self):
        Handler.notify_count += 1
        n = Handler.notify_count
        blob = self._config_blob()
        startup = self._startup_body()
        response = {"agent": {"groups": ["default"],
                              "config_hash": hashlib.sha256(blob).hexdigest()},
                    "settings_hash": hashlib.sha256(startup).hexdigest()}
        if n == 2:
            # Deliberately shuffled 4-type batch (#37733: all fire-and-forget):
            # the client dispatches AR then upgrade; restart and reload are
            # covered by the upgrade and dropped with a log line.
            response["tasks"] = [
                {"task_id": "018f9a-0003", "task_type": "agent_restart",
                 "payload": {}},
                {"task_id": "018f9a-0001", "task_type": "active_response",
                 "payload": {"wazuh": {"active_response": {
                     "name": "firewall-drop", "executable": "firewall-drop",
                     "extra_arguments": "192.168.1.100"}},
                     "rule": {"id": 5503}}},
                {"task_id": "018f9a-0005", "task_type": "remote_upgrade",
                 "payload": {"wpk_file": "wazuh_agent_v5.1.0_linux_x86_64.wpk",
                             "wpk_sha1": "a1b2c3d4e5f6",
                             "installer": "upgrade.sh"}},
                {"task_id": "018f9a-0004", "task_type": "agent_reload",
                 "payload": {}},
            ]
        self._reply(200, response)
        markers = []
        if n == Handler.CONFIG_FLIP_AT:
            markers.append("CONFIG FLIPPED (new config_hash)")
        if n == Handler.SETTINGS_FLIP_AT:
            markers.append("SETTINGS FLIPPED (new settings_hash)")
        if n == Handler.ROTATE_KEY_AT:
            markers.append("KEY ROTATED - old key now 401s, agent must re-enroll")
        tasks = [t["task_id"] for t in response.get("tasks", [])]
        marker = (" <- " + ", ".join(markers)) if markers else ""
        log(f"     /control    -> 200  NOTIFY #{n} "
            f"cfg={response['agent']['config_hash'][:8]}.. "
            f"set={response['settings_hash'][:8]}.. tasks={tasks}{marker}")

    def _handle_download(self, body):
        # 5.2: signed request for a resource, chunked octet-stream back.
        try:
            request = json.loads(body.decode())
        except (ValueError, UnicodeDecodeError):
            request = {}
        blob = self._config_blob()
        log(f"     /download   <- resource_type={request.get('resource_type')} "
            f"resource_id={request.get('resource_id')}")
        self._reply_chunked(blob)
        log(f"     /download   -> 200  chunked, {len(blob)} B "
            f"(sha256 {hashlib.sha256(blob).hexdigest()[:8]}..)")

    def _handle_stateless(self, body):
        if len(body) > Handler.STATELESS_MAX_BODY:
            self._reply(413, {"error": "payload too large"})
            log(f"     /stateless  -> 413  ({len(body)} B > "
                f"{Handler.STATELESS_MAX_BODY} B cap; client halves + resends)")
            return
        events = body.count(b"\nE ") + (1 if b"\nE " not in body and b"E " in body else 0)
        self._reply(200)  # 200 with an empty body per #37732
        log(f"     /stateless  -> 200  ({len(body)} B, ~{events} events accepted)")

    def _handle_report(self, target, body):
        # /stats and /config (#37843): the agent pushes a full snapshot the
        # module stamped with agent_id + cluster; the manager stores it.
        try:
            doc = json.loads(body.decode())
        except (ValueError, UnicodeDecodeError):
            doc = {}
        self._reply(200, {})
        cluster = doc.get("cluster", {})
        log(f"     {target:<11} -> 200  stored: agent_id={doc.get('agent_id')} "
            f"cluster={cluster.get('name')} keys={sorted(doc.keys())}")
        # The whole document, for the field-contract comparison against the
        # manager side (#38136). The preview in do_POST() truncates at 70 bytes,
        # which is not enough to see the per-module bodies.
        log(f"     {target} FULL BODY: {json.dumps(doc, sort_keys=True)}")

    def _handle_stateful(self, body):
        session = self.headers.get("X-Session-Id", "?")
        module, payload_start = self._parse_session_header(body)
        payload = body[payload_start:]
        # A FIM session carries one JSON entry per line; count entries, not bytes.
        items = payload.count(b"\n") if module == "fim" else len(payload)
        self._reply(200, {"status": "success", "sessionId": session,
                          "itemsProcessed": items})
        log(f"     /stateful   -> 200  session={session} "
            f"module={module} itemsProcessed={items}")
        if len(body) > OS_MAXSTR:
            self._announce_large_session(body, payload_start, module)

    def _parse_session_header(self, body):
        """Return (module, payload_start) from a 'FULLSESSION:<module>:' prefix."""
        if not body.startswith(b"FULLSESSION:"):
            return "?", 0
        colon = body.find(b":", len("FULLSESSION:"))
        if colon < 0:
            return "?", 0
        return body[len("FULLSESSION:"):colon].decode("latin-1"), colon + 1

    def _announce_large_session(self, body, payload_start, module):
        size = len(body)
        chunks = -(-size // MAX_BATCH_PAYLOAD)  # ceil
        log("──[ LARGE SESSION ]── streamed whole over the new intake socket ──")
        log(f"     {human_size(size)} ({size} B) arrived as ONE CMAC-signed POST")
        log(f"     = {size / OS_MAXSTR:.0f}x the 64 KB OS_MAXSTR DGRAM cap; the legacy")
        log(f"       chunked path would need {chunks} x 60 KB datagrams reassembled")
        if module == "fim":
            self._announce_fim_payload(body, payload_start)
        else:
            intact = body.count(b"D", payload_start) == size - payload_start
            log(f"     payload byte-exact after streaming: {'yes' if intact else 'NO'}")

    def _announce_fim_payload(self, body, payload_start):
        """Parse the received FIM entries and print the same additive checksum
        the producer printed: equal values mean the sync arrived byte-exact."""
        lines = body[payload_start:].splitlines()
        parsed = 0
        for line in lines:
            try:
                json.loads(line)
                parsed += 1
            except ValueError:
                break
        first = json.loads(lines[0])["path"] if parsed else "?"
        last = json.loads(lines[-1])["path"] if parsed == len(lines) else "?"
        health = "all valid JSON" if parsed == len(lines) else f"INVALID at line {parsed}"
        checksum = sum(body) & 0xFFFFFFFF
        log(f"     FIM entries: {len(lines)} ({health})")
        log(f"     first={first}  last={last}")
        log(f"     checksum 0x{checksum:08x} (must match the producer's printed checksum)")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=27860)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--key-hex", default="000102030405060708090a0b0c0d0e0f")
    # Exists for the connection/config validation (#38163): the agent's
    # <ssl><certificate>/<key> can only be shown to have a runtime effect against a
    # manager that actually demands a client certificate.
    parser.add_argument("--client-ca",
                        help="Require a client certificate and verify it against this CA "
                             "(mutual TLS). Without it, client certs are not requested.")
    args = parser.parse_args()

    Handler.key_hex = args.key_hex
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)

    # Same floor remoted enforces (SSL_CTX_set_min_proto_version in
    # RestinioHttpServer), so the demo negotiates what a real manager would.
    #
    # There is deliberately no --ciphers here. Restricting the suites would mean
    # SSL_CTX_set_ciphersuites(), which Python's ssl module does not expose:
    # set_ciphers() governs TLS 1.2 and below only and rejects 1.3 suite names
    # outright. The one way to make a restriction observable was to cap the
    # server at TLS 1.2, which an agent that requires 1.3 can no longer reach --
    # the handshake would fail before any suite was chosen. <ssl><ciphers> is
    # therefore validated against a real manager, not here.
    context.minimum_version = ssl.TLSVersion.TLSv1_3

    if args.client_ca:
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(args.client_ca)

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.requires_client_cert = bool(args.client_ca)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    log(f"HTTPS manager on https://127.0.0.1:{args.port} "
        f"(agent key {args.key_hex[:8]}..)")
    log(f"     mutual TLS: {'required, CA ' + args.client_ca if args.client_ca else 'not requested'}")
    log(f"     min TLS:    1.3")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    sys.exit(main())
