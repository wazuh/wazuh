#!/usr/bin/env python3
# Wazuh agent HTTPS client — demo mock manager.
# Copyright (C) 2015, Wazuh Inc.
#
# A tiny TLS "manager" that speaks the proposed #37732/#37733 contract just
# enough to watch the REAL https_client module communicate: it verifies the
# wazuh-agent+jwt bearer token of every request (HS256 with the standard
# library, so it is an independent implementation), then answers /control,
# /stateless and /stateful. Every
# request is logged so the conversation is visible. A /stateful session that
# is larger than the legacy 64 KB DGRAM cap gets spotlighted, since arriving
# whole in one signed POST is exactly what the new STREAM intake makes possible.
#
# Not production code; a demo harness only.

import argparse
import base64
import hashlib
import hmac
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


ENROLL_HKDF_INFO = b"WAZUH-ENROLL-JWT-KEY" + b"\x01"


def hkdf_sha256(password, length=32, info=ENROLL_HKDF_INFO):
    """HKDF-SHA256(IKM=password, salt=32 zero bytes, info="WAZUH-ENROLL-JWT-KEY"+0x01): the
    wazuh-enroll+jwt key, via the stdlib hmac/hashlib, independent of the C++
    enrollKeyDerivation.hpp it verifies (the frozen KAT in jwt_vectors.json "enroll.hkdf" was
    itself derived this way -- see enrollSigner_test.cpp)."""
    salt = bytes(32)
    prk = hmac.new(salt, password, hashlib.sha256).digest()
    okm = b""
    previous = b""
    counter = 1
    while len(okm) < length:
        previous = hmac.new(prk, previous + info + bytes([counter]), hashlib.sha256).digest()
        okm += previous
        counter += 1
    return okm[:length]


def zstd_decompress(data):
    """Decompress a zstd frame via the `zstd` CLI (independent of the agent's
    own libzstd linkage, reuse-a-real-CLI idiom). Returns
    the original bytes, or None if `data` isn't a valid zstd frame."""
    try:
        out = subprocess.run(["zstd", "-d", "-c"], input=data, capture_output=True, check=True)
        return out.stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # chunked /download needs 1.1
    key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
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
    # re-enroll. The demo driver swaps to ROTATED_KEY via hc_set_agent_identity.
    ROTATE_KEY_AT = 7

    # key_hash (#38465) exists precisely so a re-enrolling agent that already
    # has an entry is recognized as the SAME identity, not reassigned a new
    # one: hc_set_agent_identity() (the module's #37828 credential-rotation path)
    # only ever refreshes the key material on a live handle, by design --
    # there is no ABI to also change its cached agent_id. A mock (or a real
    # manager) that mints a fresh id on every /enroll regardless of key_hash
    # would silently desync the module's id from what's on disk.
    KEY_HASH_TO_ID = {}
    ROTATED_KEY = "0f0e0d0c0b0a090807060504030201001f1e1d1c1b1a19181716151413121110"

    # #38465: empty (default) -> /enroll accepts any request carrying
    # protocol-version, no signature required (open mode). Non-empty ->
    # /enroll additionally requires Authorization: Bearer <wazuh-enroll+jwt>
    # verified against the HKDF key of this password. ENROLL_STATUS != 0 forces
    # every /enroll response to that status with a generic error body, so the
    # C-side 400/401/403/409/500/503 mapping (w_enrollment_process_response)
    # can be driven on demand without five separate mocks.
    ENROLL_PASSWORD = ""
    ENROLL_STATUS = 0
    ENROLL_NEXT_ID = 100

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
        """The manager's wazuh-agent+jwt check, in stdlib: Bearer HS256 over
        exactly {alg,kid,typ} / {exp,iat,iss,jti,nbf,sub}, keyed with the 32
        bytes the 64-hex client.keys secret decodes to. The target and the body
        play no part (identity only)."""
        del target, body
        auth = self.headers.get("Authorization", "")
        version = self.headers.get("protocol-version", "")
        if not auth.startswith("Bearer ") or version != "1":
            return None, "missing/!=1 protocol-version or Authorization"
        active_key = (Handler.ROTATED_KEY
                      if Handler.notify_count >= Handler.ROTATE_KEY_AT
                      else Handler.key_hex)
        try:
            h64, p64, s64 = auth[len("Bearer "):].split(".")
            pad = lambda x: x + "=" * (-len(x) % 4)
            header = json.loads(base64.urlsafe_b64decode(pad(h64)))
            claims = json.loads(base64.urlsafe_b64decode(pad(p64)))
            sig = base64.urlsafe_b64decode(pad(s64))
        except (ValueError, json.JSONDecodeError):
            return None, "malformed Authorization"
        if header != {"alg": "HS256", "kid": claims.get("sub"), "typ": "wazuh-agent+jwt"}:
            return None, f"unexpected header {header}"
        if set(claims) != {"exp", "iat", "iss", "jti", "nbf", "sub"}:
            return None, f"unexpected claim set {sorted(claims)}"
        expected = hmac.new(bytes.fromhex(active_key), f"{h64}.{p64}".encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, sig):
            return None, f"signature mismatch (kid {claims.get('sub')} - rotated?)"
        now = int(time.time())
        if not (claims["nbf"] == claims["iat"] and 0 < claims["exp"] - claims["iat"] <= 60):
            return None, "structural time rules violated"
        if claims["iat"] > now + 30 or now > claims["exp"] + 30 or now - claims["iat"] > 90:
            return None, f"token outside the time window (iat {claims['iat']}, now {now})"
        if claims["iss"] != "wazuh-agent/" + claims["sub"]:
            return None, "iss/sub mismatch"
        return (claims["sub"], claims["iat"], claims["jti"]), None

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

        # /enroll predates any client.keys identity (that is the whole point:
        # it is how one gets minted) -- it cannot go through the generic
        # Bearer _verify() below, which requires an id the
        # agent does not have yet. It carries its own wazuh-enroll+jwt bearer.
        if target == "/enroll":
            self._handle_enroll(body)
            return

        identity, err = self._verify(target, body)
        if err:
            log(f"POST {target:<11} -> 401  ({err})")
            self._reply(401, {"error": "unauthorized"})
            return

        agent_id, ts, jti = identity

        # Authentication never looked at the (possibly compressed) wire bytes, same
        # as /enroll -- decompress only now, for the handlers below, which
        # all expect plain JSON/text content.
        if self.headers.get("Content-Encoding", "") == "zstd":
            decompressed = zstd_decompress(body)
            if decompressed is None:
                log(f"POST {target:<11} -> 400  (bad zstd frame)")
                self._reply(400, {"error": "bad zstd frame"})
                return
            body = decompressed

        preview = body[:70].decode("latin-1", errors="replace").replace("\n", "\\n")
        log(f"POST {target:<11} <- id={agent_id} iat={ts} jti={jti[:10]}.. "
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
        # config_token is what the agent must echo back as /download's resource_id. It is
        # opaque to the agent, so this value is deliberately not the group name -- seeing it
        # in the /download log below proves the agent relayed the token instead of deriving a
        # selector from agent.groups on its own.
        response = {"agent": {"groups": ["default"],
                              "config_token": "cfg-token-abc123",
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

    def _verify_enroll(self, body):
        """Returns None on success, or an error string. Open mode (no
        ENROLL_PASSWORD configured) accepts any request with protocol-version
        present; password mode additionally checks Authorization: Bearer
        <wazuh-enroll+jwt> -- header exactly {alg: HS256, typ: wazuh-enroll+jwt}
        (no kid), claims exactly {exp, iat, jti, nbf}, HS256 with the HKDF key
        of the password (see hkdf_sha256), same time rules as the agent bearer."""
        del body  # The token does not cover the body (TLS does).
        if self.headers.get("protocol-version", "") != "1":
            return "missing/!=1 protocol-version"
        if not Handler.ENROLL_PASSWORD:
            return None
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return "missing Bearer Authorization header"
        parts = auth[len("Bearer "):].split(".")
        if len(parts) != 3 or not all(parts):
            return "malformed token"

        def b64d(segment):
            return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))

        try:
            header = json.loads(b64d(parts[0]))
            claims = json.loads(b64d(parts[1]))
            signature = b64d(parts[2])
        except (ValueError, UnicodeDecodeError):
            return "malformed token segments"
        if header != {"alg": "HS256", "typ": "wazuh-enroll+jwt"}:
            return f"header is not exactly the enroll profile: {header}"
        key = hkdf_sha256(Handler.ENROLL_PASSWORD.encode())
        expected = hmac.new(key, (parts[0] + "." + parts[1]).encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, signature):
            return "signature mismatch (wrong password?)"
        if set(claims) != {"exp", "iat", "jti", "nbf"}:
            return f"claims are not exactly the enroll profile: {sorted(claims)}"
        if not all(isinstance(claims[k], int) for k in ("exp", "iat", "nbf")):
            return "non-integer time claim"
        now = int(time.time())
        if claims["nbf"] != claims["iat"] or not 0 < claims["exp"] - claims["iat"] <= 60:
            return "structural time rule broken"
        if claims["iat"] > now + 30 or now > claims["exp"] + 30 or now - claims["iat"] > 90:
            return "token outside the accepted time window"
        log(f"     /enroll     bearer ok iat={claims['iat']} jti={claims['jti'][:10]}..")
        return None

    def _handle_enroll(self, body):
        compressed = self.headers.get("Content-Encoding", "") == "zstd"
        preview = body[:120].decode("latin-1", errors="replace").replace("\n", "\\n")
        log(f"POST /enroll     <- ({len(body)} B{', zstd' if compressed else ''}) body='{preview}'")

        if Handler.ENROLL_STATUS:
            self._reply(Handler.ENROLL_STATUS,
                        {"error": {"code": "forced", "message": "forced by --enroll-status"}})
            log(f"     /enroll     -> {Handler.ENROLL_STATUS}  (forced by --enroll-status)")
            return

        # The token does not cover the wire bytes (compressed or not, #38465
        # D7) -- verify against the raw body exactly as received, same as
        # every other endpoint. Only the JSON parsing below needs the
        # decompressed content.
        err = self._verify_enroll(body)
        if err:
            self._reply(401, {"error": {"code": "invalid_signature", "message": err}})
            log(f"     /enroll     -> 401  ({err})")
            return

        payload = body
        if compressed:
            decompressed = zstd_decompress(body)
            if decompressed is None:
                self._reply(400, {"error": {"code": "invalid_body", "message": "bad zstd frame"}})
                log("     /enroll     -> 400  (bad zstd frame)")
                return
            payload = decompressed

        try:
            request = json.loads(payload.decode())
        except (ValueError, UnicodeDecodeError):
            self._reply(400, {"error": {"code": "invalid_body", "message": "malformed JSON"}})
            log("     /enroll     -> 400  (malformed JSON)")
            return

        key_hash = request.get("key_hash")
        agent_id = Handler.KEY_HASH_TO_ID.get(key_hash) if key_hash else None
        if agent_id is None:
            Handler.ENROLL_NEXT_ID += 1
            agent_id = f"{Handler.ENROLL_NEXT_ID:03d}"
            if key_hash:
                Handler.KEY_HASH_TO_ID[key_hash] = agent_id
        name = request.get("name", "unknown")
        # Must match whatever _verify() checks the bearer against right now: if a
        # key rotation (ROTATE_KEY_AT) already happened, handing back the
        # pre-rotation key_hex would make the agent re-enroll, get the same
        # already-invalid key, 401 again, and loop forever -- indistinguishable
        # from a real bug on the agent side unless this endpoint tracks the
        # same rotation state.
        active_key = (Handler.ROTATED_KEY
                      if Handler.ROTATE_KEY_AT > 0 and Handler.notify_count >= Handler.ROTATE_KEY_AT
                      else Handler.key_hex)
        response = {"id": agent_id, "name": name, "ip": request.get("ip", "any"),
                   "key": active_key}
        self._reply(200, response)
        log(f"     /enroll     -> 200  minted id={agent_id} name={name} "
            f"groups={request.get('groups')} key_hash={request.get('key_hash')}")

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
        log(f"     {human_size(size)} ({size} B) arrived as ONE bearer-authenticated POST")
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
    parser.add_argument("--bind", default="127.0.0.1",
                        help="Listen address. Default 127.0.0.1 (single-machine demo); use "
                             "0.0.0.0 to accept real agents on other hosts on the LAN.")
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--key-hex", default="000102030405060708090a0b0c0d0e0f")
    # Exists for the connection/config validation (#38163): the agent's
    # <ssl><certificate>/<key> can only be shown to have a runtime effect against a
    # manager that actually demands a client certificate.
    parser.add_argument("--client-ca",
                        help="Require a client certificate and verify it against this CA "
                             "(mutual TLS). Without it, client certs are not requested.")
    parser.add_argument("--enroll-password", default="",
                        help="#38465/#38582: require this password on POST /enroll (Authorization: "
                             "Bearer <wazuh-enroll+jwt>, verified with the HKDF key of the password). "
                             "Empty (default): open mode, no credential required.")
    parser.add_argument("--enroll-status", type=int, default=0,
                        help="#38465: force every POST /enroll response to this HTTP status "
                             "(e.g. 403/409/500/503), to demo the agent-side error mapping "
                             "instead of the real enroll flow.")
    args = parser.parse_args()

    Handler.key_hex = args.key_hex
    Handler.ENROLL_PASSWORD = args.enroll_password
    Handler.ENROLL_STATUS = args.enroll_status
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

    server = ThreadingHTTPServer((args.bind, args.port), Handler)
    server.requires_client_cert = bool(args.client_ca)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    log(f"HTTPS manager on https://{args.bind}:{args.port} "
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
