#!/usr/bin/env python3
from __future__ import annotations
"""
Inventory Sync benchmark sender — scenario-driven, multi-agent load generator.

Each simulated agent owns ONE TCP socket and multiplexes N concurrent sync
sessions over that socket (one per entry in the scenario's `agent_configs`).
A reader thread on each agent's socket dispatches incoming FlatBuffer
responses to per-session inboxes keyed by `session_id`.

Usage:
    python3 benchmark_sender_v2.py \\
        --scenario scenarios/baseline.json \\
        --manager 127.0.0.1 -o bench.csv --summary-json summary.json

Scenario schema (see scenarios/*.json):
    {
      "name": "...", "description": "...",
      "agent_configs": [
        {
          "payload_kind": "package",
          "session_type": "delta",       // delta | modulecheck | dataclean
          "sync_mode": 1,                 // 0=Full, 1=Delta
          "data_size": 100,
          "max_eps": 0,
          "use_databatch": false,
          "batch_max_bytes": 61440,
          "retransmit": true,
          "payload_size": 0,
          "pad_field": null,
          "modulecheck_checksum": null,
          "auto_resync": false,
          "module": null,
          "index": null
        }, ...
      ],
      "behavior": {
        "total_agents": 10,
        "parallel_agents": 0,   // 0 = all at once; >0 = sliding-window cap
        "repeat_until": 0       // 0 = one pass; >0 = loop seconds
      }
    }

Dependencies:
    pip install pycryptodome
    FlatBuffers classes must be generated (see ../shared/generate_flatbuffers.py)
"""

import argparse
import copy
import csv
import hashlib
import json
import logging
import os
import queue
import signal
import socket
import ssl
import struct
import sys
import threading
import time
import zlib
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from random import sample as random_sample
from string import ascii_letters
from typing import Any

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("benchmark_sender")

# ---------------------------------------------------------------------------
# Resolve shared/ helpers (FlatBuffersManager, agent controller).
# ---------------------------------------------------------------------------
SHARED_DIR = Path(__file__).resolve().parent.parent / "shared"
sys.path.insert(0, str(SHARED_DIR))

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
_running = True
_sigint_count = 0


def _signal_handler(_signum, _frame):
    global _running, _sigint_count
    _sigint_count += 1
    if _sigint_count == 1:
        _running = False
        logger.info("Stop signal received — draining in-flight sessions. "
                    "Press Ctrl+C again to force exit.")
    else:
        logger.warning("Second Ctrl+C — forcing exit.")
        os._exit(130)


# ---------------------------------------------------------------------------
# Status code mapping (mirrors Wazuh::SyncSchema::Status)
# ---------------------------------------------------------------------------
STATUS_OK = 0
STATUS_ERROR = 1
STATUS_OFFLINE = 2
STATUS_CHECKSUM_MISMATCH = 3
STATUS_PROCESSING = 4


# ---------------------------------------------------------------------------
# Payload kind → (sample file, default module, default index)
# ---------------------------------------------------------------------------
PAYLOAD_KINDS: dict[str, dict[str, str]] = {
    "package":           {"file": "syscollector_package.json", "module": "syscollector", "index": "wazuh-states-inventory-packages"},
    "system":            {"file": "syscollector_system.json",  "module": "syscollector", "index": "wazuh-states-inventory-system"},
    "hotfix":            {"file": "syscollector_hotfix.json",  "module": "syscollector", "index": "wazuh-states-inventory-hotfixes"},
    "fim_file":          {"file": "fim_file.json",             "module": "fim",          "index": "wazuh-states-fim-files"},
    "fim_file_windows":  {"file": "fim_file_windows.json",     "module": "fim",          "index": "wazuh-states-fim-files"},
    "fim_registry_key":  {"file": "fim_registry_key.json",     "module": "fim",          "index": "wazuh-states-fim-registry-keys"},
    "fim_registry_value":{"file": "fim_registry_value.json",   "module": "fim",          "index": "wazuh-states-fim-registry-values"},
    "sca_check":         {"file": "sca_check.json",            "module": "sca",          "index": "wazuh-states-sca"},
}

PAD_FIELD_BY_KIND: dict[str, str] = {
    "package":           "package.description",
    "system":            "host.os.full",
    "hotfix":            "package.hotfix.name",
    "fim_file":          "file.path",
    "fim_file_windows":  "file.path",
    "fim_registry_key":  "registry.path",
    "fim_registry_value":"registry.path",
    "sca_check":         "check.description",
}

VALID_SESSION_TYPES = {"delta", "modulecheck", "dataclean"}

# DataBatch cap on the wire (mirrors the real agent's MAX_BATCH_PAYLOAD in
# shared_modules/sync_protocol/.../agent_sync_protocol.cpp). Always used
# when use_databatch=true; not exposed in the scenario schema anymore.
DEFAULT_BATCH_MAX_BYTES = 60 * 1024

# String → int maps mirroring the enums in
# shared_modules/utils/flatbuffers/schemas/inventorySync.fbs. Hardcoded so
# loading a scenario does not need to import the generated FlatBuffers
# modules.
MODE_STR_TO_INT: dict[str, int] = {
    "ModuleFull": 0, "ModuleDelta": 1, "ModuleCheck": 2,
    "MetadataDelta": 3, "MetadataCheck": 4,
    "GroupDelta": 5, "GroupCheck": 6,
}
OPTION_STR_TO_INT: dict[str, int] = {"Sync": 0, "VDFirst": 1, "VDSync": 2}
OPERATION_STR_TO_INT: dict[str, int] = {"Upsert": 0, "Delete": 1}


# ---------------------------------------------------------------------------
# Atomic counters (thread-safe)
# ---------------------------------------------------------------------------
COUNTER_FIELDS = (
    "messages_sent",
    "sessions_started",
    "sessions_completed",
    "sessions_failed",
    "start_ack_ok",
    "start_ack_offline",
    "start_ack_error",
    "end_ack_ok",
    "end_ack_offline",
    "end_ack_error",
    "end_ack_processing",
    "reqret",
    "missing_ranges_total",
    "messages_dropped",
    "start_retries",
)


class AtomicCounters:
    def __init__(self):
        self._lock = threading.Lock()
        self._counters = {k: 0 for k in COUNTER_FIELDS}
        self._latency_lock = threading.Lock()
        self._latency_start_ms: list[float] = []
        self._latency_end_ms: list[float] = []
        self._latency_session_ms: list[float] = []

    def add(self, field: str, n: int = 1):
        with self._lock:
            self._counters[field] = self._counters.get(field, 0) + n

    def add_messages_sent(self, n: int = 1):       self.add("messages_sent", n)
    def add_sessions_started(self, n: int = 1):    self.add("sessions_started", n)
    def add_sessions_completed(self, n: int = 1):  self.add("sessions_completed", n)
    def add_sessions_failed(self, n: int = 1):     self.add("sessions_failed", n)
    def add_messages_dropped(self, n: int = 1):    self.add("messages_dropped", n)

    def record_latency(self, kind: str, ms: float):
        if ms < 0:
            return
        with self._latency_lock:
            if kind == "start":
                self._latency_start_ms.append(ms)
            elif kind == "end":
                self._latency_end_ms.append(ms)
            elif kind == "session":
                self._latency_session_ms.append(ms)

    def snapshot_and_reset(self) -> dict:
        with self._lock:
            snap = dict(self._counters)
            for k in self._counters:
                self._counters[k] = 0
            return snap

    def latency_summary(self) -> dict:
        def pct(samples: list[float]) -> dict:
            if not samples:
                return {"count": 0}
            s = sorted(samples)
            def q(p):
                k = max(0, min(len(s) - 1, int(round((p / 100.0) * (len(s) - 1)))))
                return round(s[k], 2)
            return {
                "count": len(s),
                "p50":   q(50),
                "p90":   q(90),
                "p95":   q(95),
                "p99":   q(99),
                "max":   round(s[-1], 2),
                "avg":   round(sum(s) / len(s), 2),
            }
        with self._latency_lock:
            return {
                "start_ack":    pct(self._latency_start_ms),
                "end_ack":      pct(self._latency_end_ms),
                "session_full": pct(self._latency_session_ms),
            }


# ---------------------------------------------------------------------------
# Payload helpers
# ---------------------------------------------------------------------------
def _get_dotted(d: dict, path: str) -> Any:
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _set_dotted(d: dict, path: str, value: Any) -> None:
    parts = path.split(".")
    cur = d
    for part in parts[:-1]:
        if part not in cur or not isinstance(cur[part], dict):
            cur[part] = {}
        cur = cur[part]
    cur[parts[-1]] = value


def _pad_payload_to_size(template: dict, target_size: int, pad_field: str) -> dict:
    base = copy.deepcopy(template)
    existing = _get_dotted(base, pad_field)
    if not isinstance(existing, str):
        existing = "" if existing is None else str(existing)

    current = len(json.dumps(base).encode("utf-8"))
    if current >= target_size:
        return base

    pad_len = target_size - current
    _set_dotted(base, pad_field, existing + ("x" * pad_len))
    encoded = len(json.dumps(base).encode("utf-8"))
    if encoded < target_size:
        extra = target_size - encoded
        _set_dotted(base, pad_field, existing + ("x" * (pad_len + extra)))
    return base


def _load_payload_dump_for_cfg(cfg: dict) -> dict:
    """Load a recorded-session dump and return a normalized payload info.

    Dumps have shape (see sample_payloads/syscollector/*.json):
        {
          "metadata": {
            "module":  "syscollector" | "syscollector_vd",
            "mode":    "ModuleDelta" | "ModuleFull" | ...,
            "option":  "Sync" | "VDFirst" | "VDSync",
            "size":    <int>,
            "indices": [ "...", "..." ]      # some dumps use "index" instead
          },
          "items": [
            { "seq": <int>, "operation": "Upsert"|"Delete",
              "id": "...", "index": "...", "data": { ... } },
            ...
          ]
        }

    Items can target multiple indices within a single session, so the
    per-item `index` is preserved instead of being collapsed into a single
    session-level value.
    """
    dump_path = cfg["payload_dump"]
    with open(dump_path) as f:
        dump = json.load(f)

    meta = dump.get("metadata") or {}
    raw_items = dump.get("items") or []
    if not isinstance(raw_items, list) or not raw_items:
        raise ValueError(f"payload_dump {dump_path}: items must be a non-empty list")

    module = meta.get("module")
    if not module:
        raise ValueError(f"payload_dump {dump_path}: metadata.module is required")

    mode_str = meta.get("mode", "ModuleDelta")
    if mode_str not in MODE_STR_TO_INT:
        raise ValueError(
            f"payload_dump {dump_path}: metadata.mode={mode_str!r} unknown "
            f"(want one of {sorted(MODE_STR_TO_INT)})"
        )
    mode_int = MODE_STR_TO_INT[mode_str]

    option_str = meta.get("option", "Sync")
    if option_str not in OPTION_STR_TO_INT:
        raise ValueError(
            f"payload_dump {dump_path}: metadata.option={option_str!r} unknown "
            f"(want one of {sorted(OPTION_STR_TO_INT)})"
        )
    option_int = OPTION_STR_TO_INT[option_str]

    # Accept both "indices" (newer dumps) and "index" (one of the existing
    # syscollector dumps spells it singular).
    indices = meta.get("indices") or meta.get("index") or []
    if not isinstance(indices, list):
        raise ValueError(f"payload_dump {dump_path}: metadata.indices must be a list")

    size = int(meta.get("size") or len(raw_items))

    # Normalize items: convert operation string → int once, so the sender's
    # hot path doesn't re-do the lookup per DataValue.
    items: list[dict] = []
    for j, it in enumerate(raw_items):
        if not isinstance(it, dict):
            raise ValueError(f"payload_dump {dump_path}: items[{j}] must be an object")
        op_str = it.get("operation", "Upsert")
        op_int = OPERATION_STR_TO_INT.get(op_str)
        if op_int is None:
            raise ValueError(
                f"payload_dump {dump_path}: items[{j}].operation={op_str!r} unknown "
                f"(want one of {sorted(OPERATION_STR_TO_INT)})"
            )
        idx = it.get("index")
        if not idx:
            raise ValueError(f"payload_dump {dump_path}: items[{j}].index is required")
        items.append({
            "seq":       int(it.get("seq", j)),
            "operation": op_int,
            "id":        it.get("id") or f"{j}",
            "index":     idx,
            "data":      it.get("data") or {},
        })

    return {
        "kind":      "dump",
        "module":    module,
        "mode":      mode_int,
        "option":    option_int,
        "indices":   list(indices),
        "data_size": size,
        "items":     items,
        # template stays unset; SessionRunner branches on kind
        "template":  None,
    }


def _load_payload_for_cfg(cfg: dict) -> dict:
    """Load the payload info for a single agent_config.

    Returns a normalized dict with keys:
        kind:      "static" | "dump"
        module:    str         — used to build Start.module
        mode:      int         — used as Start.mode (overrides cfg.sync_mode for dumps)
        option:    int         — used as Start.option
        indices:   list[str]   — used as Start.index vector
        data_size: int         — used as Start.size and as the loop count for static
        items:     list[dict]  — only for kind="dump"
        template:  dict        — only for kind="static"
    """
    if cfg.get("payload_dump"):
        return _load_payload_dump_for_cfg(cfg)

    kind = cfg["payload_kind"]
    kind_meta = PAYLOAD_KINDS[kind]
    sample_path = Path(__file__).parent / "sample_payloads" / kind_meta["file"]
    if not sample_path.exists():
        raise FileNotFoundError(f"Built-in payload not found: {sample_path}")
    with open(sample_path) as f:
        template = json.load(f)

    payload_size = cfg.get("payload_size", 0) or 0
    if payload_size > 0:
        pad_field = cfg.get("pad_field") or PAD_FIELD_BY_KIND.get(kind, "")
        if not pad_field:
            raise ValueError(
                f"payload_size>0 but no pad_field default for kind={kind} "
                "and pad_field not provided in agent_config"
            )
        original = len(json.dumps(template).encode("utf-8"))
        template = _pad_payload_to_size(template, payload_size, pad_field)
        applied = len(json.dumps(template).encode("utf-8"))
        logger.info(
            "Padded payload (kind=%s field=%s): %d → %d bytes (target=%d)",
            kind, pad_field, original, applied, payload_size,
        )

    return {
        "kind":      "static",
        "module":    cfg["module"],
        "mode":      int(cfg.get("sync_mode", 1)),
        "option":    int(cfg.get("option", 0)),
        "indices":   [cfg["index"]],
        "data_size": int(cfg.get("data_size", 0)),
        "items":     None,
        "template":  template,
    }


# ---------------------------------------------------------------------------
# BenchmarkAgent: 1 TCP socket per agent, reader thread dispatches by session_id.
# ---------------------------------------------------------------------------
class BenchmarkAgent:
    def __init__(
        self,
        agent_id: int,
        manager_address: str,
        manager_port: int = 1514,
        reg_port: int = 1515,
        fb_manager: Any = None,
    ):
        self.agent_num = agent_id
        self.manager_address = manager_address
        self.manager_port = manager_port
        self.reg_port = reg_port

        self.id: str | None = None
        self.name: str | None = None
        self.key: str | None = None
        self.encryption_key: bytes | None = None
        self.sock: socket.socket | None = None

        # Reuse a shared FlatBuffersManager when one is supplied (the bench
        # builds N agents and they all need the same schema dict). If none
        # is provided we fall back to constructing one — that single
        # instance still hits the class-level cache in FlatBuffersManager.
        if fb_manager is not None:
            self.fb_manager = fb_manager
        else:
            self.fb_manager = None
            self._load_flatbuffers()

        # Multiplexing state
        self._send_lock = threading.Lock()
        self._sessions: dict[int, "SessionRunner"] = {}
        self._sessions_lock = threading.Lock()
        # FIFO of runners awaiting their StartAck. Protected by _send_lock
        # (enqueue is done atomically with the Start send so wire order == FIFO).
        self._pending_starts: deque["SessionRunner"] = deque()
        self._reader_thread: threading.Thread | None = None
        self._reader_running = False
        self._socket_alive = False

    def _load_flatbuffers(self):
        try:
            from flatbuffers_manager import FlatBuffersManager
            self.fb_manager = FlatBuffersManager()
        except Exception as e:
            logger.warning("Agent %d: FlatBuffers not available: %s", self.agent_num, e)

    # -- Registration -------------------------------------------------------
    def register(self) -> bool:
        rand_str = "".join(random_sample(f"0123456789{ascii_letters}", 12))
        self.name = f"bench-{self.agent_num:04d}-{rand_str}"

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            ssl_sock = ctx.wrap_socket(sock, server_hostname=self.manager_address)
            ssl_sock.connect((self.manager_address, self.reg_port))
            ssl_sock.send(f"OSSEC A:'{self.name}'\n".encode())
            recv = ssl_sock.recv(4096)
            info = recv.decode().split("'")[1].split(" ")
            self.id = info[0]
            self.key = info[3]
            self._create_encryption_key()
            return True
        except Exception as e:
            logger.error("Agent %d registration failed: %s", self.agent_num, e)
            return False
        finally:
            sock.close()

    def _create_encryption_key(self):
        sum1 = hashlib.md5(
            hashlib.md5(self.name.encode()).hexdigest().encode()
            + hashlib.md5(self.id.encode()).hexdigest().encode()
        ).hexdigest().encode()[:15]
        sum2 = hashlib.md5(self.key.encode()).hexdigest().encode()
        self.encryption_key = sum2 + sum1

    # -- Connection ---------------------------------------------------------
    def connect(self) -> bool:
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(30.0)
            self.sock.connect((self.manager_address, self.manager_port))

            ctrl = f'#!-agent startup {{"version":"4.8.0","name":"{self.name}","id":"{self.id}"}}'
            self._send_text_unlocked(ctrl)
            time.sleep(1.0)

            self._drain_recv_buffer()
            self._socket_alive = True
            return True
        except Exception as e:
            logger.error("Agent %s connect failed: %s", self.id, e)
            return False

    def _drain_recv_buffer(self):
        if not self.sock:
            return
        orig_timeout = self.sock.gettimeout()
        self.sock.settimeout(0.5)
        try:
            while True:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
        except (socket.timeout, BlockingIOError, OSError):
            pass
        self.sock.settimeout(orig_timeout)

    def disconnect(self):
        self._socket_alive = False
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    # -- Reader thread ------------------------------------------------------
    def start_reader(self):
        if self._reader_thread is not None and self._reader_thread.is_alive():
            return
        self._reader_running = True
        self._reader_thread = threading.Thread(
            target=self._reader_loop, daemon=True,
            name=f"reader-{self.id}",
        )
        self._reader_thread.start()

    def stop_reader(self, timeout: float = 2.0):
        self._reader_running = False
        # Unblock the reader's blocking recv() so it can observe the flag
        # and exit. shutdown(SHUT_RDWR) makes recv() return b"" immediately.
        if self.sock is not None:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        if self._reader_thread is not None:
            self._reader_thread.join(timeout=timeout)
            self._reader_thread = None

    def _reader_loop(self):
        """Read frames continuously; dispatch by message type/session_id.

        Uses a blocking recv (timeout=None). The reader exits cleanly when
        stop_reader() or disconnect() calls socket.shutdown(SHUT_RDWR), which
        makes recv() return b"". This avoids per-second polling that would
        otherwise add 1 GIL-acquiring wake-up per agent per second."""
        sock = self.sock
        if sock is None:
            return
        try:
            sock.settimeout(None)
        except OSError:
            self._socket_alive = False
            self._wake_all_runners()
            return

        while self._reader_running and self._socket_alive:
            try:
                length_data = sock.recv(4)
            except OSError:
                break

            if not length_data:
                # Peer closed (or shutdown was called locally).
                break
            if len(length_data) < 4:
                # Partial header — re-read the remainder.
                try:
                    while len(length_data) < 4:
                        more = sock.recv(4 - len(length_data))
                        if not more:
                            break
                        length_data += more
                except OSError:
                    break
                if len(length_data) < 4:
                    break

            length = struct.unpack("<I", length_data)[0]
            data = b""
            try:
                while len(data) < length:
                    chunk = sock.recv(length - len(data))
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                break
            if len(data) != length:
                break

            resp = self._decode_frame(data)
            if resp is None:
                continue
            self._dispatch(resp)

        # Socket closed or reader stopped: wake any blocked runners.
        self._socket_alive = False
        self._wake_all_runners()

    def _decode_frame(self, data: bytes) -> dict | None:
        try:
            if not data.startswith(b"#AES:"):
                return None
            decrypted = self._decrypt(data[5:])
            i = 0
            while i < len(decrypted) and decrypted[i] == ord("!"):
                i += 1
            decompressed = zlib.decompress(decrypted[i:])
            colon2 = 32 + 5 + 10 + 1 + 4
            if colon2 + 1 >= len(decompressed):
                return None
            message = decompressed[colon2 + 1:]
            return self._parse_response(message)
        except Exception:
            return None

    def _dispatch(self, resp: dict):
        """Route a decoded response to the correct SessionRunner inbox."""
        if resp.get("type") != "flatbuffer":
            return
        data = resp.get("data", {})
        if not isinstance(data, dict):
            return

        msg_type = data.get("type")
        if msg_type == "start_ack":
            # Pop the next runner that is awaiting a StartAck.
            # Skip dead entries (runners whose start_pending was reset).
            with self._send_lock:
                runner: SessionRunner | None = None
                while self._pending_starts:
                    candidate = self._pending_starts.popleft()
                    if candidate.start_pending:
                        runner = candidate
                        break
                if runner is not None:
                    runner.start_pending = False
            if runner is None:
                logger.debug("Agent %s: StartAck arrived but no pending runner", self.id)
                return
            runner.inbox.put(resp)
            return

        # All other types carry a session id.
        sid = data.get("session_id") or data.get("session")
        if sid is None:
            return
        with self._sessions_lock:
            target = self._sessions.get(sid)
        if target is None:
            logger.debug("Agent %s: response for unknown session_id=%s type=%s",
                         self.id, sid, msg_type)
            return
        target.inbox.put(resp)

    def _wake_all_runners(self):
        """Notify pending and registered runners that the socket is gone."""
        with self._send_lock:
            pending = list(self._pending_starts)
            self._pending_starts.clear()
        for r in pending:
            r.inbox.put({"type": "socket_closed"})
        with self._sessions_lock:
            registered = list(self._sessions.values())
        for r in registered:
            r.inbox.put({"type": "socket_closed"})

    # -- Session registry ---------------------------------------------------
    def register_session(self, runner: "SessionRunner"):
        if runner.session_id is None:
            return
        with self._sessions_lock:
            self._sessions[runner.session_id] = runner

    def unregister_session(self, runner: "SessionRunner"):
        if runner.session_id is None:
            return
        with self._sessions_lock:
            self._sessions.pop(runner.session_id, None)

    # -- Crypto / framing ---------------------------------------------------
    def _encrypt(self, data: bytes) -> bytes:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        iv = b"FEDCBA0987654321"
        cipher = AES.new(self.encryption_key[:32], AES.MODE_CBC, iv)
        return cipher.encrypt(pad(data, 16))

    def _decrypt(self, data: bytes) -> bytes:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        iv = b"FEDCBA0987654321"
        cipher = AES.new(self.encryption_key[:32], AES.MODE_CBC, iv)
        return cipher.decrypt(pad(data, 16))

    def _wazuh_pad(self, data: bytes) -> bytes:
        extra = len(data) % 8
        padding = (8 - extra) if extra > 0 else 8
        return (b"!" * padding) + data

    def _compose_event(self, payload: bytes) -> bytes:
        msg = b"55555" + b"1234567891" + b":" + b"5555" + b":" + payload
        md5 = hashlib.md5(msg).hexdigest().encode()
        return md5 + msg

    def _encode_binary(self, identifier: str, binary_data: bytes) -> bytes:
        """Build the full framed AES payload for a binary message (no lock, no send)."""
        s_prefix = b"s:"
        id_bytes = identifier.encode()
        msg = b"55555" + b"1234567891" + b":" + b"5555" + b":" + s_prefix + id_bytes + b":" + binary_data
        md5 = hashlib.md5(msg).hexdigest().encode()
        event = md5 + msg
        compressed = zlib.compress(event)
        padded = self._wazuh_pad(compressed)
        encrypted = self._encrypt(padded)
        header = f"!{self.id}!#AES:".encode()
        return header + encrypted

    def _encode_text(self, text: str) -> bytes:
        event = self._compose_event(text.encode())
        compressed = zlib.compress(event)
        padded = self._wazuh_pad(compressed)
        encrypted = self._encrypt(padded)
        header = f"!{self.id}!#AES:".encode()
        return header + encrypted

    def _send_frame(self, framed: bytes):
        """Send a pre-encoded frame atomically. Caller already holds _send_lock."""
        if not self.sock:
            raise RuntimeError("Not connected")
        length = struct.pack("<I", len(framed))
        self.sock.sendall(length + framed)

    def _send_text_unlocked(self, text: str):
        """Send a control text frame. Used during connect() before reader starts."""
        framed = self._encode_text(text)
        if not self.sock:
            raise RuntimeError("Not connected")
        length = struct.pack("<I", len(framed))
        self.sock.sendall(length + framed)

    def send_binary(self, identifier: str, binary_data: bytes):
        """Encode (outside the lock) and send (inside the lock) a binary message."""
        framed = self._encode_binary(identifier, binary_data)
        with self._send_lock:
            self._send_frame(framed)

    def send_start_for_runner(self, runner: "SessionRunner", identifier: str, binary_data: bytes):
        """Atomic: enqueue the runner into the StartAck FIFO and emit the Start frame.

        Holding _send_lock while we both append to _pending_starts AND call
        sendall guarantees wire order == FIFO order for outgoing Start
        messages from this agent. The reader thread dispatches StartAck
        responses by popping the head of the FIFO.
        """
        framed = self._encode_binary(identifier, binary_data)
        with self._send_lock:
            runner.start_pending = True
            self._pending_starts.append(runner)
            self._send_frame(framed)

    # -- Response parsing ---------------------------------------------------
    def _parse_response(self, message: bytes) -> dict | None:
        fb_bytes = None
        if message.startswith(b"s:"):
            parts = message.split(b":", 2)
            if len(parts) >= 3:
                fb_bytes = parts[2]
        elif message.startswith(b"#!-"):
            space_idx = message.find(b" ", 3)
            if space_idx != -1 and space_idx + 1 < len(message):
                fb_bytes = message[space_idx + 1:]
        if fb_bytes is not None:
            try:
                from flatbuffers_manager import parse_message
                parsed = parse_message(fb_bytes)
                return {"type": "flatbuffer", "data": parsed}
            except Exception:
                pass
        return {"type": "raw", "data": message}

    # -- FlatBuffer message construction ------------------------------------
    def create_start_message(
        self, module: str, mode: int, size: int, option: int = 0,
        indices: list[str] | None = None,
    ) -> bytes | None:
        if not self.fb_manager:
            return None
        data = {
            "module": module,
            "mode": mode,
            "size": size,
            "agentid": self.id,
            "agentname": self.name,
            "agentversion": "4.8.0",
            "option": option,
        }
        if indices:
            data["indices"] = indices
        return self.fb_manager.create_message("start", data)

    def create_data_value_message(
        self, session_id: int, seq: int, index: str,
        doc_id: str, payload: dict, operation: int = 0,
    ) -> bytes | None:
        if not self.fb_manager:
            return None
        return self.fb_manager.create_message("data", {
            "session": session_id,
            "seq": seq,
            "index": index,
            "id": doc_id,
            "data": payload,
            "operation": operation,
        })

    def create_end_message(self, session_id: int) -> bytes | None:
        if not self.fb_manager:
            return None
        return self.fb_manager.create_message("end", {"session": session_id})

    def create_checksum_module_message(
        self, session_id: int, index: str, checksum: str,
    ) -> bytes | None:
        if not self.fb_manager:
            return None
        return self.fb_manager.create_message("checksum_module", {
            "session": session_id,
            "index": index,
            "checksum": checksum,
        })

    def create_data_clean_message(
        self, session_id: int, seq: int, index: str,
    ) -> bytes | None:
        if not self.fb_manager:
            return None
        return self.fb_manager.create_message("dataclean", {
            "session": session_id,
            "seq": seq,
            "index": index,
        })

    def create_data_batch_message(
        self,
        session_id: int,
        items: list[tuple[int, str, Any, int, str]],
    ) -> bytes | None:
        """Build a DataBatch from a list of (seq, doc_id, payload, op, index)
        tuples. Each item carries its own index — a single batch may span
        multiple wazuh-states-* indices when replaying a dump that recorded
        a multi-index session."""
        if not self.fb_manager or not items:
            return None
        import flatbuffers
        import Wazuh.SyncSchema.DataValue as DataValueModule
        import Wazuh.SyncSchema.DataBatch as DataBatchModule
        import Wazuh.SyncSchema.Message as MessageModule
        from Wazuh.SyncSchema.MessageType import MessageType

        builder = flatbuffers.Builder(1024)
        dv_offsets: list[int] = []
        for seq, doc_id, payload, operation, index in items:
            if isinstance(payload, (dict, list)):
                data_bytes = json.dumps(payload).encode("utf-8")
            elif isinstance(payload, str):
                data_bytes = payload.encode("utf-8")
            else:
                data_bytes = bytes(payload)
            data_vec = builder.CreateByteVector(data_bytes)
            id_str = builder.CreateString(doc_id)
            index_str = builder.CreateString(index)
            DataValueModule.DataValueStart(builder)
            DataValueModule.DataValueAddSeq(builder, seq)
            DataValueModule.DataValueAddSession(builder, session_id)
            DataValueModule.DataValueAddOperation(builder, operation)
            DataValueModule.DataValueAddId(builder, id_str)
            DataValueModule.DataValueAddIndex(builder, index_str)
            DataValueModule.DataValueAddData(builder, data_vec)
            dv_offsets.append(DataValueModule.DataValueEnd(builder))

        DataBatchModule.DataBatchStartValuesVector(builder, len(dv_offsets))
        for off in reversed(dv_offsets):
            builder.PrependUOffsetTRelative(off)
        values_vec = builder.EndVector()

        DataBatchModule.DataBatchStart(builder)
        DataBatchModule.DataBatchAddValues(builder, values_vec)
        batch_off = DataBatchModule.DataBatchEnd(builder)

        MessageModule.MessageStart(builder)
        MessageModule.MessageAddContentType(builder, MessageType.DataBatch)
        MessageModule.MessageAddContent(builder, batch_off)
        msg_off = MessageModule.MessageEnd(builder)

        builder.Finish(msg_off)
        return bytes(builder.Output())


# ---------------------------------------------------------------------------
# SessionRunner: one logical sync session multiplexed over the agent's socket.
# ---------------------------------------------------------------------------
class SessionRunner:
    """Drives a single Start → Data… → End → EndAck flow.

    Variants by cfg["session_type"]:
      - "delta":       Start(mode=sync_mode) → DataValue*N or DataBatch → End → EndAck
      - "modulecheck": Start(mode=2) → ChecksumModule → End → EndAck
      - "dataclean":   Start(mode=1) → DataClean → End → EndAck
    """

    MAX_RETRANSMIT = 5
    START_ACK_TIMEOUT = 15.0
    END_ACK_TIMEOUT = 120.0
    MODULECHECK_END_ACK_TIMEOUT = 70.0

    def __init__(
        self,
        agent: BenchmarkAgent,
        cfg: dict,
        counters: AtomicCounters,
        payload_info: dict,
    ):
        self.agent = agent
        self.cfg = cfg
        self.counters = counters
        self.payload_info = payload_info
        self.inbox: queue.Queue = queue.Queue()
        self.session_id: int | None = None
        self.start_pending: bool = False
        # True once we've received our StartAck. Used by the agent loop to
        # decide whether a failure should trigger a retry (pre-Start) or be
        # accepted as a final session outcome (post-Start).
        self.start_succeeded: bool = False
        # EPS throttle state (per-runner — each logical session honors its own cap)
        self._eps_cap = int(cfg.get("max_eps", 0) or 0)
        self._eps_t0: float | None = None
        self._eps_sent: int = 0
        # For dump replay: lookup table seq → item, used by ReqRet retransmits.
        if payload_info.get("kind") == "dump":
            self._items_by_seq: dict[int, dict] = {
                it["seq"]: it for it in payload_info["items"]
            }
        else:
            self._items_by_seq = {}

    @property
    def module(self) -> str:
        # Start params come from the loaded payload (dump-overridden when applicable)
        return self.payload_info["module"]

    @property
    def index(self) -> str:
        # Default/session-level index (used by modulecheck/dataclean and as
        # a fallback for retransmits in synthetic-payload sessions). For
        # dump sessions individual items carry their own index.
        indices = self.payload_info.get("indices") or []
        return indices[0] if indices else self.cfg.get("index", "")

    def reset(self):
        """Reset state for a fresh attempt (used by retry loop)."""
        self.session_id = None
        self.start_pending = False
        self.start_succeeded = False
        self._eps_t0 = None
        self._eps_sent = 0
        # Drain leftover inbox messages from a previous attempt.
        try:
            while True:
                self.inbox.get_nowait()
        except queue.Empty:
            pass

    # -- Throttle / send wrappers ------------------------------------------
    def _eps_throttle(self):
        if self._eps_cap <= 0:
            return
        if self._eps_t0 is None:
            self._eps_t0 = time.monotonic()
        self._eps_sent += 1
        target = self._eps_t0 + self._eps_sent / self._eps_cap
        now = time.monotonic()
        if now < target:
            time.sleep(target - now)

    def _send(self, fb: bytes):
        self._eps_throttle()
        self.agent.send_binary(f"{self.module}_sync", fb)
        self.counters.add_messages_sent()

    def _send_start(self, fb: bytes):
        self._eps_throttle()
        self.agent.send_start_for_runner(self, f"{self.module}_sync", fb)
        self.counters.add_messages_sent()

    # -- Inbox helpers ------------------------------------------------------
    def _await_inbox(self, total_timeout: float, slice_s: float = 1.0) -> dict | None:
        """Block on inbox with periodic shutdown checks."""
        deadline = time.monotonic() + total_timeout
        while time.monotonic() < deadline:
            if not _running:
                return None
            try:
                wait = min(slice_s, max(0.05, deadline - time.monotonic()))
                msg = self.inbox.get(timeout=wait)
            except queue.Empty:
                continue
            if msg.get("type") == "socket_closed":
                return None
            return msg
        return None

    # -- Top-level driver ---------------------------------------------------
    def run(self) -> bool:
        """Execute the configured session. Returns True if a final ACK was
        received (success or final error status), False if aborted before
        StartAck (the agent loop may retry in that case)."""
        flow = self.cfg.get("session_type", "delta")
        if flow not in VALID_SESSION_TYPES:
            logger.error("Invalid session_type=%s; treating as delta", flow)
            flow = "delta"
        try:
            if flow == "modulecheck":
                return self._run_modulecheck()
            elif flow == "dataclean":
                return self._run_dataclean()
            else:
                return self._run_delta()
        except Exception as e:
            logger.debug("Agent %s session(%s) failed: %s", self.agent.id, flow, e)
            self.counters.add_sessions_failed()
            return self.start_succeeded
        finally:
            self.agent.unregister_session(self)

    # -- Common: send Start and wait for StartAck ---------------------------
    def _start_session(self, mode: int, size: int, option: int | None = None,
                       indices: list[str] | None = None) -> bool:
        if option is None:
            option = self.payload_info.get("option", 0)
        if indices is None:
            indices = self.payload_info.get("indices") or [self.index]
        fb_start = self.agent.create_start_message(
            module=self.module, mode=mode, size=size, option=option,
            indices=indices,
        )
        if fb_start is None:
            raise RuntimeError("Failed to create Start message")

        self._t_start_sent = time.monotonic()
        self._send_start(fb_start)
        self.counters.add_sessions_started()

        resp = self._await_inbox(self.START_ACK_TIMEOUT)
        # If we never received a StartAck, drop ourselves from the pending FIFO.
        if resp is None:
            with self.agent._send_lock:
                self.start_pending = False
            return False

        t_start_ack = time.monotonic()
        self.counters.record_latency("start", (t_start_ack - self._t_start_sent) * 1000.0)

        if resp.get("type") != "flatbuffer":
            return False
        data = resp.get("data", {})
        if not isinstance(data, dict) or data.get("type") != "start_ack":
            return False

        sid = data.get("session_id") or data.get("session")
        status = data.get("status", -1)

        if status == STATUS_OFFLINE:
            self.counters.add("start_ack_offline")
            return False
        if status not in (STATUS_OK, STATUS_PROCESSING):
            self.counters.add("start_ack_error")
            return False

        self.counters.add("start_ack_ok")
        if sid is None:
            return False

        self.session_id = sid
        self.agent.register_session(self)
        self.start_succeeded = True
        return True

    # -- Delta flow ---------------------------------------------------------
    def _run_delta(self) -> bool:
        cfg = self.cfg
        use_databatch = bool(cfg.get("use_databatch", False))
        retransmit = bool(cfg.get("retransmit", True))

        # Start params come from payload_info (dump metadata overrides
        # cfg.sync_mode and supplies indices+option). For synthetic payloads
        # payload_info["mode"] was set to cfg.sync_mode at load time.
        info = self.payload_info
        size = int(info["data_size"])
        mode = int(info["mode"])

        if not self._start_session(mode=mode, size=size):
            return False

        # Materialize the per-DataValue iterator. Each element is a tuple
        #   (seq, operation_int, doc_id, index, payload_dict)
        items_iter = self._materialize_items(size)

        if use_databatch:
            self._send_data_as_batches(items_iter)
        else:
            self._send_data_as_values(items_iter)

        # Send End and wait for EndAck (with optional ReqRet retransmits).
        if not _running:
            return True

        sid = self.session_id
        fb_end = self.agent.create_end_message(sid)
        if fb_end is None:
            raise RuntimeError("Failed to create End message")
        t_end_sent = time.monotonic()
        self._send(fb_end)

        return self._wait_end_ack(t_end_sent, retransmit=retransmit)

    def _materialize_items(self, count: int) -> list[tuple[int, int, str, str, Any]]:
        """Build the list of (seq, op, doc_id, index, payload) tuples to send.

        - Dump replay: one tuple per item from the dump, preserving the
          item's own seq/operation/id/index/data.
        - Synthetic: `count` synthetic Upsert tuples using the cfg's index
          and the loaded template payload, all sharing the same data shape.
        """
        sid = self.session_id
        info = self.payload_info
        if info.get("kind") == "dump":
            return [
                (it["seq"], it["operation"],
                 it["id"] or f"{self.agent.id}-{sid}-{it['seq']}",
                 it["index"], it["data"])
                for it in info["items"]
            ]
        template = info["template"]
        index = self.index
        return [
            (seq, 0, f"{self.agent.id}-{sid}-{seq}", index, template)
            for seq in range(count)
        ]

    def _send_data_as_values(self, items: list[tuple[int, int, str, str, Any]]):
        sid = self.session_id
        for seq, op, doc_id, index, payload in items:
            if not _running:
                break
            fb = self.agent.create_data_value_message(
                session_id=sid, seq=seq, index=index,
                doc_id=doc_id, payload=payload, operation=op,
            )
            if fb is None:
                raise RuntimeError(f"Failed to create DataValue seq={seq}")
            self._send(fb)

    def _send_data_as_batches(self, items: list[tuple[int, int, str, str, Any]]):
        # Mirror real agent's batching policy (MAX_BATCH_PAYLOAD = 60 KB).
        # NOTE: DataBatch is a vector of fully-populated DataValues — items
        # in the same batch may target different indices, which matters for
        # dump replays that span 9 wazuh-states-inventory-* indices.
        FB_OVERHEAD_PER_ITEM = 80
        BATCH_MESSAGE_OVERHEAD = 128

        sid = self.session_id
        pending: list[tuple[int, str, Any, int, str]] = []
        batch_est = BATCH_MESSAGE_OVERHEAD

        def flush():
            nonlocal batch_est
            if not pending:
                return
            fb_batch = self.agent.create_data_batch_message(sid, pending)
            if fb_batch is None:
                raise RuntimeError("Failed to create DataBatch message")
            self._send(fb_batch)
            pending.clear()
            batch_est = BATCH_MESSAGE_OVERHEAD

        for seq, op, doc_id, index, payload in items:
            if not _running:
                break
            try:
                payload_bytes_len = len(json.dumps(payload).encode("utf-8"))
            except Exception:
                payload_bytes_len = 600
            item_size = FB_OVERHEAD_PER_ITEM + len(doc_id) + len(index) + payload_bytes_len
            if pending and batch_est + item_size > DEFAULT_BATCH_MAX_BYTES:
                flush()
            pending.append((seq, doc_id, payload, op, index))
            batch_est += item_size
        if _running:
            flush()

    def _wait_end_ack(self, t_end_sent: float, retransmit: bool) -> bool:
        retransmit_count = 0
        start_wait = time.monotonic()
        while time.monotonic() - start_wait < self.END_ACK_TIMEOUT:
            if not _running:
                return True
            remaining = self.END_ACK_TIMEOUT - (time.monotonic() - start_wait)
            resp = self._await_inbox(min(remaining, 2.0))
            if resp is None:
                if time.monotonic() - start_wait >= self.END_ACK_TIMEOUT:
                    raise RuntimeError("No EndAck received")
                continue
            if resp.get("type") != "flatbuffer":
                continue
            data = resp.get("data", {})
            if not isinstance(data, dict):
                continue
            msg_type = data.get("type")
            if msg_type == "end_ack":
                status = data.get("status", -1)
                if status == STATUS_PROCESSING:
                    self.counters.add("end_ack_processing")
                    continue
                t_end_ack = time.monotonic()
                self.counters.record_latency("end",     (t_end_ack - t_end_sent) * 1000.0)
                self.counters.record_latency("session", (t_end_ack - self._t_start_sent) * 1000.0)
                if status == STATUS_OK:
                    self.counters.add("end_ack_ok")
                    self.counters.add_sessions_completed()
                    return True
                if status == STATUS_OFFLINE:
                    self.counters.add("end_ack_offline")
                    raise RuntimeError("EndAck offline")
                self.counters.add("end_ack_error")
                raise RuntimeError(f"EndAck error status={status}")
            elif msg_type == "reqret":
                self.counters.add("reqret")
                ranges = data.get("ranges", []) or []
                self.counters.add("missing_ranges_total", len(ranges))
                if not retransmit:
                    self.counters.add_messages_dropped()
                    raise RuntimeError("ReqRet received and retransmit is disabled")
                retransmit_count += 1
                if retransmit_count > self.MAX_RETRANSMIT:
                    self.counters.add_messages_dropped()
                    raise RuntimeError(f"ReqRet: exceeded {self.MAX_RETRANSMIT} retransmissions")
                # Retransmit only the missing sequences. For dump replays we
                # look up the original item by seq so the resent DataValue
                # carries the recorded id/index/data/operation; otherwise we
                # synthesize one from the cfg's index + template.
                sid = self.session_id
                info = self.payload_info
                template = info.get("template")
                default_index = self.index
                for r in ranges:
                    for seq in range(r["start"], r["end"] + 1):
                        if self._items_by_seq:
                            it = self._items_by_seq.get(seq)
                            if it is None:
                                # Seq outside the dump — skip; manager will
                                # eventually time out the missing range.
                                continue
                            doc_id = it["id"] or f"{self.agent.id}-{sid}-{seq}"
                            idx = it["index"]
                            payload = it["data"]
                            op = it["operation"]
                        else:
                            doc_id = f"{self.agent.id}-{sid}-{seq}"
                            idx = default_index
                            payload = template
                            op = 0
                        fb_retx = self.agent.create_data_value_message(
                            session_id=sid, seq=seq, index=idx,
                            doc_id=doc_id, payload=payload, operation=op,
                        )
                        if fb_retx:
                            self._send(fb_retx)
        raise RuntimeError("EndAck timeout")

    # -- ModuleCheck flow ---------------------------------------------------
    def _run_modulecheck(self) -> bool:
        cfg = self.cfg
        checksum = cfg.get("modulecheck_checksum") or ("0" * 40)
        auto_resync = bool(cfg.get("auto_resync", False))

        if not self._start_session(mode=2, size=0):
            return False

        sid = self.session_id
        fb_cs = self.agent.create_checksum_module_message(sid, self.index, checksum)
        if fb_cs is None:
            raise RuntimeError("Failed to create ChecksumModule message")
        self._send(fb_cs)

        fb_end = self.agent.create_end_message(sid)
        if fb_end is None:
            raise RuntimeError("Failed to create End message (ModuleCheck)")
        t_end_sent = time.monotonic()
        self._send(fb_end)

        # Wait for EndAck — may be Ok or ChecksumMismatch.
        start_wait = time.monotonic()
        while time.monotonic() - start_wait < self.MODULECHECK_END_ACK_TIMEOUT:
            if not _running:
                return True
            remaining = self.MODULECHECK_END_ACK_TIMEOUT - (time.monotonic() - start_wait)
            resp = self._await_inbox(min(remaining, 2.0))
            if resp is None:
                if time.monotonic() - start_wait >= self.MODULECHECK_END_ACK_TIMEOUT:
                    raise RuntimeError("EndAck timeout (ModuleCheck)")
                continue
            if resp.get("type") != "flatbuffer":
                continue
            data = resp.get("data", {})
            if not isinstance(data, dict) or data.get("type") != "end_ack":
                continue
            status = data.get("status", -1)
            if status == STATUS_PROCESSING:
                self.counters.add("end_ack_processing")
                continue
            t_end_ack = time.monotonic()
            self.counters.record_latency("end",     (t_end_ack - t_end_sent) * 1000.0)
            self.counters.record_latency("session", (t_end_ack - self._t_start_sent) * 1000.0)
            if status == STATUS_OK:
                self.counters.add("end_ack_ok")
                self.counters.add_sessions_completed()
                return True
            if status == STATUS_CHECKSUM_MISMATCH:
                self.counters.add("end_ack_error")
                self.counters.add_sessions_completed()
                if auto_resync:
                    # Spawn a delta full session in-place over the same socket.
                    self.agent.unregister_session(self)
                    full_cfg = dict(self.cfg)
                    full_cfg["session_type"] = "delta"
                    full_cfg["sync_mode"] = 0
                    # Build a payload_info clone with mode forced to Full.
                    full_info = dict(self.payload_info)
                    full_info["mode"] = 0
                    follow_up = SessionRunner(
                        self.agent, full_cfg, self.counters, full_info,
                    )
                    follow_up.run()
                return True
            if status == STATUS_OFFLINE:
                self.counters.add("end_ack_offline")
                raise RuntimeError("EndAck offline (ModuleCheck)")
            self.counters.add("end_ack_error")
            raise RuntimeError(f"EndAck error status={status} (ModuleCheck)")
        raise RuntimeError("EndAck timeout (ModuleCheck)")

    # -- DataClean flow -----------------------------------------------------
    def _run_dataclean(self) -> bool:
        if not self._start_session(mode=1, size=1):
            return False

        sid = self.session_id
        fb_dc = self.agent.create_data_clean_message(sid, seq=0, index=self.index)
        if fb_dc is None:
            raise RuntimeError("Failed to create DataClean message")
        self._send(fb_dc)

        fb_end = self.agent.create_end_message(sid)
        if fb_end is None:
            raise RuntimeError("Failed to create End message (DataClean)")
        t_end_sent = time.monotonic()
        self._send(fb_end)

        start_wait = time.monotonic()
        while time.monotonic() - start_wait < 60.0:
            if not _running:
                return True
            remaining = 60.0 - (time.monotonic() - start_wait)
            resp = self._await_inbox(min(remaining, 2.0))
            if resp is None:
                if time.monotonic() - start_wait >= 60.0:
                    raise RuntimeError("EndAck timeout (DataClean)")
                continue
            if resp.get("type") != "flatbuffer":
                continue
            data = resp.get("data", {})
            if not isinstance(data, dict) or data.get("type") != "end_ack":
                continue
            status = data.get("status", -1)
            if status == STATUS_PROCESSING:
                self.counters.add("end_ack_processing")
                continue
            t_end_ack = time.monotonic()
            self.counters.record_latency("end",     (t_end_ack - t_end_sent) * 1000.0)
            self.counters.record_latency("session", (t_end_ack - self._t_start_sent) * 1000.0)
            if status == STATUS_OK:
                self.counters.add("end_ack_ok")
                self.counters.add_sessions_completed()
                return True
            if status == STATUS_OFFLINE:
                self.counters.add("end_ack_offline")
                raise RuntimeError("EndAck offline (DataClean)")
            self.counters.add("end_ack_error")
            raise RuntimeError(f"EndAck error status={status} (DataClean)")
        raise RuntimeError("EndAck timeout (DataClean)")


# ---------------------------------------------------------------------------
# Agent loop: multiplex N runners (one per agent_config) on a single socket.
# ---------------------------------------------------------------------------
def _run_runner_once(runner: SessionRunner) -> None:
    """Run a single SessionRunner attempt. Pre-Start failures are retried at
    the agent_loop iteration granularity (which reconnects first), not here:
    retrying on the same dead socket amplifies load against a saturated
    manager and is exactly what the post-refactor sender did wrong."""
    runner.reset()
    runner.run()


def agent_loop(
    agent: BenchmarkAgent,
    configs: list[dict],
    payload_infos: list[dict],
    behavior: dict,
    counters: AtomicCounters,
    deadline: float,
    barrier: threading.Barrier | None,
    parallel_sem: threading.Semaphore | None,
):
    """Drive one agent through the scenario (single TCP socket, N runners per iteration).

    Between iterations the socket is torn down and reconnected — mirroring
    the pre-refactor sender. This keeps the manager from accumulating
    half-dead connections under burst load and gives every iteration a
    clean slate."""
    global _running

    if parallel_sem is not None:
        parallel_sem.acquire()

    try:
        if not agent.connect():
            counters.add_sessions_failed(len(configs))
            # Only signal the barrier if we are in barrier mode. With a
            # sliding-window semaphore the barrier is `None` because not
            # every agent reaches the convergence point at the same time.
            if barrier is not None:
                try:
                    barrier.wait(timeout=5)
                except threading.BrokenBarrierError:
                    pass
            return

        agent.start_reader()

        if barrier is not None:
            try:
                barrier.wait(timeout=60)
            except threading.BrokenBarrierError:
                logger.error("Agent %s: barrier broken", agent.id)
                agent.stop_reader()
                agent.disconnect()
                return

        repeat_until = int(behavior.get("repeat_until", 0) or 0)
        iteration = 0
        while _running and time.monotonic() < deadline:
            iteration += 1

            # Refresh the socket between iterations (mirrors the pre-refactor
            # sender). Skip on iteration 1 — we already connected above and
            # passed the barrier.
            if iteration > 1:
                agent.stop_reader()
                agent.disconnect()
                # Brief breather before reconnecting — gives the manager a
                # chance to free server-side state and avoids hammering a
                # potentially saturated remoted.
                if not _running or time.monotonic() >= deadline:
                    break
                time.sleep(1.0)
                if not agent.connect():
                    logger.error(
                        "Agent %s: reconnect failed at iteration %d — exiting agent loop",
                        agent.id, iteration,
                    )
                    counters.add_sessions_failed(len(configs))
                    break
                agent.start_reader()

            runners = [
                SessionRunner(agent, cfg, counters, payload_infos[i])
                for i, cfg in enumerate(configs)
            ]
            threads = [
                threading.Thread(
                    target=_run_runner_once,
                    args=(r,),
                    daemon=True,
                    name=f"runner-{agent.id}-it{iteration}-{i}",
                )
                for i, r in enumerate(runners)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            if repeat_until == 0:
                break  # single-pass mode
            # else: loop until deadline.

        agent.stop_reader()
        agent.disconnect()
        logger.info("Agent %s finished (%d iteration(s))", agent.id, iteration)
    finally:
        if parallel_sem is not None:
            parallel_sem.release()


# ---------------------------------------------------------------------------
# Stats collector (unchanged in spirit)
# ---------------------------------------------------------------------------
CSV_HEADER = ["timestamp", "elapsed_s"] + list(COUNTER_FIELDS)


def stats_collector(
    counters: AtomicCounters,
    csv_path: str,
    deadline: float,
    drain_timeout: float = 60.0,
    summary_json_path: str | None = None,
    run_meta: dict | None = None,
    agents_done: threading.Event | None = None,
):
    """Sample counters once per second and write the bench CSV.

    Drain phase triggers (whichever comes first):
      - wall clock crosses `deadline` (set by `repeat_until > 0`), OR
      - `agents_done` event fires (set by the main-thread watcher when all
        agent loops have exited — the natural signal when `repeat_until=0`).

    Once in drain phase, exit on `in_flight <= 0` or after `drain_timeout`
    seconds elapsed from the drain trigger. Without the event, a
    single-pass scenario would loop here forever because the deadline is
    24 h away."""
    global _running

    with open(csv_path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_HEADER)
        writer.writeheader()
        fh.flush()

        t0 = time.monotonic()
        second = 0
        cumulative = defaultdict(int)
        announced_drain = False
        drain_started_at: float | None = None

        while _running:
            time.sleep(1.0)
            # Use wall-clock elapsed seconds rather than an incrementing
            # counter: under heavy thread contention time.sleep(1.0) can
            # take much longer to actually return, and the previous
            # implementation labeled rows by iteration count instead of
            # actual wall time, producing misleading charts.
            second = int(time.monotonic() - t0)
            snap = counters.snapshot_and_reset()
            for k, v in snap.items():
                cumulative[k] += v

            row = {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "elapsed_s": second,
                **{k: snap.get(k, 0) for k in COUNTER_FIELDS},
            }
            writer.writerow(row)
            fh.flush()

            in_flight = (cumulative["sessions_started"]
                         - cumulative["sessions_completed"]
                         - cumulative["sessions_failed"])

            now = time.monotonic()
            agents_done_set = bool(agents_done and agents_done.is_set())
            in_drain = now >= deadline or agents_done_set
            phase = "drain" if in_drain else "send"
            if in_drain and drain_started_at is None:
                drain_started_at = now
            if phase == "drain" and not announced_drain:
                announced_drain = True
                reason = "agents finished" if agents_done_set else "deadline reached"
                logger.info(
                    "%s. Entering drain phase (in_flight=%d, drain_timeout=%.0fs).",
                    reason, in_flight, drain_timeout,
                )

            logger.info(
                "[%3ds %5s]  sent=%d  started=%d  completed=%d  failed=%d  "
                "in_flight=%d  start_ack(ok/off/err)=%d/%d/%d  "
                "end_ack(ok/off/err/proc)=%d/%d/%d/%d  reqret=%d  retries=%d",
                second, phase,
                snap["messages_sent"],
                snap["sessions_started"],
                snap["sessions_completed"],
                snap["sessions_failed"],
                in_flight,
                snap["start_ack_ok"], snap["start_ack_offline"], snap["start_ack_error"],
                snap["end_ack_ok"], snap["end_ack_offline"], snap["end_ack_error"], snap["end_ack_processing"],
                snap["reqret"], snap["start_retries"],
            )

            if phase == "drain":
                if in_flight <= 0:
                    logger.info("All in-flight sessions drained after %ds.", second)
                    break
                if drain_started_at is not None and now > drain_started_at + drain_timeout:
                    logger.warning(
                        "Drain timeout reached with %d session(s) still in flight.",
                        in_flight,
                    )
                    break

    latency = counters.latency_summary()

    print()
    print("=" * 65)
    print("              INVENTORY SYNC BENCHMARK REPORT")
    print("=" * 65)
    print()
    print(f"  Duration:             {second} s")
    print(f"  Messages sent:        {cumulative['messages_sent']:,}")
    print(f"  Sessions started:     {cumulative['sessions_started']:,}")
    print(f"  Sessions completed:   {cumulative['sessions_completed']:,}")
    print(f"  Sessions failed:      {cumulative['sessions_failed']:,}")
    print(f"  StartAck ok/off/err:  {cumulative['start_ack_ok']:,} / "
          f"{cumulative['start_ack_offline']:,} / {cumulative['start_ack_error']:,}")
    print(f"  EndAck ok/off/err:    {cumulative['end_ack_ok']:,} / "
          f"{cumulative['end_ack_offline']:,} / {cumulative['end_ack_error']:,}")
    print(f"  ReqRet count:         {cumulative['reqret']:,}")
    print(f"  Start retries:        {cumulative['start_retries']:,}")
    if cumulative["sessions_started"] > 0:
        success_pct = cumulative["sessions_completed"] / cumulative["sessions_started"] * 100
        print(f"  Success rate:         {success_pct:.1f}%")
    if second > 0:
        print(f"  Avg msg/s:            {cumulative['messages_sent'] / second:,.1f}")
        print(f"  Avg sessions/s:       {cumulative['sessions_completed'] / second:,.1f}")
    for kind in ("start_ack", "end_ack", "session_full"):
        p = latency.get(kind, {})
        if p.get("count"):
            print(f"  Latency {kind:13s} count={p['count']:,} "
                  f"p50={p['p50']:.1f}ms p95={p['p95']:.1f}ms "
                  f"p99={p['p99']:.1f}ms max={p['max']:.1f}ms")
    print()
    print("=" * 65)

    if summary_json_path:
        summary = {
            "meta":         run_meta or {},
            "duration_sec": second,
            "messages":     dict(cumulative),
            "latency_ms":   latency,
        }
        with open(summary_json_path, "w") as jf:
            json.dump(summary, jf, indent=2, default=str)
        logger.info("Summary written: %s", summary_json_path)


# ---------------------------------------------------------------------------
# Scenario loader
# ---------------------------------------------------------------------------
def load_scenario(path: str) -> dict:
    """Load + normalize a scenario JSON.

    Returns a dict with keys:
      name, description, agent_configs (list[dict]), behavior (dict).
    Each agent_config is fully resolved. The payload source is either a
    synthetic `payload_kind` (single-doc template padded into N copies) or
    a `payload_dump` (path to a JSON dump of a real recorded session whose
    items are replayed verbatim, including per-item index and operation).
    """
    with open(path) as f:
        raw = json.load(f)

    name = raw.get("name") or Path(path).stem
    description = raw.get("description") or ""
    agent_configs_raw = raw.get("agent_configs") or []
    if not isinstance(agent_configs_raw, list) or not agent_configs_raw:
        raise ValueError(f"Scenario {path}: agent_configs must be a non-empty list")

    scenario_dir = Path(path).parent

    configs: list[dict] = []
    for i, cfg in enumerate(agent_configs_raw):
        if not isinstance(cfg, dict):
            raise ValueError(f"Scenario {path}: agent_configs[{i}] must be an object")

        kind = cfg.get("payload_kind")
        dump_ref = cfg.get("payload_dump")

        if dump_ref and kind:
            raise ValueError(
                f"Scenario {path}: agent_configs[{i}] cannot set both "
                f"payload_kind and payload_dump"
            )
        if not dump_ref and kind not in PAYLOAD_KINDS:
            raise ValueError(
                f"Scenario {path}: agent_configs[{i}].payload_kind={kind!r} "
                f"not in {list(PAYLOAD_KINDS.keys())} (and payload_dump not set)"
            )

        # Resolve dump path relative to the scenario file so users can write
        # short paths like "sample_payloads/syscollector/session-delta-sin-vd.json".
        dump_path: str | None = None
        if dump_ref:
            cand = Path(dump_ref)
            if not cand.is_absolute():
                cand = (scenario_dir / cand).resolve()
            if not cand.exists():
                # Fall back to a path relative to the benchmark dir (the
                # scripts that live next to the sender) — useful when the
                # scenario lives in scenarios_v2/ and refers to
                # sample_payloads/.
                alt = (Path(__file__).resolve().parent / dump_ref).resolve()
                if alt.exists():
                    cand = alt
                else:
                    raise ValueError(
                        f"Scenario {path}: agent_configs[{i}].payload_dump "
                        f"file not found: {dump_ref}"
                    )
            dump_path = str(cand)

        session_type = cfg.get("session_type", "delta")
        if session_type not in VALID_SESSION_TYPES:
            raise ValueError(
                f"Scenario {path}: agent_configs[{i}].session_type={session_type!r} "
                f"not in {sorted(VALID_SESSION_TYPES)}"
            )

        kind_meta = PAYLOAD_KINDS[kind] if kind else None
        default_module = kind_meta["module"] if kind_meta else None
        default_index  = kind_meta["index"]  if kind_meta else None

        resolved = {
            "payload_kind":         kind,                # None when using a dump
            "payload_dump":         dump_path,           # None when using payload_kind
            "session_type":         session_type,
            "sync_mode":            int(cfg.get("sync_mode", 1)),
            "data_size":            int(cfg.get("data_size", 0)),
            "max_eps":              int(cfg.get("max_eps", 0) or 0),
            "use_databatch":        bool(cfg.get("use_databatch", False)),
            "retransmit":           bool(cfg.get("retransmit", True)),
            "payload_size":         int(cfg.get("payload_size", 0) or 0),
            "pad_field":            cfg.get("pad_field"),
            "modulecheck_checksum": cfg.get("modulecheck_checksum"),
            "auto_resync":          bool(cfg.get("auto_resync", False)),
            # `module` / `index` are placeholders for synthetic payloads; for
            # dumps they will be overwritten by metadata at load time.
            "module":               cfg.get("module") or default_module,
            "index":                cfg.get("index")  or default_index,
            "option":               OPTION_STR_TO_INT.get(cfg.get("option", "Sync"), 0),
        }
        configs.append(resolved)

    behavior_raw = raw.get("behavior") or {}
    if not isinstance(behavior_raw, dict):
        raise ValueError(f"Scenario {path}: behavior must be an object")
    behavior = {
        "total_agents":    int(behavior_raw.get("total_agents", 1)),
        "parallel_agents": int(behavior_raw.get("parallel_agents", 0) or 0),
        "repeat_until":    int(behavior_raw.get("repeat_until", 0) or 0),
    }
    # Optional per-scenario override of the post-drain grace window. When
    # `repeat_until=0` (single pass) the natural exit signal is "all agents
    # finished their iteration"; the stats collector then waits up to
    # drain_timeout extra seconds for in-flight EndAcks before closing.
    # When omitted, the CLI default (`--drain-timeout`) is used.
    if "drain_timeout" in behavior_raw and behavior_raw["drain_timeout"] is not None:
        dt = int(behavior_raw["drain_timeout"])
        if dt < 0:
            raise ValueError(f"Scenario {path}: behavior.drain_timeout must be >= 0")
        behavior["drain_timeout"] = dt
    if behavior["total_agents"] < 1:
        raise ValueError(f"Scenario {path}: behavior.total_agents must be >= 1")
    if behavior["parallel_agents"] < 0:
        raise ValueError(f"Scenario {path}: behavior.parallel_agents must be >= 0")
    if behavior["repeat_until"] < 0:
        raise ValueError(f"Scenario {path}: behavior.repeat_until must be >= 0")

    return {
        "name":          name,
        "description":   description,
        "agent_configs": configs,
        "behavior":      behavior,
    }


# ---------------------------------------------------------------------------
# CLI / main
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Inventory Sync scenario-driven benchmark sender.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--scenario", type=str, required=True,
                   help="Path to scenario JSON (see scenarios/).")
    p.add_argument("--manager", type=str, default="127.0.0.1",
                   help="Manager address (default: 127.0.0.1)")
    p.add_argument("--port", type=int, default=1514,
                   help="Manager port (default: 1514)")
    p.add_argument("--reg-port", type=int, default=1515,
                   help="Registration port (default: 1515)")
    p.add_argument("-o", "--output", type=str, default="bench.csv",
                   help="Output CSV file (default: bench.csv)")
    p.add_argument("--summary-json", type=str, default=None,
                   help="If set, write a final summary JSON.")
    p.add_argument("--drain-timeout", type=float, default=60.0,
                   help="Seconds to keep sampling once all agents finish "
                        "(or the deadline is hit) before forcing exit. "
                        "Can be overridden per-scenario via "
                        "behavior.drain_timeout. Default: 60.")
    p.add_argument("--key-wait", type=int, default=35,
                   help="Seconds to wait after registration for remoted key reload (default: 35)")
    p.add_argument("--debug", action="store_true", help="Debug logging")
    return p.parse_args()


def _global_deadline_for(behavior: dict) -> float:
    """Compute the global deadline that bounds every agent's iteration loop."""
    repeat_until = int(behavior.get("repeat_until", 0) or 0)
    if repeat_until > 0:
        return time.monotonic() + repeat_until
    # Single-pass mode: no time bound from the scenario, but we still need a
    # finite deadline so the runner-retry loop terminates if Start keeps
    # failing. Use a generous default (24h); the scenario's natural end
    # (all agents finish their one pass) will normally kick in much sooner.
    return time.monotonic() + 24 * 3600


def main() -> None:
    global _running
    args = parse_args()
    if args.debug:
        logger.setLevel(logging.DEBUG)

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    scenario = load_scenario(args.scenario)
    configs: list[dict] = scenario["agent_configs"]
    behavior: dict = scenario["behavior"]

    payload_infos: list[dict] = [_load_payload_for_cfg(cfg) for cfg in configs]

    total_agents = behavior["total_agents"]
    parallel_agents = behavior["parallel_agents"]
    repeat_until = behavior["repeat_until"]

    print()
    print(f"Inventory Sync Benchmark — scenario: {scenario['name']}")
    print(f"  Manager:           {args.manager}:{args.port}")
    print(f"  Total agents:      {total_agents}")
    print(f"  Parallel agents:   {parallel_agents if parallel_agents > 0 else 'all'}")
    print(f"  Repeat until:      {repeat_until}s ({'single pass' if repeat_until == 0 else 'loop'})")
    print(f"  Sessions/agent:    {len(configs)} (multiplexed over 1 socket)")
    for i, cfg in enumerate(configs):
        info = payload_infos[i]
        if cfg.get("payload_dump"):
            source = f"dump={Path(cfg['payload_dump']).name}"
        else:
            source = f"kind={cfg.get('payload_kind')}"
        print(f"    [{i}] {source:40s} "
              f"session_type={cfg['session_type']:12s} "
              f"module={info['module']:18s} mode={info['mode']} "
              f"size={info['data_size']} max_eps={cfg['max_eps']} "
              f"use_databatch={cfg['use_databatch']}")
    print(f"  Output:            {args.output}")
    print()

    counters = AtomicCounters()

    # Build the FlatBuffers schema/manager ONCE and share it across all
    # agents. Without this, BenchmarkAgent.__init__ would call
    # FlatBuffersManager() per agent — which (pre-cache) re-ran flatc and
    # printed a 25-line banner per instance.
    try:
        from flatbuffers_manager import FlatBuffersManager
        shared_fb_manager = FlatBuffersManager()
    except Exception as e:
        logger.warning("FlatBuffersManager not available, agents will fall back: %s", e)
        shared_fb_manager = None

    # ---- Phase 1: Register all agents ------------------------------------
    logger.info("Registering %d agents...", total_agents)
    agents: list[BenchmarkAgent] = []
    for i in range(total_agents):
        agent = BenchmarkAgent(
            i, args.manager, args.port, args.reg_port,
            fb_manager=shared_fb_manager,
        )
        if not agent.register():
            logger.error("Agent %d registration failed, skipping", i)
            continue
        agents.append(agent)
        time.sleep(0.05)

    if not agents:
        logger.error("No agents registered successfully, aborting")
        return

    logger.info(
        "%d/%d agents registered. Waiting %ds for remoted key reload...",
        len(agents), total_agents, args.key_wait,
    )

    for remaining in range(args.key_wait, 0, -1):
        if not _running:
            return
        if remaining % 10 == 0:
            logger.info("  %ds remaining...", remaining)
        time.sleep(1.0)

    logger.info("Key reload wait complete. Spawning agent loops...")

    deadline = _global_deadline_for(behavior)

    # Concurrency model: either "all-at-once" (parallel_agents == 0) or
    # sliding-window (parallel_agents > 0). The barrier only makes sense
    # in the first case — sliding-window means agents trickle in as the
    # semaphore allows, so there is no single instant where every agent
    # is connected and ready. Mixing the two deadlocks: agents blocked on
    # the semaphore never reach the barrier, the barrier times out after
    # 60 s, and every agent_loop crashes with BrokenBarrierError.
    parallel_sem: threading.Semaphore | None = None
    barrier: threading.Barrier | None = None
    if parallel_agents > 0:
        parallel_sem = threading.Semaphore(parallel_agents)
    else:
        barrier = threading.Barrier(len(agents) + 1, timeout=180)

    threads: list[threading.Thread] = []
    for agent in agents:
        t = threading.Thread(
            target=agent_loop,
            args=(agent, configs, payload_infos, behavior,
                  counters, deadline, barrier, parallel_sem),
            daemon=True,
            name=f"agent-loop-{agent.id}",
        )
        t.start()
        threads.append(t)

    if barrier is not None:
        try:
            barrier.wait(timeout=180)
        except threading.BrokenBarrierError:
            logger.error("Not all agents reached the barrier in time")
            _running = False
            return
        logger.info("All agents ready — starting benchmark")
    else:
        # Sliding-window mode: agents trickle in as the semaphore allows.
        # There is no single "everyone ready" instant — start sampling
        # immediately so the CSV captures the ramp-up faithfully.
        logger.info(
            "Sliding-window mode (parallel_agents=%d) — sampling starts now.",
            parallel_agents,
        )

    # Per-scenario override of the grace window after agents finish; the
    # CLI default applies when the scenario doesn't set it.
    drain_timeout = float(behavior.get("drain_timeout", args.drain_timeout))

    # Watcher thread: signals stats_collector when every agent loop has
    # exited. Required for `repeat_until=0` runs, where there is no
    # meaningful wall-clock deadline — without this signal stats_collector
    # would keep writing zero-rows until the 24 h fallback deadline.
    agents_done = threading.Event()
    def _watch_agents():
        for t in threads:
            t.join()
        agents_done.set()
        logger.info("All agent loops exited; signalling drain phase.")
    watcher_thread = threading.Thread(
        target=_watch_agents, daemon=True, name="agent-watcher",
    )
    watcher_thread.start()

    run_meta = {
        "scenario_name":        scenario["name"],
        "scenario_path":        args.scenario,
        "manager":              args.manager,
        "port":                 args.port,
        "total_agents":         total_agents,
        "agents_registered":    len(agents),
        "parallel_agents":      parallel_agents,
        "repeat_until":         repeat_until,
        "drain_timeout":        drain_timeout,
        "agent_configs":        configs,
        "started_at":           datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    stats_collector(
        counters,
        args.output,
        deadline,
        drain_timeout=drain_timeout,
        summary_json_path=args.summary_json,
        run_meta=run_meta,
        agents_done=agents_done,
    )

    _running = False
    join_deadline = time.monotonic() + 5.0
    for t in threads:
        remaining = max(0.1, join_deadline - time.monotonic())
        t.join(timeout=remaining)

    still_alive = sum(1 for t in threads if t.is_alive())
    if still_alive:
        logger.warning(
            "%d agent thread(s) still alive after 5s; they are daemons and "
            "will be killed at process exit.",
            still_alive,
        )

    logger.info("Benchmark complete. Results in %s", args.output)


if __name__ == "__main__":
    main()
