#!/usr/bin/env python3
from __future__ import annotations
"""
Inventory Sync benchmark sender – multi-agent load generator.

Simulates N concurrent agents, each running continuous sync sessions
(Start → DataValue×M → End → wait ACK → repeat) for a configurable
duration.  Writes per-second statistics to CSV for comparison with the
resource monitor output.

Usage:
    # 50 agents, 100 data items each, for 60s
    python3 benchmark_sender.py \\
        -a 50 -d 100 -t 60 \\
        --manager 127.0.0.1 \\
        -o bench.csv

    # Throttled to the Wazuh default of 75 wire-events/second per agent,
    # one first-sync per agent (matches real-agent semantics), 200 agents.
    python3 benchmark_sender.py \\
        -a 200 -d 500 -t 120 --max-eps 75 --sessions-per-agent 1 \\
        --manager 127.0.0.1 \\
        -o bench.csv

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
import signal
import socket
import ssl
import struct
import sys
import threading
import time
import zlib
from collections import defaultdict
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
    """
    First Ctrl+C: graceful shutdown — flip _running; agent threads will exit
    after the current recv() times out or completes.
    Second Ctrl+C: hard exit — kill the process immediately. Useful because
    socket.recv() with a long timeout (e.g. 120s for EndAck) doesn't react
    to the flag until the timeout elapses.
    """
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
# Each kind matches the dynamic:strict mapping of its destination index
# (src/external/indexer-plugins/*.json).
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

# Pad target for --payload-size: dotted path to an existing free-text string
# field in the mapping. Adding a new top-level field (e.g. "_pad") would be
# rejected by the dynamic:strict mappings of wazuh-states-* indices with
# (status 400) 'mapping set to strict, dynamic introduction of [_pad] within
# [_doc] is not allowed' — so we extend an existing field instead.
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
)


class AtomicCounters:
    """Thread-safe per-second counters for benchmark statistics."""

    def __init__(self):
        self._lock = threading.Lock()
        self._counters = {k: 0 for k in COUNTER_FIELDS}
        # Latency samples are kept across the whole run for final percentiles.
        self._latency_lock = threading.Lock()
        self._latency_start_ms: list[float] = []   # Start sent -> StartAck received
        self._latency_end_ms: list[float] = []     # End sent -> EndAck(Ok) received
        self._latency_session_ms: list[float] = [] # Start sent -> EndAck(Ok) received

    def add(self, field: str, n: int = 1):
        with self._lock:
            self._counters[field] = self._counters.get(field, 0) + n

    # Backwards-compatible helpers (used by older call sites in this module).
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
        """Return percentile summary across the whole run. Not reset."""
        def pct(samples: list[float]) -> dict:
            if not samples:
                return {"count": 0}
            s = sorted(samples)
            def q(p):
                if not s:
                    return None
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
# Lightweight agent (reuses crypto from wazuh_agent_controller.py)
# ---------------------------------------------------------------------------
class BenchmarkAgent:
    """Minimal Wazuh agent for benchmark purposes.

    Handles registration, connection, message sending/receiving
    with minimal logging overhead.
    """

    def __init__(
        self,
        agent_id: int,
        manager_address: str,
        manager_port: int = 1514,
        reg_port: int = 1515,
        cipher: str = "aes",
    ):
        self.agent_num = agent_id
        self.manager_address = manager_address
        self.manager_port = manager_port
        self.reg_port = reg_port
        self.cipher = cipher

        self.id: str | None = None
        self.name: str | None = None
        self.key: str | None = None
        self.encryption_key: bytes | None = None
        self.sock: socket.socket | None = None

        self.fb_manager = None
        self._load_flatbuffers()

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

            # Send startup control message
            ctrl = f'#!-agent startup {{"version":"4.8.0","name":"{self.name}","id":"{self.id}"}}'
            self._send_text(ctrl)
            time.sleep(1.0)

            # Drain any startup response from the buffer to avoid
            # it being read as the first session response.
            self._drain_recv_buffer()
            return True
        except Exception as e:
            logger.error("Agent %s connect failed: %s", self.id, e)
            return False

    def _drain_recv_buffer(self):
        """Read and discard any data sitting in the TCP receive buffer."""
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
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

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

    def _frame_and_send(self, raw_event: bytes):
        if not self.sock:
            raise RuntimeError("Not connected")
        length = struct.pack("<I", len(raw_event))
        self.sock.sendall(length + raw_event)

    def _send_text(self, text: str):
        event = self._compose_event(text.encode())
        compressed = zlib.compress(event)
        padded = self._wazuh_pad(compressed)
        encrypted = self._encrypt(padded)
        header = f"!{self.id}!#AES:".encode()
        self._frame_and_send(header + encrypted)

    def _send_binary(self, identifier: str, binary_data: bytes):
        s_prefix = b"s:"
        id_bytes = identifier.encode()
        msg = b"55555" + b"1234567891" + b":" + b"5555" + b":" + s_prefix + id_bytes + b":" + binary_data
        md5 = hashlib.md5(msg).hexdigest().encode()
        event = md5 + msg
        compressed = zlib.compress(event)
        padded = self._wazuh_pad(compressed)
        encrypted = self._encrypt(padded)
        header = f"!{self.id}!#AES:".encode()
        self._frame_and_send(header + encrypted)

    # -- Receive response ---------------------------------------------------
    def receive_response(self, timeout: float = 30.0) -> dict | None:
        if not self.sock:
            return None
        try:
            self.sock.settimeout(timeout)
            length_data = self.sock.recv(4)
            if not length_data or len(length_data) < 4:
                return None
            length = struct.unpack("<I", length_data)[0]
            data = b""
            while len(data) < length:
                chunk = self.sock.recv(length - len(data))
                if not chunk:
                    break
                data += chunk
            if len(data) != length:
                return None

            # Decrypt
            if data.startswith(b"#AES:"):
                decrypted = self._decrypt(data[5:])
                # Remove padding
                i = 0
                while i < len(decrypted) and decrypted[i] == ord("!"):
                    i += 1
                decompressed = zlib.decompress(decrypted[i:])
                # Skip MD5(32) + random(5) + global(10) + : + local(4) + :
                colon2 = 32 + 5 + 10 + 1 + 4
                if colon2 + 1 < len(decompressed):
                    message = decompressed[colon2 + 1:]
                    return self._parse_response(message)
            return None
        except (socket.timeout, OSError):
            return None

    def _parse_response(self, message: bytes) -> dict | None:
        fb_bytes = None

        if message.startswith(b"s:"):
            # Agent→manager format: s:identifier:binary_data
            parts = message.split(b":", 2)
            if len(parts) >= 3:
                fb_bytes = parts[2]
        elif message.startswith(b"#!-"):
            # Manager→agent format: #!-identifier {binary_data}
            # Find first space after the prefix
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
        data = {
            "session": session_id,
            "seq": seq,
            "index": index,
            "id": doc_id,
            "data": payload,
            "operation": operation,
        }
        return self.fb_manager.create_message("data", data)

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
        items: list[tuple[int, str, Any, int]],
        index: str,
    ) -> bytes | None:
        """Build a Message{DataBatch{DataValue[]}} FlatBuffer.

        Each item is (seq, doc_id, payload, operation). Constructed directly
        with the generated FlatBuffers classes to avoid touching the shared
        FlatBuffersManager (which is also used by QA). Mirrors the layout
        consumed by inventorySyncFacade.hpp under MessageType_DataBatch.
        """
        if not self.fb_manager or not items:
            return None
        import flatbuffers
        import Wazuh.SyncSchema.DataValue as DataValueModule
        import Wazuh.SyncSchema.DataBatch as DataBatchModule
        import Wazuh.SyncSchema.Message as MessageModule
        from Wazuh.SyncSchema.MessageType import MessageType

        builder = flatbuffers.Builder(1024)

        dv_offsets: list[int] = []
        for seq, doc_id, payload, operation in items:
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
# Single-agent benchmark worker
# ---------------------------------------------------------------------------
def agent_worker(
    agent: BenchmarkAgent,
    cfg: dict,
    counters: AtomicCounters,
    payload_template: dict,
    deadline: float,
    barrier: threading.Barrier,
):
    """Thread function: connect a pre-registered agent, run sessions until deadline."""
    global _running

    module = cfg["module"]
    data_size = cfg["data_size"]
    index = cfg["index"]
    drop_every = cfg.get("drop_every", 0)
    no_end = cfg.get("no_end", False)
    use_databatch = cfg.get("use_databatch", False)
    batch_max_bytes = cfg.get("batch_max_bytes", 60 * 1024)
    session_type = cfg.get("session_type", "delta")
    sync_mode = cfg.get("sync_mode", 1)
    mc_checksum = cfg.get("modulecheck_checksum", "0" * 40)
    auto_resync = cfg.get("auto_resync", False)
    end_delay = cfg.get("end_delay", 1.0)
    retransmit = cfg.get("retransmit", True)
    max_eps = cfg.get("max_eps", 0)
    sessions_per_agent = cfg.get("sessions_per_agent", 0)  # 0 = unlimited (legacy default)

    # Connect (agent is already registered and keys are loaded)
    if not agent.connect():
        counters.add_sessions_failed()
        logger.error("Agent %s: connection failed, exiting thread", agent.id)
        try:
            barrier.wait(timeout=5)
        except threading.BrokenBarrierError:
            pass
        return

    # Per-agent EPS rate limiter. Mirrors the agent-side throttle that real
    # Wazuh agents apply via the syscollector synchronization <max_eps> config
    # (default 75 events/sec per agent). With max_eps=0 there is no throttle
    # and the sender bursts at full TCP speed.
    #
    # Algorithm: target inter-message spacing of 1/max_eps seconds. Track the
    # count of messages sent since the agent's start; message N must not be
    # released before t0 + N/max_eps. If a previous send ran fast we just
    # advance the counter; if we're ahead of schedule we sleep the diff.
    # This converges exactly to max_eps EPS in steady state (no burst penalty
    # like the naive window-and-sleep approach).
    if max_eps > 0:
        original_send = agent._send_binary
        eps_state = {"t0": time.monotonic(), "sent": 0}

        def throttled_send(identifier: str, binary_data: bytes,
                           _orig=original_send, _state=eps_state, _cap=max_eps):
            _state["sent"] += 1
            target_t = _state["t0"] + _state["sent"] / _cap
            now = time.monotonic()
            if now < target_t:
                time.sleep(target_t - now)
            return _orig(identifier, binary_data)

        agent._send_binary = throttled_send

    logger.info("Agent %s (%s) ready", agent.id, agent.name)

    # Wait for all agents to be ready
    try:
        barrier.wait(timeout=60)
    except threading.BrokenBarrierError:
        logger.error("Agent %s: barrier broken", agent.id)
        agent.disconnect()
        return

    session_count = 0
    while _running and time.monotonic() < deadline:
        session_count += 1

        # Reconnect before each session to avoid stale connections.
        # Remoted may close idle TCP sockets; a fresh connection ensures
        # Start messages are not silently dropped.
        if session_count > 1:
            agent.disconnect()
            if not agent.connect():
                logger.error("Agent %s pre-session reconnect failed, exiting", agent.id)
                break

        try:
            if session_type == "modulecheck":
                _run_modulecheck_session(
                    agent, module, index, mc_checksum, counters,
                    auto_resync=auto_resync,
                    data_size=data_size,
                    payload_template=payload_template,
                )
            elif session_type == "dataclean":
                _run_dataclean_session(agent, module, index, counters)
            else:
                _run_single_session(
                    agent, module, data_size, index, payload_template, counters,
                    drop_every=drop_every,
                    no_end=no_end,
                    use_databatch=use_databatch,
                    batch_max_bytes=batch_max_bytes,
                    sync_mode=sync_mode,
                    end_delay=end_delay,
                    retransmit=retransmit,
                )
        except Exception as e:
            logger.debug("Agent %s session %d failed: %s", agent.id, session_count, e)
            counters.add_sessions_failed()
            # Reconnect
            agent.disconnect()
            time.sleep(1.0)
            if not agent.connect():
                logger.error("Agent %s reconnect failed, exiting", agent.id)
                break

        # Single-shot / N-shot mode: exit after sessions_per_agent sessions.
        # Matches the real-agent behaviour where syscollector emits exactly
        # one first-sync per <interval> instead of looping continuously.
        if sessions_per_agent > 0 and session_count >= sessions_per_agent:
            logger.info(
                "Agent %s completed %d session(s) — exiting (sessions_per_agent=%d).",
                agent.id, session_count, sessions_per_agent,
            )
            break

    agent.disconnect()
    logger.info("Agent %s finished (%d sessions)", agent.id, session_count)


def _run_single_session(
    agent: BenchmarkAgent,
    module: str,
    data_size: int,
    index: str,
    payload_template: dict,
    counters: AtomicCounters,
    drop_every: int = 0,
    no_end: bool = False,
    use_databatch: bool = False,
    batch_max_bytes: int = 60 * 1024,
    sync_mode: int = 1,
    end_delay: float = 1.0,
    retransmit: bool = True,
):
    """Execute one complete sync session: Start → Data×N → [sleep] → End → ACK.

    Flags:
      drop_every       If >0, skip DataValues where (seq+1) % drop_every == 0.
                       Forces ReqRet/missing_ranges on the manager.
      no_end           Skip the End message and EndAck wait. The manager-side
                       session_timeout reclaims the session. Used by no_end.json
                       to validate the timeout/cleanup path.
      use_databatch    Send DataValues as MessageType_DataBatch packed by the
                       agent's MAX_BATCH_PAYLOAD policy (cap by bytes, not by
                       count) instead of one DataValue per message.
      batch_max_bytes  Cap per DataBatch in estimated bytes (default 60 KB —
                       same constant as the real agent's
                       shared_modules/sync_protocol/.../MAX_BATCH_PAYLOAD).
                       Only used with use_databatch=True.
      end_delay      Seconds to sleep between the last DataValue and the End
                     message.
      retransmit     If True (default), on ReqRet the sender retransmits the
                     missing sequences and waits for EndAck — matching the
                     real agent (shared_modules/sync_protocol). If False,
                     the first ReqRet aborts the session.
    """

    # 1. Send Start
    fb_start = agent.create_start_message(
        module=module, mode=sync_mode, size=data_size, option=0,
        indices=[index],
    )
    if fb_start is None:
        raise RuntimeError("Failed to create Start message")

    t_start_sent = time.monotonic()
    agent._send_binary(f"{module}_sync", fb_start)
    counters.add_messages_sent()
    counters.add_sessions_started()

    # 2. Wait for StartAck (record Start→StartAck latency). Poll in short
    # slices so Ctrl+C is noticed quickly.
    resp = None
    start_recv = time.monotonic()
    while time.monotonic() - start_recv < 15.0:
        if not _running:
            raise RuntimeError("Shutdown requested while waiting for StartAck")
        resp = agent.receive_response(timeout=1.0)
        if resp is not None:
            break
    if resp is None:
        raise RuntimeError("No StartAck received")

    t_start_ack = time.monotonic()
    counters.record_latency("start", (t_start_ack - t_start_sent) * 1000.0)

    # Extract session ID + status from StartAck
    session_id = None
    if resp.get("type") == "flatbuffer":
        data = resp.get("data", {})
        if isinstance(data, dict) and data.get("type") == "start_ack":
            session_id = data.get("session_id") or data.get("session")
            status = data.get("status", -1)
            if status == STATUS_OK:
                counters.add("start_ack_ok")
            elif status == STATUS_PROCESSING:
                # Treat as OK for accounting; spec uses Processing during async paths
                counters.add("start_ack_ok")
            elif status == STATUS_OFFLINE:
                counters.add("start_ack_offline")
                raise RuntimeError("StartAck offline (manager saturated or unavailable)")
            else:
                counters.add("start_ack_error")
                raise RuntimeError(f"StartAck rejected: status={status}")

    if session_id is None:
        raise RuntimeError(f"Could not extract session ID from response: {resp}")

    # 3. Send DataValue messages (one-per-message or batched).
    #
    # Vary doc_id per sequence to create unique documents.
    # The payload is sent verbatim — we do NOT inject extra fields like
    # package.name because that breaks dynamic:strict mappings of kinds
    # that don't have a `package` field (system, fim_file, sca_check) or
    # that use a different shape (hotfix has package.hotfix.name only).
    def _should_drop(seq: int) -> bool:
        return drop_every > 0 and (seq + 1) % drop_every == 0

    if use_databatch:
        # Mirror the real agent's batching policy: pack DataValues into a
        # DataBatch until the *estimated bytes* on the wire approach the cap.
        # Constants match shared_modules/sync_protocol/.../agent_sync_protocol.cpp:
        #   FLATBUFFERS_OVERHEAD_PER_ITEM = 80
        #   BATCH_MESSAGE_OVERHEAD        = 128
        # so the bench builds DataBatches with the same shape (same items per
        # batch) as the real agent for any given payload size.
        FB_OVERHEAD_PER_ITEM = 80
        BATCH_MESSAGE_OVERHEAD = 128

        # Pre-compute the JSON bytes of the payload once; it is the same value
        # for every DataValue in this session (template is read-only).
        try:
            payload_bytes_len = len(json.dumps(payload_template).encode("utf-8"))
        except Exception:
            payload_bytes_len = 600  # conservative fallback

        index_len = len(index)
        pending: list[tuple[int, str, Any, int]] = []
        batch_est = BATCH_MESSAGE_OVERHEAD

        def _flush_batch() -> None:
            nonlocal batch_est
            if not pending:
                return
            fb_batch = agent.create_data_batch_message(session_id, pending, index)
            if fb_batch is None:
                raise RuntimeError("Failed to create DataBatch message")
            agent._send_binary(f"{module}_sync", fb_batch)
            counters.add_messages_sent()
            pending.clear()
            batch_est = BATCH_MESSAGE_OVERHEAD

        for seq in range(data_size):
            if not _running:
                break
            if _should_drop(seq):
                continue
            doc_id = f"{agent.id}-{session_id}-{seq}"
            # FB-overhead + doc_id chars + index chars + payload bytes.
            item_size = FB_OVERHEAD_PER_ITEM + len(doc_id) + index_len + payload_bytes_len
            if pending and batch_est + item_size > batch_max_bytes:
                _flush_batch()
            pending.append((seq, doc_id, payload_template, 0))
            batch_est += item_size
        if _running:
            _flush_batch()
    else:
        for seq in range(data_size):
            if not _running:
                break
            if _should_drop(seq):
                continue
            doc_id  = f"{agent.id}-{session_id}-{seq}"
            fb_data = agent.create_data_value_message(
                session_id=session_id,
                seq=seq,
                index=index,
                doc_id=doc_id,
                payload=payload_template,
            )
            if fb_data is None:
                raise RuntimeError(f"Failed to create DataValue seq={seq}")
            agent._send_binary(f"{module}_sync", fb_data)
            counters.add_messages_sent()

    # --no-end: skip End entirely. The session is left open server-side and
    # is reclaimed by the module's session_timeout. We count the session as
    # completed for accounting (the agent did everything it intended to do);
    # end-ack and session-full latency are simply not recorded.
    if no_end:
        counters.add_sessions_completed()
        return

    # Mirror the real agent: sleep `sync_end_delay` seconds before sending End
    # so the server's WorkersQueue can drain in-flight DataValues into the
    # GapSet. Without this, handleEnd may see false gaps and emit ReqRet
    # even though TCP delivered everything in order.
    if end_delay > 0 and _running:
        sleep_remaining = end_delay
        while sleep_remaining > 0 and _running:
            slice_s = min(sleep_remaining, 0.5)
            time.sleep(slice_s)
            sleep_remaining -= slice_s

    # 4. Send End
    fb_end = agent.create_end_message(session_id)
    if fb_end is None:
        raise RuntimeError("Failed to create End message")
    t_end_sent = time.monotonic()
    agent._send_binary(f"{module}_sync", fb_end)
    counters.add_messages_sent()

    # 5. Wait for EndAck (may receive Processing first, then final).
    #    The server's WorkersQueue is multi-threaded so End may be processed
    #    before all DataValues.  When that happens the server replies with a
    #    ReqRet listing missing sequences.  We retransmit those and resend End.
    MAX_RETRANSMIT = 5
    max_wait = 120.0
    start_wait = time.monotonic()
    retransmit_count = 0
    while time.monotonic() - start_wait < max_wait:
        if not _running:
            # Ctrl+C: don't keep blocking on socket reads for many seconds.
            raise RuntimeError("Shutdown requested while waiting for EndAck")
        # Cap the per-recv timeout so a SIGINT is noticed within a few seconds.
        remaining = max_wait - (time.monotonic() - start_wait)
        resp = agent.receive_response(timeout=min(remaining, 2.0))
        if resp is None:
            # Either timed out (loop will re-check _running) or got a partial
            # frame. Only treat as missing EndAck when we've exhausted max_wait.
            if time.monotonic() - start_wait >= max_wait:
                raise RuntimeError("No EndAck received")
            continue
        if resp.get("type") == "flatbuffer":
            data = resp.get("data", {})
            if isinstance(data, dict):
                if data.get("type") == "end_ack":
                    status = data.get("status", -1)
                    if status == STATUS_PROCESSING:
                        counters.add("end_ack_processing")
                        continue  # wait for final
                    if status == STATUS_OK:
                        t_end_ack = time.monotonic()
                        counters.add("end_ack_ok")
                        counters.add_sessions_completed()
                        counters.record_latency("end",     (t_end_ack - t_end_sent)   * 1000.0)
                        counters.record_latency("session", (t_end_ack - t_start_sent) * 1000.0)
                        return
                    elif status == STATUS_OFFLINE:
                        counters.add("end_ack_offline")
                        raise RuntimeError("EndAck offline")
                    else:
                        counters.add("end_ack_error")
                        raise RuntimeError(f"EndAck error status={status}")
                elif data.get("type") == "reqret":
                    counters.add("reqret")
                    ranges = data.get("ranges", []) or []
                    counters.add("missing_ranges_total", len(ranges))
                    if not retransmit:
                        counters.add_messages_dropped()
                        raise RuntimeError(
                            "ReqRet received and retransmit is disabled"
                        )
                    retransmit_count += 1
                    if retransmit_count > MAX_RETRANSMIT:
                        counters.add_messages_dropped()
                        raise RuntimeError(
                            f"ReqRet: exceeded {MAX_RETRANSMIT} retransmissions"
                        )
                    # Retransmit the missing sequences only.
                    for r in ranges:
                        for seq in range(r["start"], r["end"] + 1):
                            doc_id = f"{agent.id}-{session_id}-{seq}"
                            fb_retx = agent.create_data_value_message(
                                session_id=session_id,
                                seq=seq,
                                index=index,
                                doc_id=doc_id,
                                payload=payload_template,
                            )
                            if fb_retx:
                                agent._send_binary(f"{module}_sync", fb_retx)
                                counters.add_messages_sent()

    raise RuntimeError("EndAck timeout")


# ---------------------------------------------------------------------------
# ModuleCheck session
# ---------------------------------------------------------------------------
def _run_modulecheck_session(
    agent: BenchmarkAgent,
    module: str,
    index: str,
    checksum: str,
    counters: AtomicCounters,
    auto_resync: bool = False,
    data_size: int = 100,
    payload_template: dict | None = None,
):
    """Execute a ModuleCheck session: Start(mode=2) → ChecksumModule → End → EndAck.

    If EndAck = ChecksumMismatch and auto_resync=True, immediately runs a
    ModuleFull session to simulate the full recovery cycle.
    """
    global _running

    fb_start = agent.create_start_message(
        module=module, mode=2, size=0, option=0, indices=[index],
    )
    if fb_start is None:
        raise RuntimeError("Failed to create Start message for ModuleCheck")

    t_start_sent = time.monotonic()
    agent._send_binary(f"{module}_sync", fb_start)
    counters.add_messages_sent()
    counters.add_sessions_started()

    # Wait for StartAck
    resp = None
    start_recv = time.monotonic()
    while time.monotonic() - start_recv < 15.0:
        if not _running:
            raise RuntimeError("Shutdown during ModuleCheck StartAck wait")
        resp = agent.receive_response(timeout=1.0)
        if resp is not None:
            break
    if resp is None:
        raise RuntimeError("No StartAck received (ModuleCheck)")

    counters.record_latency("start", (time.monotonic() - t_start_sent) * 1000.0)

    session_id = None
    if resp.get("type") == "flatbuffer":
        data = resp.get("data", {})
        if isinstance(data, dict) and data.get("type") == "start_ack":
            session_id = data.get("session_id") or data.get("session")
            status = data.get("status", -1)
            if status == STATUS_OFFLINE:
                counters.add("start_ack_offline")
                raise RuntimeError("StartAck offline (ModuleCheck)")
            elif status not in (STATUS_OK, STATUS_PROCESSING):
                counters.add("start_ack_error")
                raise RuntimeError(f"StartAck error status={status} (ModuleCheck)")
            counters.add("start_ack_ok")

    if session_id is None:
        raise RuntimeError(f"Could not extract session_id (ModuleCheck): {resp}")

    # Send ChecksumModule then End
    fb_checksum = agent.create_checksum_module_message(session_id, index, checksum)
    if fb_checksum is None:
        raise RuntimeError("Failed to create ChecksumModule message")
    agent._send_binary(f"{module}_sync", fb_checksum)
    counters.add_messages_sent()

    fb_end = agent.create_end_message(session_id)
    if fb_end is None:
        raise RuntimeError("Failed to create End message (ModuleCheck)")
    t_end_sent = time.monotonic()
    agent._send_binary(f"{module}_sync", fb_end)
    counters.add_messages_sent()

    # Wait for EndAck — ModuleCheck can block up to 5 retries × 10s = 50s
    max_wait = 70.0
    start_wait = time.monotonic()
    while time.monotonic() - start_wait < max_wait:
        if not _running:
            raise RuntimeError("Shutdown during ModuleCheck EndAck wait")
        remaining = max_wait - (time.monotonic() - start_wait)
        resp = agent.receive_response(timeout=min(remaining, 2.0))
        if resp is None:
            if time.monotonic() - start_wait >= max_wait:
                raise RuntimeError("EndAck timeout (ModuleCheck)")
            continue
        if resp.get("type") == "flatbuffer":
            data = resp.get("data", {})
            if not isinstance(data, dict) or data.get("type") != "end_ack":
                continue
            status = data.get("status", -1)
            if status == STATUS_PROCESSING:
                counters.add("end_ack_processing")
                continue
            t_end_ack = time.monotonic()
            counters.record_latency("end",     (t_end_ack - t_end_sent)   * 1000.0)
            counters.record_latency("session", (t_end_ack - t_start_sent) * 1000.0)
            if status == STATUS_OK:
                counters.add("end_ack_ok")
                counters.add_sessions_completed()
                return
            elif status == STATUS_CHECKSUM_MISMATCH:
                counters.add("end_ack_error")
                counters.add_sessions_completed()
                if auto_resync and payload_template is not None:
                    logger.debug(
                        "Agent %s: ChecksumMismatch → starting ModuleFull recovery",
                        agent.id,
                    )
                    _run_single_session(
                        agent, module, data_size, index, payload_template,
                        counters, sync_mode=0,
                    )
                return
            elif status == STATUS_OFFLINE:
                counters.add("end_ack_offline")
                raise RuntimeError("EndAck offline (ModuleCheck)")
            else:
                counters.add("end_ack_error")
                raise RuntimeError(f"EndAck error status={status} (ModuleCheck)")

    raise RuntimeError("EndAck timeout (ModuleCheck)")


# ---------------------------------------------------------------------------
# DataClean session
# ---------------------------------------------------------------------------
def _run_dataclean_session(
    agent: BenchmarkAgent,
    module: str,
    index: str,
    counters: AtomicCounters,
):
    """Execute a DataClean session: Start → DataClean → End → EndAck.

    Simulates an agent removing all SCA policies. The manager calls
    deleteByQuery(index, agentId) for each agent that sends this.
    """
    global _running

    fb_start = agent.create_start_message(
        module=module, mode=1, size=1, option=0, indices=[index],
    )
    if fb_start is None:
        raise RuntimeError("Failed to create Start message for DataClean")

    t_start_sent = time.monotonic()
    agent._send_binary(f"{module}_sync", fb_start)
    counters.add_messages_sent()
    counters.add_sessions_started()

    # Wait for StartAck
    resp = None
    start_recv = time.monotonic()
    while time.monotonic() - start_recv < 15.0:
        if not _running:
            raise RuntimeError("Shutdown during DataClean StartAck wait")
        resp = agent.receive_response(timeout=1.0)
        if resp is not None:
            break
    if resp is None:
        raise RuntimeError("No StartAck received (DataClean)")

    counters.record_latency("start", (time.monotonic() - t_start_sent) * 1000.0)

    session_id = None
    if resp.get("type") == "flatbuffer":
        data = resp.get("data", {})
        if isinstance(data, dict) and data.get("type") == "start_ack":
            session_id = data.get("session_id") or data.get("session")
            status = data.get("status", -1)
            if status == STATUS_OFFLINE:
                counters.add("start_ack_offline")
                raise RuntimeError("StartAck offline (DataClean)")
            elif status not in (STATUS_OK, STATUS_PROCESSING):
                counters.add("start_ack_error")
                raise RuntimeError(f"StartAck error status={status} (DataClean)")
            counters.add("start_ack_ok")

    if session_id is None:
        raise RuntimeError(f"Could not extract session_id (DataClean): {resp}")

    # Send DataClean then End
    fb_dataclean = agent.create_data_clean_message(session_id, seq=0, index=index)
    if fb_dataclean is None:
        raise RuntimeError("Failed to create DataClean message")
    agent._send_binary(f"{module}_sync", fb_dataclean)
    counters.add_messages_sent()

    fb_end = agent.create_end_message(session_id)
    if fb_end is None:
        raise RuntimeError("Failed to create End message (DataClean)")
    t_end_sent = time.monotonic()
    agent._send_binary(f"{module}_sync", fb_end)
    counters.add_messages_sent()

    # Wait for EndAck
    max_wait = 60.0
    start_wait = time.monotonic()
    while time.monotonic() - start_wait < max_wait:
        if not _running:
            raise RuntimeError("Shutdown during DataClean EndAck wait")
        remaining = max_wait - (time.monotonic() - start_wait)
        resp = agent.receive_response(timeout=min(remaining, 2.0))
        if resp is None:
            if time.monotonic() - start_wait >= max_wait:
                raise RuntimeError("EndAck timeout (DataClean)")
            continue
        if resp.get("type") == "flatbuffer":
            data = resp.get("data", {})
            if not isinstance(data, dict) or data.get("type") != "end_ack":
                continue
            status = data.get("status", -1)
            if status == STATUS_PROCESSING:
                counters.add("end_ack_processing")
                continue
            t_end_ack = time.monotonic()
            counters.record_latency("end",     (t_end_ack - t_end_sent)   * 1000.0)
            counters.record_latency("session", (t_end_ack - t_start_sent) * 1000.0)
            if status == STATUS_OK:
                counters.add("end_ack_ok")
                counters.add_sessions_completed()
                return
            elif status == STATUS_OFFLINE:
                counters.add("end_ack_offline")
                raise RuntimeError("EndAck offline (DataClean)")
            else:
                counters.add("end_ack_error")
                raise RuntimeError(f"EndAck error status={status} (DataClean)")

    raise RuntimeError("EndAck timeout (DataClean)")


# ---------------------------------------------------------------------------
# Per-second statistics collector
# ---------------------------------------------------------------------------
CSV_HEADER = ["timestamp", "elapsed_s"] + list(COUNTER_FIELDS)


def stats_collector(
    counters: AtomicCounters,
    csv_path: str,
    start_time: float,
    deadline: float,
    drain_timeout: float = 60.0,
    summary_json_path: str | None = None,
    run_meta: dict | None = None,
):
    """Runs in main thread: samples counters every second, writes CSV.

    Phases:
      1) "send phase":  time.monotonic() < deadline. Agents push new sessions.
      2) "drain phase": deadline reached but we keep sampling until either
                        (a) all started sessions cerraron (ok/failed),
                        (b) drain_timeout segundos pasaron desde deadline,
                        (c) Ctrl+C.
    Without this the last burst is reported as "failed" simply because the
    benchmark cut before EndAck arrived (manager latency can be 15-25s per
    session under indexer refresh_interval=1s).

    On exit, writes a one-shot summary JSON with cumulative counters and
    latency percentiles (Start->StartAck, End->EndAck, full session).
    """
    global _running

    with open(csv_path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_HEADER)
        writer.writeheader()
        fh.flush()

        second = 0
        cumulative = defaultdict(int)
        announced_drain = False

        while _running:
            time.sleep(1.0)
            second += 1
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

            phase = "drain" if time.monotonic() >= deadline else "send"
            if phase == "drain" and not announced_drain:
                announced_drain = True
                logger.info(
                    "Deadline reached. Entering drain phase (in_flight=%d, "
                    "drain_timeout=%.0fs).",
                    in_flight, drain_timeout,
                )

            logger.info(
                "[%3ds %5s]  sent=%d  started=%d  completed=%d  failed=%d  "
                "in_flight=%d  start_ack(ok/off/err)=%d/%d/%d  "
                "end_ack(ok/off/err/proc)=%d/%d/%d/%d  reqret=%d  missing=%d",
                second, phase,
                snap["messages_sent"],
                snap["sessions_started"],
                snap["sessions_completed"],
                snap["sessions_failed"],
                in_flight,
                snap["start_ack_ok"], snap["start_ack_offline"], snap["start_ack_error"],
                snap["end_ack_ok"], snap["end_ack_offline"], snap["end_ack_error"], snap["end_ack_processing"],
                snap["reqret"], snap["missing_ranges_total"],
            )

            # Exit conditions, only after the send deadline has passed:
            if phase == "drain":
                if in_flight <= 0:
                    logger.info("All in-flight sessions drained after %ds.", second)
                    break
                if time.monotonic() > deadline + drain_timeout:
                    logger.warning(
                        "Drain timeout reached with %d session(s) still in flight.",
                        in_flight,
                    )
                    break

    latency = counters.latency_summary()

    # Console summary
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
    print(f"  Missing ranges total: {cumulative['missing_ranges_total']:,}")
    print(f"  Messages dropped:     {cumulative['messages_dropped']:,}")
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

    # Machine-readable summary
    if summary_json_path:
        summary = {
            "meta":     run_meta or {},
            "duration_sec": second,
            "messages":   dict(cumulative),
            "latency_ms": latency,
        }
        with open(summary_json_path, "w") as jf:
            json.dump(summary, jf, indent=2, default=str)
        logger.info("Summary written: %s", summary_json_path)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Inventory Sync multi-agent benchmark sender.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("-a", "--agents", type=int, default=10,
                   help="Number of concurrent agents (default: 10)")
    p.add_argument("-d", "--data-size", type=int, default=100,
                   help="DataValue messages per session (default: 100)")
    p.add_argument("-t", "--duration", type=int, default=60,
                   help="Test duration in seconds (default: 60)")
    p.add_argument("--manager", type=str, default="127.0.0.1",
                   help="Manager address (default: 127.0.0.1)")
    p.add_argument("--port", type=int, default=1514,
                   help="Manager port (default: 1514)")
    p.add_argument("--reg-port", type=int, default=1515,
                   help="Registration port (default: 1515)")
    p.add_argument("-o", "--output", type=str, default="bench.csv",
                   help="Output CSV file (default: bench.csv)")
    p.add_argument("--summary-json", type=str, default=None,
                   help="If set, write a final summary JSON with totals and "
                        "latency percentiles (p50/p90/p95/p99/max).")
    p.add_argument("--module", type=str, default=None,
                   help="Module name (default: comes from --payload-kind, "
                        "or 'syscollector' if --payload is used).")
    p.add_argument("--index", type=str, default=None,
                   help="Index name (default: comes from --payload-kind, "
                        "or 'wazuh-states-inventory-packages' if --payload is used). "
                        "Must accept the payload shape (dynamic:strict mapping).")
    p.add_argument("--payload-kind", choices=list(PAYLOAD_KINDS.keys()),
                   default="package",
                   help="Built-in payload shape (default: package). Selects the "
                        "matching sample file under sample_payloads/ and sets "
                        "module/index defaults so they match the index mapping.")
    p.add_argument("--payload", type=str, default=None,
                   help="Custom JSON payload file. Overrides --payload-kind.")
    p.add_argument("--drain-timeout", type=float, default=60.0,
                   help="After the duration deadline, keep waiting up to N "
                        "seconds for in-flight sessions to close before forcing "
                        "exit (default: 60). EndAck latency at the indexer can "
                        "be 15-25s, so 0 will mark the last burst as failed.")
    p.add_argument("--key-wait", type=int, default=35,
                   help="Seconds to wait after registration for remoted key reload (default: 35)")
    p.add_argument("--payload-size", type=int, default=0,
                   help="If > 0, pad each DataValue payload to at least N bytes "
                        "by extending a free-text field of the payload. Target "
                        "field is picked from PAD_FIELD_BY_KIND based on "
                        "--payload-kind (e.g. file.path for fim_file). Used by "
                        "large_payload.json / heavy_payload_burst.json to stress "
                        "the m_workersQueue with heavy elements (default: 0).")
    p.add_argument("--pad-field", type=str, default=None,
                   help="Dotted path of the payload field to extend with the "
                        "'_pad' filler. Overrides PAD_FIELD_BY_KIND default. "
                        "Must be an existing string field — wazuh-states-* "
                        "indices are dynamic:strict, so new fields are rejected.")
    p.add_argument("--drop-every", type=int, default=0,
                   help="If > 0, skip every Nth DataValue (drops seq=N-1, 2N-1, "
                        "...). Forces ReqRet/missing_ranges on the manager. "
                        "Used by missing_seq.json (default: 0).")
    p.add_argument("--no-end", action="store_true",
                   help="Skip the End message and don't wait for EndAck. The "
                        "session is left open server-side and reclaimed by the "
                        "module session_timeout. Used by no_end.json.")
    p.add_argument("--use-databatch", action="store_true",
                   help="Send DataValues batched as MessageType_DataBatch "
                        "instead of one DataValue per message. Used by "
                        "databatch.json to exercise the re-serialization path.")
    p.add_argument("--batch-max-bytes", type=int, default=60 * 1024,
                   help="Cap per DataBatch in estimated bytes when "
                        "--use-databatch is set. Mirrors the real agent's "
                        "MAX_BATCH_PAYLOAD constant in shared_modules/"
                        "sync_protocol/.../agent_sync_protocol.cpp "
                        "(default: 61440 = 60 KB).")
    p.add_argument("--max-eps", type=int, default=0,
                   help="Per-agent rate limit in events/second on wire sends. "
                        "Mirrors the real syscollector <max_eps> agent-side "
                        "throttle (default 75 EPS per real agent). 0 = no "
                        "throttle, sender bursts at full TCP speed (default: 0).")
    p.add_argument("--sessions-per-agent", type=int, default=0,
                   help="Hard cap on the number of sync sessions each "
                        "simulated agent runs before exiting. 0 = unlimited "
                        "(legacy: keep looping until --duration). Use 1 to "
                        "match the real-agent behaviour where syscollector "
                        "emits exactly one first-sync per <interval>.")
    p.add_argument("--session-type",
                   choices=["delta", "modulecheck", "dataclean"],
                   default="delta",
                   help="Session flow: delta=Start→DataValues→End (default), "
                        "modulecheck=Start→ChecksumModule→End, "
                        "dataclean=Start→DataClean→End.")
    p.add_argument("--sync-mode", type=int, default=1,
                   help="Start message mode: 0=ModuleFull, 1=ModuleDelta (default). "
                        "Ignored when --session-type=modulecheck (always uses mode=2).")
    p.add_argument("--modulecheck-checksum", type=str,
                   default="0" * 40,
                   help="SHA1 checksum sent in ChecksumModule. Default: all zeros, "
                        "which always produces a mismatch on the manager side.")
    p.add_argument("--auto-resync", action="store_true",
                   help="After a ChecksumMismatch EndAck, automatically run a "
                        "ModuleFull session. Used by sca_modulecheck_full_recovery.")
    p.add_argument("--end-delay", type=float, default=1.0,
                   help="Seconds to sleep between the last DataValue and the "
                        "End message (default: 1.0)")
    p.add_argument("--no-retransmit", action="store_true",
                   help="Disable ReqRet handling. Default is to retransmit")
    p.add_argument("--debug", action="store_true", help="Debug logging")
    return p.parse_args()


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
    """Return a deep copy of `template` with `pad_field` (dotted path) extended
    so the JSON-encoded payload reaches at least `target_size` bytes.

    The pad target must be an existing free-text field in the mapping; padding
    via a new top-level field is rejected by the dynamic:strict mappings of
    wazuh-states-* indices (see PAD_FIELD_BY_KIND).
    """
    base = copy.deepcopy(template)
    existing = _get_dotted(base, pad_field)
    if not isinstance(existing, str):
        existing = "" if existing is None else str(existing)

    current = len(json.dumps(base).encode("utf-8"))
    if current >= target_size:
        return base

    pad_len = target_size - current
    _set_dotted(base, pad_field, existing + ("x" * pad_len))

    # Re-roll if JSON quoting overhead left us under target.
    encoded = len(json.dumps(base).encode("utf-8"))
    if encoded < target_size:
        extra = target_size - encoded
        _set_dotted(base, pad_field, existing + ("x" * (pad_len + extra)))
    return base


def main() -> None:
    global _running
    args = parse_args()
    if args.debug:
        logger.setLevel(logging.DEBUG)

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    # Resolve payload + index + module from kind unless explicitly overridden.
    kind_cfg = PAYLOAD_KINDS[args.payload_kind]
    module = args.module if args.module is not None else kind_cfg["module"]
    index  = args.index  if args.index  is not None else kind_cfg["index"]

    if args.payload:
        with open(args.payload) as f:
            payload_template = json.load(f)
    else:
        payload_path = Path(__file__).parent / "sample_payloads" / kind_cfg["file"]
        if not payload_path.exists():
            logger.error("Built-in payload not found: %s", payload_path)
            return
        with open(payload_path) as f:
            payload_template = json.load(f)

    payload_pad_applied = 0
    pad_field_used = ""
    if args.payload_size > 0:
        pad_field_used = args.pad_field or PAD_FIELD_BY_KIND.get(args.payload_kind, "")
        if not pad_field_used:
            logger.error("No pad-field default for payload_kind=%s and "
                         "--pad-field not given. Indexer will reject the docs.",
                         args.payload_kind)
            return
        original = len(json.dumps(payload_template).encode("utf-8"))
        payload_template = _pad_payload_to_size(
            payload_template, args.payload_size, pad_field_used,
        )
        payload_pad_applied = len(json.dumps(payload_template).encode("utf-8"))
        logger.info(
            "Payload padded into '%s': %d -> %d bytes (target=%d).",
            pad_field_used, original, payload_pad_applied, args.payload_size,
        )

    cfg = {
        "manager": args.manager,
        "port": args.port,
        "reg_port": args.reg_port,
        "module": module,
        "index":  index,
        "data_size": args.data_size,
        "drop_every":    args.drop_every,
        "no_end":        args.no_end,
        "use_databatch": args.use_databatch,
        "batch_max_bytes": args.batch_max_bytes,
        "session_type":          args.session_type,
        "sync_mode":             args.sync_mode,
        "modulecheck_checksum":  args.modulecheck_checksum,
        "auto_resync":           args.auto_resync,
        "end_delay":             args.end_delay,
        "retransmit":            not args.no_retransmit,
        "max_eps":               args.max_eps,
        "sessions_per_agent":    args.sessions_per_agent,
    }

    print()
    print("Inventory Sync Benchmark")
    print(f"  Agents:            {args.agents}")
    print(f"  DataValues/session:{args.data_size}")
    print(f"  Duration:          {args.duration}s")
    print(f"  Manager:           {args.manager}:{args.port}")
    print(f"  Payload kind:      {args.payload_kind}"
          f"{'  (overridden via --payload)' if args.payload else ''}")
    print(f"  Module:            {module}")
    print(f"  Index:             {index}")
    print(f"  Output:            {args.output}")
    if args.payload_size > 0:
        print(f"  Payload size:      target={args.payload_size}B  applied={payload_pad_applied}B  field={pad_field_used}")
    if args.drop_every > 0:
        print(f"  Drop every:        {args.drop_every} (forces ReqRet)")
    if args.no_end:
        print(f"  No-End mode:       enabled (session_timeout reclaims sessions)")
    if args.use_databatch:
        print(f"  DataBatch mode:    enabled  batch_max_bytes={args.batch_max_bytes}")
    print(f"  End delay:         {args.end_delay:.2f}s (sleep before End)")
    print(f"  Retransmit:        {'disabled' if args.no_retransmit else 'enabled'}")
    if args.max_eps > 0:
        print(f"  Max EPS per agent: {args.max_eps} msg/s (real-syscollector match)")
    print()

    counters = AtomicCounters()
    barrier = threading.Barrier(args.agents + 1, timeout=120)

    # ---- Phase 1: Register all agents ------------------------------------
    logger.info("Registering %d agents...", args.agents)
    agents = []
    for i in range(args.agents):
        agent = BenchmarkAgent(i, cfg["manager"], cfg["port"], cfg["reg_port"])
        if not agent.register():
            logger.error("Agent %d registration failed, skipping", i)
            continue
        agents.append(agent)
        time.sleep(0.05)  # Slight stagger to avoid overloading authd

    if not agents:
        logger.error("No agents registered successfully, aborting")
        return

    logger.info(
        "%d/%d agents registered. Waiting %ds for remoted key reload (keyupdate_interval)...",
        len(agents), args.agents, args.key_wait,
    )

    # ---- Phase 2: Wait for remoted to reload client.keys -----------------
    for remaining in range(args.key_wait, 0, -1):
        if not _running:
            return
        if remaining % 10 == 0:
            logger.info("  %ds remaining...", remaining)
        time.sleep(1.0)

    logger.info("Key reload wait complete. Connecting agents...")

    # Adjust barrier for actual registered count
    barrier = threading.Barrier(len(agents) + 1, timeout=120)
    deadline = time.monotonic() + args.duration

    # ---- Phase 3: Start worker threads (connect + send) ------------------
    threads = []
    for agent in agents:
        t = threading.Thread(
            target=agent_worker,
            args=(agent, cfg, counters, payload_template, deadline, barrier),
            daemon=True,
        )
        t.start()
        threads.append(t)

    # Wait for all agents to connect
    logger.info("Waiting for %d agents to connect...", len(agents))
    try:
        barrier.wait(timeout=120)
    except threading.BrokenBarrierError:
        logger.error("Not all agents could register in time")
        _running = False
        return

    logger.info("All agents ready — starting benchmark")

    run_meta = {
        "manager":           cfg["manager"],
        "port":              cfg["port"],
        "agents_requested":  args.agents,
        "agents_registered": len(agents),
        "data_size":         args.data_size,
        "duration_sec":      args.duration,
        "payload_kind":      args.payload_kind,
        "payload_override":  args.payload,
        "module":            module,
        "index":             index,
        "payload_size":      args.payload_size,
        "payload_size_applied": payload_pad_applied,
        "pad_field":         pad_field_used,
        "drop_every":        args.drop_every,
        "no_end":            args.no_end,
        "use_databatch":     args.use_databatch,
        "batch_max_bytes":   args.batch_max_bytes if args.use_databatch else 0,
        "end_delay":         args.end_delay,
        "retransmit":        not args.no_retransmit,
        "max_eps":           args.max_eps,
        "started_at":        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    # Collect stats in main thread
    stats_collector(
        counters,
        args.output,
        time.monotonic(),
        deadline,
        drain_timeout=args.drain_timeout,
        summary_json_path=args.summary_json,
        run_meta=run_meta,
    )

    # Wait for threads to finish. Use a single global budget instead of
    # per-thread timeout so that shutdown stays bounded even with many agents.
    _running = False
    join_deadline = time.monotonic() + 5.0
    for t in threads:
        remaining = max(0.1, join_deadline - time.monotonic())
        t.join(timeout=remaining)

    still_alive = sum(1 for t in threads if t.is_alive())
    if still_alive:
        logger.warning("%d agent thread(s) still alive after 5s; they are "
                       "daemons and will be killed at process exit.",
                       still_alive)

    logger.info("Benchmark complete. Results in %s", args.output)


if __name__ == "__main__":
    main()
