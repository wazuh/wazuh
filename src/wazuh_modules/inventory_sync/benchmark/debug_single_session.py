#!/usr/bin/env python3
"""
Minimal single-agent debug script to trace exactly what happens 
during an inventory sync session.
"""
import hashlib
import json
import os
import socket
import ssl
import struct
import sys
import time
import zlib
from pathlib import Path
from random import sample
from string import ascii_letters

# Resolve shared/ helpers for flatbuffers_manager.
SHARED_DIR = Path(__file__).resolve().parent.parent / "shared"
sys.path.insert(0, str(SHARED_DIR))

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

MANAGER = "127.0.0.1"
REG_PORT = 1515
REMOTE_PORT = 1514


def log(msg):
    print(f"[DEBUG] {msg}", flush=True)


class DebugAgent:
    def __init__(self):
        self.id = None
        self.name = None
        self.key = None
        self.encryption_key = None
        self.sock = None

    def register(self):
        rand_str = "".join(sample(f"0123456789{ascii_letters}", 12))
        self.name = f"debug-{rand_str}"
        log(f"Registering agent: {self.name}")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ssl_sock = ctx.wrap_socket(sock, server_hostname=MANAGER)
        ssl_sock.connect((MANAGER, REG_PORT))
        ssl_sock.send(f"OSSEC A:'{self.name}'\n".encode())
        recv = ssl_sock.recv(4096)
        info = recv.decode().split("'")[1].split(" ")
        self.id = info[0]
        self.key = info[3]
        ssl_sock.close()

        # Derive encryption key
        sum1 = hashlib.md5(
            hashlib.md5(self.name.encode()).hexdigest().encode()
            + hashlib.md5(self.id.encode()).hexdigest().encode()
        ).hexdigest().encode()[:15]
        sum2 = hashlib.md5(self.key.encode()).hexdigest().encode()
        self.encryption_key = sum2 + sum1

        log(f"Registered: id={self.id}, name={self.name}")

    def connect(self):
        log("Connecting to remoted...")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(30.0)
        self.sock.connect((MANAGER, REMOTE_PORT))
        log("TCP connected")

        # Send startup
        ctrl = f'#!-agent startup {{"version":"4.8.0","name":"{self.name}","id":"{self.id}"}}'
        self._send_text(ctrl)
        log("Startup sent")

        # Wait and try to drain any response to startup
        log("Waiting 3s for startup response...")
        time.sleep(3.0)
        self._drain_buffer()

    def _drain_buffer(self):
        """Try to read anything sitting in the recv buffer (non-blocking)."""
        self.sock.settimeout(0.5)
        try:
            while True:
                data = self.sock.recv(4096)
                if not data:
                    break
                log(f"  Drained {len(data)} bytes from buffer: {data[:100]!r}")
        except (socket.timeout, BlockingIOError):
            log("  Buffer empty (nothing to drain)")
        self.sock.settimeout(30.0)

    def _encrypt(self, data: bytes) -> bytes:
        iv = b"FEDCBA0987654321"
        cipher = AES.new(self.encryption_key[:32], AES.MODE_CBC, iv)
        return cipher.encrypt(pad(data, 16))

    def _decrypt(self, data: bytes) -> bytes:
        iv = b"FEDCBA0987654321"
        cipher = AES.new(self.encryption_key[:32], AES.MODE_CBC, iv)
        return cipher.decrypt(data)

    def _wazuh_pad(self, data: bytes) -> bytes:
        extra = len(data) % 8
        padding = (8 - extra) if extra > 0 else 8
        return (b"!" * padding) + data

    def _compose_event(self, payload: bytes) -> bytes:
        msg = b"55555" + b"1234567891" + b":" + b"5555" + b":" + payload
        md5 = hashlib.md5(msg).hexdigest().encode()
        return md5 + msg

    def _frame_and_send(self, raw_event: bytes):
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

    def receive_response(self, timeout=15.0):
        """Receive and fully decode one response, with detailed logging."""
        self.sock.settimeout(timeout)
        try:
            # 1. Read length
            length_data = self.sock.recv(4)
            if not length_data or len(length_data) < 4:
                log(f"  recv length failed: got {len(length_data) if length_data else 0} bytes")
                return None
            length = struct.unpack("<I", length_data)[0]
            log(f"  Response length: {length} bytes")

            # 2. Read payload
            data = b""
            while len(data) < length:
                chunk = self.sock.recv(length - len(data))
                if not chunk:
                    break
                data += chunk
            log(f"  Read {len(data)} bytes, first 60: {data[:60]!r}")

            if len(data) != length:
                log(f"  Incomplete read: {len(data)}/{length}")
                return None

            # 3. Decrypt
            if data.startswith(b"#AES:"):
                encrypted = data[5:]
                log(f"  AES encrypted payload: {len(encrypted)} bytes")
                
                # Check alignment
                if len(encrypted) % 16 != 0:
                    log(f"  WARNING: encrypted data not 16-byte aligned ({len(encrypted)} bytes)")
                    # Pad to 16 for AES
                    encrypted = pad(encrypted, 16)
                
                decrypted = self._decrypt(encrypted)
                log(f"  Decrypted: {len(decrypted)} bytes, first 20: {decrypted[:20]!r}")

                # 4. Remove wazuh padding
                i = 0
                while i < len(decrypted) and decrypted[i] == ord("!"):
                    i += 1
                log(f"  Stripped {i} padding bytes")

                # 5. Decompress
                try:
                    decompressed = zlib.decompress(decrypted[i:])
                    log(f"  Decompressed: {len(decompressed)} bytes")
                except zlib.error as e:
                    log(f"  DECOMPRESSION FAILED: {e}")
                    log(f"  Raw after strip: {decrypted[i:i+40]!r}")
                    return None

                # 6. Parse header
                # MD5(32) + random(5) + global(10) + : + local(4) + :
                header_len = 32 + 5 + 10 + 1 + 4 + 1  # 53
                if len(decompressed) < header_len:
                    log(f"  Message too short: {len(decompressed)} < {header_len}")
                    return None

                msg_header = decompressed[:header_len]
                message = decompressed[header_len:]
                log(f"  Header: {msg_header!r}")
                log(f"  Message ({len(message)} bytes): {message[:100]!r}")

                # 7. Parse message
                if message.startswith(b"s:"):
                    # Agent→manager format: s:identifier:binary_data
                    parts = message.split(b":", 2)
                    if len(parts) >= 3:
                        fb_data = parts[2]
                        log(f"  FlatBuffer (s:) identifier: {parts[1]!r}, data len: {len(fb_data)}")
                        try:
                            from flatbuffers_manager import parse_message
                            parsed = parse_message(fb_data)
                            log(f"  Parsed FlatBuffer: {parsed}")
                            return {"type": "flatbuffer", "data": parsed}
                        except Exception as e:
                            log(f"  FlatBuffer parse error: {e}")
                            import traceback
                            traceback.print_exc()
                    else:
                        log(f"  s: prefix but only {len(parts)} parts")
                elif message.startswith(b"#!-"):
                    # Manager→agent format: #!-identifier {binary_data}
                    space_idx = message.find(b" ", 3)
                    if space_idx != -1 and space_idx + 1 < len(message):
                        identifier = message[3:space_idx]
                        fb_data = message[space_idx + 1:]
                        log(f"  FlatBuffer (#!-) identifier: {identifier!r}, data len: {len(fb_data)}")
                        try:
                            from flatbuffers_manager import parse_message
                            parsed = parse_message(fb_data)
                            log(f"  Parsed FlatBuffer: {parsed}")
                            return {"type": "flatbuffer", "data": parsed}
                        except Exception as e:
                            log(f"  FlatBuffer parse error: {e}")
                            import traceback
                            traceback.print_exc()
                    else:
                        log(f"  #!- prefix but no space separator found")
                else:
                    log(f"  Non-s:/Non-#!- message: {message[:200]!r}")

                return {"type": "raw", "data": message}
            else:
                log(f"  Not AES response, starts with: {data[:20]!r}")
                return {"type": "unknown", "data": data}

        except socket.timeout:
            log("  TIMEOUT waiting for response")
            return None
        except Exception as e:
            log(f"  EXCEPTION: {e}")
            import traceback
            traceback.print_exc()
            return None


def main():
    from flatbuffers_manager import FlatBuffersManager, parse_message

    fb = FlatBuffersManager()

    agent = DebugAgent()

    # Use existing agent 205 (already in client.keys and remoted reloaded)
    agent.id = "205"
    agent.name = "debug-Uuml9Iv7gfek"
    agent.key = "f98b45201fe1a17e40ae307ba25d3112f7caf087182e2a38ffbe6db519566f48"
    sum1 = hashlib.md5(
        hashlib.md5(agent.name.encode()).hexdigest().encode()
        + hashlib.md5(agent.id.encode()).hexdigest().encode()
    ).hexdigest().encode()[:15]
    sum2 = hashlib.md5(agent.key.encode()).hexdigest().encode()
    agent.encryption_key = sum2 + sum1
    log(f"Using existing agent: id={agent.id}, name={agent.name}")

    agent.connect()

    # --- Send Start ---
    log("=== Sending START ===")
    start_msg = fb.create_message("start", {
        "module": "fim",
        "mode": 1,
        "size": 5,
        "agentid": agent.id,
        "agentname": agent.name,
        "agentversion": "4.8.0",
        "option": 0,
        "indices": ["wazuh-states-fim"],
    })
    log(f"Start message: {len(start_msg)} bytes")
    agent._send_binary("fim_sync", start_msg)
    log("Start sent, waiting for StartAck...")

    resp = agent.receive_response(timeout=15.0)
    if resp is None:
        log("FATAL: No response at all")
        return

    session_id = None
    if resp.get("type") == "flatbuffer":
        data = resp.get("data", {})
        log(f"Response data keys: {list(data.keys()) if isinstance(data, dict) else type(data)}")
        if isinstance(data, dict):
            # Try various key names
            session_id = data.get("session_id") or data.get("session") or data.get("sessionId")
            status = data.get("status", "?")
            msg_type = data.get("type", "?")
            log(f"type={msg_type}, status={status}, session_id={session_id}")

    if session_id is None:
        log(f"FATAL: Could not get session_id from response: {resp}")
        return

    log(f"Session ID: {session_id}")

    # --- Send DataValue messages ---
    for seq in range(5):
        log(f"=== Sending DATA seq={seq} ===")
        data_msg = fb.create_message("data", {
            "session": session_id,
            "seq": seq,
            "index": "wazuh-states-fim",
            "id": f"{agent.id}-{session_id}-{seq}",
            "data": {"package": {"name": f"pkg-{seq}"}},
            "operation": 0,
        })
        agent._send_binary("fim_sync", data_msg)
        log(f"Data seq={seq} sent")

    # --- Send End ---
    log("=== Sending END ===")
    end_msg = fb.create_message("end", {"session": session_id})
    agent._send_binary("fim_sync", end_msg)
    log("End sent, waiting for EndAck...")

    # Wait for EndAck
    max_attempts = 10
    for attempt in range(max_attempts):
        log(f"--- Waiting for response (attempt {attempt+1}/{max_attempts}) ---")
        resp = agent.receive_response(timeout=30.0)
        if resp is None:
            log("No response, stopping")
            break
        if resp.get("type") == "flatbuffer":
            data = resp.get("data", {})
            if isinstance(data, dict):
                msg_type = data.get("type", "?")
                status = data.get("status", "?")
                log(f"Got: type={msg_type}, status={status}")
                if msg_type == "end_ack" and status != 4:
                    log("SESSION COMPLETE!")
                    break
        else:
            log(f"Non-flatbuffer response: {resp}")

    log("Done")


if __name__ == "__main__":
    main()
