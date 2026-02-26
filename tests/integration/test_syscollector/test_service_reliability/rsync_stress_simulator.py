"""
Custom RemotedSimulator that responds to rsync integrity_check messages
with checksum_fail responses to trigger heavy rsync traffic.

This is designed to stress test the syscollector rsync synchronization
and help reproduce the deadlock bug (Issue #33761).
"""
import json
import re
import threading
from queue import Queue
from typing import Any, Literal, Union, Callable

from wazuh_testing.constants.paths.configurations import WAZUH_CLIENT_KEYS_PATH
from wazuh_testing.tools.mitm import ManInTheMiddle
from wazuh_testing.utils import secure_message
from wazuh_testing.utils.client_keys import get_client_keys


# Internal constants
_RESPONSE_ACK = b'#!-agent ack '
_RESPONSE_SHUTDOWN = b'#!-agent shutdown '
_RESPONSE_EMPTY = b''


class RsyncStressSimulator:
    """
    A RemotedSimulator that responds to integrity_check_global messages
    with checksum_fail responses to trigger heavy rsync traffic.

    This creates the mutex contention conditions that can trigger the
    deadlock bug in syscollector.
    """

    def __init__(self,
                 server_ip: str = '127.0.0.1',
                 port: int = 1514,
                 protocol: Literal['udp', 'tcp'] = 'tcp',
                 keys_path: str = WAZUH_CLIENT_KEYS_PATH,
                 max_checksum_fails: int = 100,
                 on_integrity_check: Callable = None) -> None:
        """
        Initialize the RsyncStressSimulator.

        Args:
            server_ip: The IP address to listen on.
            port: The port number to listen on.
            protocol: The connection protocol ('udp' or 'tcp').
            keys_path: Path to the wazuh client keys file.
            max_checksum_fails: Maximum number of checksum_fail responses to send
                               before allowing sync to complete (prevents infinite loops).
            on_integrity_check: Optional callback called when integrity_check is received.
        """
        self.server_ip = server_ip
        self.port = port
        self.protocol = protocol
        self.keys_path = keys_path
        self.max_checksum_fails = max_checksum_fails
        self.on_integrity_check = on_integrity_check

        self.__mitm = ManInTheMiddle(
            address=(self.server_ip, self.port),
            family='AF_INET',
            connection_protocol=self.protocol,
            func=self.__remoted_response_simulation
        )

        self.running = False
        self.custom_message = None
        self.custom_message_sent = False
        self.last_message_ctx = {}
        self.request_counter = 0
        self.checksum_fail_counter = 0
        self.integrity_check_counter = 0

        self._queue_response_req_message = Queue()
        self._lock = threading.Lock()

        # Pattern to match integrity_check messages
        self._integrity_check_pattern = re.compile(
            r'"type"\s*:\s*"(integrity_check_global|integrity_check_left|integrity_check_right)"'
        )
        self._sync_data_pattern = re.compile(
            r'"data"\s*:\s*\{[^}]*"begin"\s*:\s*"([^"]+)"[^}]*"end"\s*:\s*"([^"]+)"[^}]*"id"\s*:\s*(\d+)'
        )

    @property
    def queue(self) -> Queue:
        return self.__mitm.queue

    def start(self) -> None:
        """Start the simulator."""
        if self.running:
            return
        self.__mitm.start()
        self.running = True
        print(f"[RSYNC_STRESS] Simulator started on {self.server_ip}:{self.port}", flush=True)

    def shutdown(self) -> None:
        """Shutdown the simulator."""
        if not self.running:
            return
        self.__mitm.shutdown()
        self.running = False
        print(f"[RSYNC_STRESS] Simulator stopped. Stats: integrity_checks={self.integrity_check_counter}, checksum_fails={self.checksum_fail_counter}", flush=True)

    def clear(self) -> None:
        """Clear the message queue."""
        while not self.__mitm.queue.empty():
            self.__mitm.queue.get_nowait()
        self.__mitm.event.clear()

    def destroy(self) -> None:
        """Clear and shutdown."""
        self.clear()
        self.shutdown()

    def reset_counters(self) -> None:
        """Reset the message counters."""
        with self._lock:
            self.checksum_fail_counter = 0
            self.integrity_check_counter = 0
            self.request_counter = 0

    def send_custom_message(self, message: Union[str, bytes]) -> None:
        """Send a custom message to the agent."""
        if not isinstance(message, (str, bytes)):
            raise TypeError('Message must be a string or bytes.')
        if not isinstance(message, bytes):
            message = message.encode()
        with self._queue_response_req_message.mutex:
            self._queue_response_req_message.queue.clear()
        self.custom_message_sent = False
        self.custom_message = message

    def __remoted_response_simulation(self, request: Any) -> bytes:
        """
        Process incoming messages and generate responses.

        For integrity_check messages, responds with checksum_fail to trigger
        more rsync traffic and create mutex contention.
        """
        self.request_counter += 1
        print(f"[RSYNC_STRESS] Request #{self.request_counter} received ({len(request) if request else 0} bytes)", flush=True)

        if not request:
            self.__mitm.event.set()
            return _RESPONSE_EMPTY

        if b'#ping' in request:
            print(f"[RSYNC_STRESS] Received ping, sending pong", flush=True)
            return b'#pong'

        try:
            # Save header values and decrypt
            self.__save_encryption_values(request)
            message = self.__decrypt_received_message(request)

            # Check if this is an integrity_check message
            response = self.__handle_message(message)

            # Save context
            self.__save_message_context(request, message, response)

            if response == _RESPONSE_EMPTY:
                return response

            # Encrypt the response
            response = self.__encrypt_response_message(response)

            if self.protocol == "tcp":
                return secure_message.pack(len(response)) + response

            return response

        except Exception as e:
            print(f"[RSYNC_STRESS] Error processing message: {e}", flush=True)
            import traceback
            traceback.print_exc()
            import sys
            sys.stdout.flush()
            sys.stderr.flush()
            return _RESPONSE_ACK

    def __handle_message(self, message: str) -> bytes:
        """
        Handle incoming message and determine response.

        For integrity_check messages, return checksum_fail to trigger more traffic.
        """
        # Debug: Log all received messages (truncated)
        msg_preview = message[:200] if len(message) > 200 else message
        print(f"[RSYNC_STRESS] Received message: {msg_preview}", flush=True)

        # Check for integrity_check messages (rsync protocol)
        integrity_match = self._integrity_check_pattern.search(message)
        if integrity_match:
            check_type = integrity_match.group(1)
            self.integrity_check_counter += 1

            # Call callback if provided
            if self.on_integrity_check:
                try:
                    self.on_integrity_check(check_type, message)
                except Exception as e:
                    print(f"[RSYNC_STRESS] Callback error: {e}", flush=True)

            # Only respond with checksum_fail if we haven't exceeded the limit
            with self._lock:
                if self.checksum_fail_counter < self.max_checksum_fails:
                    # Extract sync data to build checksum_fail response
                    response = self.__build_checksum_fail_response(message)
                    if response:
                        self.checksum_fail_counter += 1
                        print(f"[RSYNC_STRESS] Sending checksum_fail #{self.checksum_fail_counter} for {check_type}", flush=True)
                        return response

            # Once we've sent enough checksum_fails, just ACK to let sync complete
            return _RESPONSE_ACK

        # Handle other message types
        if '#!-agent shutdown' in message:
            self.__mitm.event.set()
            return _RESPONSE_SHUTDOWN
        elif '#!-req' in message:
            self._queue_response_req_message.put(message)
            return _RESPONSE_EMPTY
        elif self.custom_message and not self.custom_message_sent:
            response = self.custom_message
            self.custom_message_sent = True
            self.custom_message = None
            return response
        elif '#!-' in message:
            return _RESPONSE_ACK
        else:
            return _RESPONSE_EMPTY

    def __build_checksum_fail_response(self, message: str) -> bytes:
        """
        Build a checksum_fail response from an integrity_check message.

        The checksum_fail tells the agent that the checksums don't match,
        which triggers the agent to split the range and send more messages.
        """
        try:
            # Try to extract component/sync_id from the message
            # Format: {"component":"syscollector_xyz","type":"integrity_check_global","data":{...}}

            # Extract component name (used as sync_id)
            component_match = re.search(r'"component"\s*:\s*"([^"]+)"', message)
            if not component_match:
                return None
            component = component_match.group(1)

            # Extract data fields
            data_match = re.search(
                r'"data"\s*:\s*\{[^}]*"begin"\s*:\s*"([^"]+)"[^}]*"end"\s*:\s*"([^"]+)"[^}]*"id"\s*:\s*(\d+)',
                message
            )
            if not data_match:
                # Try alternative format with different field order
                data_match = re.search(
                    r'"data"\s*:\s*\{[^}]*"id"\s*:\s*(\d+)[^}]*"begin"\s*:\s*"([^"]+)"[^}]*"end"\s*:\s*"([^"]+)"',
                    message
                )
                if data_match:
                    sync_id = data_match.group(1)
                    begin = data_match.group(2)
                    end = data_match.group(3)
                else:
                    return None
            else:
                begin = data_match.group(1)
                end = data_match.group(2)
                sync_id = data_match.group(3)

            # Build checksum_fail response
            # Format: component checksum_fail {"begin":"...","end":"...","id":...}
            checksum_fail = f'{component} checksum_fail {{"begin":"{begin}","end":"{end}","id":{sync_id}}}'

            return checksum_fail.encode()

        except Exception as e:
            print(f"[RSYNC_STRESS] Error building checksum_fail: {e}", flush=True)
            return None

    def __get_client_keys(self):
        """Get encryption key from client keys file."""
        client_keys = get_client_keys(self.keys_path)[0]
        client_keys.pop('ip')
        return secure_message.get_encryption_key(**client_keys)

    def __decrypt_received_message(self, message: bytes) -> str:
        """Decrypt and decode a received message."""
        payload = secure_message.get_payload(message, self.algorithm)
        decrypted = secure_message.decrypt(payload, self.encryption_key, self.algorithm)
        return secure_message.decode(decrypted)

    def __encrypt_response_message(self, message: bytes) -> str:
        """Encrypt and encode a response message."""
        encoded = secure_message.encode(message)
        payload = secure_message.encrypt(encoded, self.encryption_key, self.algorithm)
        return secure_message.set_algorithm_header(payload, self.algorithm)

    def __save_encryption_values(self, message: bytes) -> None:
        """Save encryption algorithm and key from message."""
        self.algorithm = secure_message.get_algorithm(message)
        self.encryption_key = self.__get_client_keys()

    def __save_message_context(self, request: bytes, message: str, response: bytes) -> None:
        """Save the context of a received request."""
        if agent_id := secure_message.get_agent_id(request):
            self.last_message_ctx['id'] = agent_id
        self.last_message_ctx['ip'] = self.__mitm.listener.last_address[0]
        self.last_message_ctx['algorithm'] = self.algorithm
        self.last_message_ctx['message'] = message
        self.last_message_ctx['response'] = response
