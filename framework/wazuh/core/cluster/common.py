# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import base64
import datetime
import hashlib
import json
import logging
import os
import random
import struct
import traceback
from importlib import import_module
from typing import Tuple, Dict, Callable

import cryptography.fernet

import wazuh.core.cluster.utils
import wazuh.core.results as wresults
from wazuh import Wazuh
from wazuh.core import common, exception


class Response:
    """
    Define and store a response from a request.
    """

    def __init__(self):
        """Class constructor."""
        # Event object which will be set when the response is received.
        self.received_response = asyncio.Event()
        # Response content.
        self.content = None

    async def read(self) -> bytes:
        """Wait until a response is received."""
        await self.received_response.wait()
        return self.content

    def write(self, content):
        """Set the content of a response and notify its availability.

        Parameters
        ----------
        content : bytes
            Content to store in the response.
        """
        self.content = content
        self.received_response.set()


class InBuffer:
    """
    Define a buffer to receive incoming requests.
    """

    def __init__(self, total=0):
        """Class constructor.

        Parameters
        ----------
        total : int
            Size of the payload buffer in bytes.
        """
        self.payload = bytearray(total)  # array to store the message's data
        self.total = total  # total of bytes to receive
        self.received = 0  # number of received bytes
        self.cmd = ''  # request's command in header
        self.counter = 0  # request's counter in the box

    def get_info_from_header(self, header: bytes, header_format: str, header_size: int) -> bytes:
        """Get information contained in the request's header.

        Parameters
        ----------
        header : bytes
            Raw header to process.
        header_format : str
            Struct format of the header.
        header_size : int
            Size in bytes of the header.

        Returns
        -------
        header : bytes
            Buffer without the content of the header.
        """
        self.counter, self.total, cmd = struct.unpack(header_format, header[:header_size])
        self.cmd = cmd.split(b' ')[0]
        self.payload = bytearray(self.total)
        return header[header_size:]

    def receive_data(self, data: bytes) -> bytes:
        """Add received data to payload bytearray.

        Parameters
        ----------
        data : bytes
            Received data.

        Returns
        -------
            Extended data buffer.
        """
        len_data = len(data[:self.total - self.received])
        self.payload[self.received:len_data + self.received] = data[:self.total - self.received]
        self.received += len_data
        return data[len_data:]


class ReceiveFileTask:
    """
    Implement an asyncio task but including a name or ID for it.
    """

    def __init__(self, wazuh_common, logger):
        """Class constructor.

        Parameters
        ----------
        wazuh_common : WazuhCommon object
            The WazuhCommon object that creates this one.
        logger : Logger object
            Logger to use during the receiving process.
        """
        self.wazuh_common = wazuh_common
        self.coro = self.set_up_coro()
        self.name = str(random.randint(0, 2 ** 32))
        self.received_information = asyncio.Event()
        self.task = asyncio.create_task(self.coro(self.name, self.received_information))
        self.task.add_done_callback(self.done_callback)
        self.filename = ''
        self.logger = logger

    def __str__(self) -> str:
        """Magic method str.

        Returns
        -------
        str
            Task name (random numeric string).
        """
        return self.name

    def set_up_coro(self) -> Callable:
        """Define set_up_coro method. It is implemented differently for master, workers and synchronization types.

        Raises
        -------
        NotImplementedError
            If the method is not implemented.
        """
        raise NotImplementedError

    def done_callback(self, future=None):
        """Function to call when the task is finished.

        Remove task_name (if exists) from sync_tasks dict. If task was not cancelled, raise stored exception.
        """
        if self.name in self.wazuh_common.sync_tasks:
            del self.wazuh_common.sync_tasks[self.name]
        if not self.task.cancelled():
            task_exc = self.task.exception()
            if task_exc:
                self.logger.error(task_exc)


class Handler(asyncio.Protocol):
    """
    Define common methods for echo clients and servers.
    """

    def __init__(self, fernet_key: str, cluster_items: Dict, logger: logging.Logger = None, tag: str = "Handler"):
        """Class constructor.

        Parameters
        ----------
        fernet_key : str
            32 length string used as key to initialize cryptography's Fernet.
        cluster_items : dict
            Cluster.json object containing cluster internal variables.
        logger : Logger object
            Logger object to use.
        tag : str
            Log tag.
        """
        super().__init__()
        # The counter is used to identify each message. If an incoming request has a known ID,
        # it is processed as a response.
        self.counter = random.SystemRandom().randint(0, 2 ** 32 - 1)
        # The box stores all sent messages IDs.
        self.box = {}
        # Defines command length.
        self.cmd_len = 12
        # Defines header length.
        self.header_len = self.cmd_len + 8  # 4 bytes of counter and 4 bytes of message size
        # Defines header format.
        self.header_format = f'!2I{self.cmd_len}s'
        # Stores received data.
        self.in_buffer = b''
        # Stores last received message.
        self.in_msg = InBuffer()
        # Stores incoming file information from file commands.
        self.in_file = {}
        # Stores incoming string information from string commands.
        self.in_str = {}
        # Maximum message length to send in a single request.
        self.request_chunk = 5242880
        # Stores message to be sent.
        self.out_msg = bytearray(self.header_len + self.request_chunk * 2)
        # Object use to encrypt and decrypt requests.
        self.my_fernet = cryptography.fernet.Fernet(base64.b64encode(fernet_key.encode())) if fernet_key else None
        # Logging.Logger object used to write logs.
        self.logger = logging.getLogger('wazuh') if not logger else logger
        # Logging tag.
        self.tag = tag
        # Modify filter tags with context vars.
        wazuh.core.cluster.utils.context_tag.set(self.tag)
        wazuh.core.cluster.utils.context_subtag.set("Main")
        self.cluster_items = cluster_items
        # Transports in asyncio are an abstraction of sockets.
        self.transport = None

    def push(self, message: bytes):
        """Send a message to peer.

        Parameters
        ----------
        message : bytes
            Message to send.
        """
        self.transport.write(message)

    def next_counter(self) -> int:
        """Increase the message ID counter.

        Returns
        -------
        self.counter : int
            New counter.
        """
        self.counter = (self.counter + 1) % (2 ** 32)
        return self.counter

    def msg_build(self, command: bytes, counter: int, data: bytes) -> bytes:
        """Build a message with header + payload.

        It contains a header in self.header_format format that includes self.counter, the data size and the command.
        The data is also encrypted and added to the bytearray starting from the position self.header_len.

        Parameters
        ----------
        command : bytes
            Command to send to peer.
        counter : int
            Message ID.
        data : bytes
            Data to send to peer.

        Returns
        -------
        bytes
            Built message.
        """
        cmd_len = len(command)
        if cmd_len > self.cmd_len:
            raise exception.WazuhClusterError(3024, extra_message=command)

        # adds - to command until it reaches cmd length
        command = command + b' ' + b'-' * (self.cmd_len - cmd_len - 1)
        encrypted_data = self.my_fernet.encrypt(data) if self.my_fernet is not None else data
        self.out_msg[:self.header_len] = struct.pack(self.header_format, counter, len(encrypted_data), command)
        self.out_msg[self.header_len:self.header_len + len(encrypted_data)] = encrypted_data

        return self.out_msg[:self.header_len + len(encrypted_data)]

    def msg_parse(self) -> bool:
        """Parse an incoming message.

        Returns
        -------
        bool
            Whether a message was parsed or not.
        """
        if self.in_buffer:
            if self.in_msg.received == 0:
                # A new message has been received. Both header and payload must be processed.
                self.in_buffer = self.in_msg.get_info_from_header(header=self.in_buffer,
                                                                  header_format=self.header_format,
                                                                  header_size=self.header_len)
                self.in_buffer = self.in_msg.receive_data(data=self.in_buffer)
            else:
                # The previous message has not been completely received yet. No header to parse, just payload.
                self.in_buffer = self.in_msg.receive_data(data=self.in_buffer)
            return True
        else:
            return False

    def get_messages(self) -> Tuple[bytes, int, bytes]:
        """Get received command, counter and payload.

        Called when data is received in the transport. It decrypts the received data and returns it using generators.
        If the data received in the transport contains multiple separated messages, it will return all of them in
        separate yields.

        Yields
        -------
        bytes
            Last received message command.
        int
            Counter.
        bytes
            Payload.
        """
        parsed = self.msg_parse()

        while parsed:
            if self.in_msg.received == self.in_msg.total:
                # Decrypt received message
                try:
                    decrypted_payload = self.my_fernet.decrypt(bytes(self.in_msg.payload)) if self.my_fernet is not None \
                        else bytes(self.in_msg.payload)
                except cryptography.fernet.InvalidToken:
                    raise exception.WazuhClusterError(3025)
                yield self.in_msg.cmd, self.in_msg.counter, decrypted_payload
                self.in_msg = InBuffer()
            else:
                break
            parsed = self.msg_parse()

    async def send_request(self, command: bytes, data: bytes) -> bytes:
        """Send a request to peer and wait for the response to be received and processed.

        Parameters
        ----------
        command : bytes
            Command to send.
        data : bytes
            Data to send.

        Returns
        -------
        response_data : bytes
            Response from peer.
        """
        if len(data) > self.request_chunk:
            raise exception.WazuhClusterError(3033)

        response = Response()
        msg_counter = self.next_counter()
        self.box[msg_counter] = response
        try:
            self.push(self.msg_build(command, msg_counter, data))
        except MemoryError:
            self.request_chunk //= 2
            raise exception.WazuhClusterError(3026)
        except Exception as e:
            raise exception.WazuhClusterError(3018, extra_message=str(e))
        try:
            # A lock is hold until response.write() is called inside data_received() method.
            response_data = await asyncio.wait_for(response.read(),
                                                   timeout=self.cluster_items['intervals']['communication'][
                                                       'timeout_cluster_request'])
            del self.box[msg_counter]
        except asyncio.TimeoutError:
            self.box[msg_counter] = None
            return b'Error sending request: timeout expired.'
        return response_data

    async def send_file(self, filename: str) -> bytes:
        """Send a file to peer, slicing it into chunks.

        Parameters
        ----------
        filename : str
            Full path of the file to send.

        Returns
        -------
        bytes
            Response message.
        """
        if not os.path.exists(filename):
            raise exception.WazuhClusterError(3034, extra_message=filename)

        filename = filename.encode()
        relative_path = filename.replace(common.ossec_path.encode(), b'')
        # Tell to the destination node where (inside ossec_path) the file has to be written.
        await self.send_request(command=b'new_file', data=relative_path)

        # Send each chunk so it is updated in the destination.
        file_hash = hashlib.sha256()
        with open(filename, 'rb') as f:
            for chunk in iter(lambda: f.read(self.request_chunk - len(relative_path) - 1), b''):
                await self.send_request(command=b'file_upd', data=relative_path + b' ' + chunk)
                file_hash.update(chunk)

        # Close the destination file descriptor so the file in memory is dumped to disk.
        await self.send_request(command=b'file_end', data=relative_path + b' ' + file_hash.digest())

        return b'File sent'

    async def send_string(self, my_str: bytes) -> bytes:
        """Send a large string to peer, slicing it into chunks.

        Parameters
        ----------
        my_str : bytes
            String to send.

        Returns
        -------
        task_id : bytes
             Whether sending was successful or not.
        """
        # Reserve space in destination node and obtain ID to send this string to.
        total = len(my_str)
        task_id = await self.send_request(command=b'new_str', data=str(total).encode())

        # Send chunks of the string to the destination node, indicating the ID of the string.
        local_req_chunk = self.request_chunk - len(task_id) - 1
        for c in range(0, total, local_req_chunk):
            await self.send_request(command=b'str_upd', data=task_id + b' ' + my_str[c:c + local_req_chunk])

        return task_id

    def get_manager(self):
        """Get the manager object that created this Handler.

        Raises
        -------
        NotImplementedError
            If the method is not implemented.
        """
        raise NotImplementedError

    async def forward_dapi_response(self, data: bytes):
        """Forward a distributed API response from master node.

        Parameters
        ----------
        data : bytes
            Bytes containing local client name and string id separated by ' '.
        """
        client, string_id = data.split(b' ', 1)
        client = client.decode()
        try:
            res = await self.get_manager().local_server.clients[client].send_string(self.in_str[string_id].payload)
            res = await self.get_manager().local_server.clients[client].send_request(b'dapi_res', res)
        except exception.WazuhException as e:
            self.logger.error(f"Error sending API response to local client: {e}")
            res = await self.send_request(b'dapi_err', json.dumps(e, cls=WazuhJSONEncoder).encode())
        except Exception as e:
            self.logger.error(f"Error sending API response to local client: {e}")
            exc_info = json.dumps(exception.WazuhClusterError(code=1000, extra_message=str(e)),
                                  cls=WazuhJSONEncoder).encode()
            res = await self.send_request(b'dapi_err', exc_info)

    async def forward_sendsync_response(self, data: bytes):
        """Forward a sendsync response from master node.

        Parameters
        ----------
        data : bytes
            Bytes containing local client name and string id separated by ' '.
        """
        client, string_id = data.split(b' ', 1)
        client = client.decode()
        try:
            await self.get_manager().local_server.clients[client].send_request(b'ok', self.in_str[string_id].payload)
        except exception.WazuhException as e:
            self.logger.error(f"Error sending send sync response to local client: {e}")
            await self.send_request(b'sendsync_err', json.dumps(e, cls=WazuhJSONEncoder).encode())
        except Exception as e:
            self.logger.error(f"Error sending send sync response to local client: {e}")
            exc_info = json.dumps(exception.WazuhClusterError(code=1000, extra_message=str(e)),
                                  cls=WazuhJSONEncoder).encode()
            await self.send_request(b'sendsync_err', exc_info)

    def data_received(self, message: bytes) -> None:
        """Handle received data from other peer.

        This method overrides asyncio.protocols.Protocol.data_received. It parses the message received, process
        the response and notify that the corresponding Response object (inside self.box[counter]) is available.

        Parameters
        ----------
        message : bytes
            Received data.
        """
        self.in_buffer = message
        for command, counter, payload in self.get_messages():
            # If the message is the response of a previously sent request.
            if counter in self.box:
                if self.box[counter] is None:
                    # Delete entry for previously expired request, just in case is received too late.
                    del self.box[counter]
                else:
                    self.box[counter].write(self.process_response(command, payload))
            # If the message is not related to any previously sent request.
            else:
                self.dispatch(command, counter, payload)

    def dispatch(self, command: bytes, counter: int, payload: bytes) -> None:
        """Process a received message and send a response.

        Parameters
        ----------
        command : bytes
            Command received.
        counter : int
            Message ID.
        payload : bytes
            Data received.
        """
        try:
            command, payload = self.process_request(command, payload)
        except exception.WazuhException as e:
            self.logger.error(f"Internal error processing request '{command}': {e}")
            command, payload = b'err', json.dumps(e, cls=WazuhJSONEncoder).encode()
        except Exception as e:
            self.logger.error(f"Unhandled error processing request '{command}': {e}", exc_info=True)
            command, payload = b'err', json.dumps(exception.WazuhInternalError(1000, extra_message=str(e)),
                                                  cls=WazuhJSONEncoder).encode()
        if command is not None:
            self.push(self.msg_build(command, counter, payload))

    def close(self):
        """Close the connection."""
        self.transport.close()

    def process_request(self, command: bytes, data: bytes) -> Tuple[bytes, bytes]:
        """Define available commands for both master and clients.

        Parameters
        ----------
        command : bytes
            Received command from other peer.
        data : bytes
            Received data from other peer.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
        """
        if command == b'echo':
            return self.echo(data)
        elif command == b'new_file':
            return self.receive_file(data)
        elif command == b'new_str':
            return self.receive_str(data)
        elif command == b'file_upd':
            return self.update_file(data)
        elif command == b'str_upd':
            return self.str_upd(data)
        elif command == b"file_end":
            return self.end_file(data)
        else:
            return self.process_unknown_cmd(command)

    def process_response(self, command: bytes, payload: bytes) -> bytes:
        """Define response commands for both master and client.

        Parameters
        ----------
        command : bytes
            Received response command from other peer.
        payload : bytes
            Received data from other peer.

        Returns
        -------
        bytes
            Result message.
        """
        if command == b'ok':
            return payload
        elif command == b'err':
            return self.process_error_from_peer(payload)
        else:
            return b"Unkown response command received: " + command

    def echo(self, data: bytes) -> Tuple[bytes, bytes]:
        """Define response to 'echo' command.

        Parameters
        ----------
        data : bytes
            Message to send.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
        """
        return b'ok', data

    def receive_file(self, data: bytes) -> Tuple[bytes, bytes]:
        """Create a file descriptor to store the incoming file.

        Parameters
        ----------
        data : bytes
            Relative path to the file.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
        """
        self.in_file[data] = {'fd': open(common.ossec_path + data.decode(), 'wb'), 'checksum': hashlib.sha256()}
        return b"ok ", b"Ready to receive new file"

    def update_file(self, data: bytes) -> Tuple[bytes, bytes]:
        """Extend file content.

        Parameters
        ----------
        data : bytes
            Bytes containing filepath and chunk of data separated by ' '.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
        """
        name, chunk = data.split(b' ', 1)
        self.in_file[name]['fd'].write(chunk)
        self.in_file[name]['checksum'].update(chunk)
        return b"ok", b"File updated"

    def end_file(self, data: bytes) -> Tuple[bytes, bytes]:
        """Close file descriptor (write file in disk) and check MD5.

        Parameters
        ----------
        data : bytes
            File SHA256.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
        """
        name, checksum = data.split(b' ', 1)
        self.in_file[name]['fd'].close()
        if self.in_file[name]['checksum'].digest() == checksum:
            del self.in_file[name]
            return b"ok", b"File received correctly"
        else:
            del self.in_file[name]
            return b"err", b"File wasn't correctly received. Checksums aren't equal."

    def receive_str(self, data: bytes) -> Tuple[bytes, bytes]:
        """Create a bytearray with the string size.

        Parameters
        ----------
        data : bytes
            String size.

        Returns
        -------
        bytes
            Result.
        bytes
            String ID.
        """
        name = str(random.SystemRandom().randint(0, 2 ** 32 - 1)).encode()
        self.in_str[name] = InBuffer(total=int(data))
        return b"ok", name

    def str_upd(self, data: bytes) -> Tuple[bytes, bytes]:
        """Update string contents.

        Parameters
        ----------
        data : bytes
            Bytes containing string ID and chunk of data separated by ' '.

        Returns
        -------
        bytes
            Result.
        bytes
            String ID.
        """
        name, str_data = data.split(b' ', 1)
        self.in_str[name].receive_data(str_data)
        return b"ok", b"Chunk received"

    def process_unknown_cmd(self, command: bytes) -> Tuple[bytes, bytes]:
        """Define message when an unknown command is received.

        Parameters
        ----------
        command : bytes
            Command received from peer.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
        """
        return b'err', f"unknown command '{command}'".encode()

    def process_error_from_peer(self, data: bytes) -> bytes:
        """Handle errors in requests.

        Parameters
        ----------
        data : bytes
            Error message from peer.

        Returns
        -------
        exc : dict, Exception
            Received error.
        """
        try:
            exc = json.loads(data.decode(), object_hook=as_wazuh_object)
        except json.JSONDecodeError as e:
            exc = exception.WazuhClusterError(3000, extra_message=data.decode())

        return exc

    def setup_task_logger(self, task_tag: str):
        """Create logger with a task_tag.

        Parameters
        ----------
        task_tag : str
            Tag describing the synchronization process.

        Returns
        -------
        task_logger : logging.Logger
            Logger created.
        """
        task_logger = self.logger.getChild(task_tag)
        task_logger.addFilter(wazuh.core.cluster.utils.ClusterFilter(tag=self.tag, subtag=task_tag))
        return task_logger


class WazuhCommon:
    """
    Task implementing common methods for both clients and servers that are Wazuh specific.
    """

    def __init__(self):
        """Class constructor."""
        self.sync_tasks = {}
        self.logger_tag = ''

    def get_logger(self, logger_tag: str = '') -> logging.Logger:
        """Get a logger object.

        Parameters
        ----------
        logger_tag : str
            Logger task to return. If empty, it will return main class logger.

        Raises
        -------
        NotImplementedError
            If the method is not implemented.
        """
        raise NotImplementedError

    def setup_receive_file(self, ReceiveTaskClass: Callable):
        """Create ReceiveTaskClass object and add it to sync_tasks dict.

        Returns
        -------
        bytes
            Result.
        bytes
            Task ID.
        """
        my_task = ReceiveTaskClass(self, self.get_logger(self.logger_tag))
        self.sync_tasks[my_task.name] = my_task
        return b'ok', str(my_task).encode()

    def end_receiving_file(self, task_and_file_names: str) -> Tuple[bytes, bytes]:
        """Store full path to the received file in task_name and notify its availability.

        Parameters
        ----------
        task_and_file_names : str
            String containing task ID and relative filepath separated by ' '.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
        """
        task_name, filename = task_and_file_names.split(' ', 1)
        if task_name not in self.sync_tasks:
            # Remove filename if task_name does not exists, before raising exception.
            if os.path.exists(os.path.join(common.ossec_path, filename)):
                try:
                    os.remove(os.path.join(common.ossec_path, filename))
                except Exception as e:
                    self.get_logger(self.logger_tag).error(
                        f"Attempt to delete file {os.path.join(common.ossec_path, filename)} failed: {e}")
            raise exception.WazuhClusterError(3027, extra_message=task_name)

        # Set full path to file for task 'task_name' and notify it is ready to be read, so the lock is released.
        self.sync_tasks[task_name].filename = os.path.join(common.ossec_path, filename)
        self.sync_tasks[task_name].received_information.set()
        return b'ok', b'File correctly received'

    def error_receiving_file(self, taskname_and_error_details: str) -> Tuple[bytes, bytes]:
        """Handle reported error by peer in the send file process.

        Remove received file if taskname was specified. Replace filepath with the received error details and notify
        its availability.

        Parameters
        ----------
        taskname_and_error_details : str
             WazuhJSONEncoded object with the exception details.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
        """
        taskname, error_details = taskname_and_error_details.split(' ', 1)
        error_details_json = json.loads(error_details, object_hook=as_wazuh_object)
        if taskname != 'None':
            # Remove filename if exists
            if os.path.exists(self.sync_tasks[taskname].filename):
                try:
                    os.remove(self.sync_tasks[taskname].filename)
                except Exception as e:
                    self.get_logger(self.logger_tag).error(f"Attempt to delete file {self.sync_tasks[taskname].filename}"
                                                           f" failed: {e}")
            self.sync_tasks[taskname].filename = error_details_json
            self.sync_tasks[taskname].received_information.set()
        else:
            self.get_logger(self.logger_tag).error(f"Error in synchronization process: {error_details_json}")
        return b'ok', b'Error received'

    def get_node(self):
        """Get basic information about the node.

        Returns
        -------
        dict
            Basic node information.
        """
        return self.get_manager().get_node()


def asyncio_exception_handler(loop, context: Dict):
    """Exception handler used in the protocol.

    Asyncio's default raises an exception and closes the transport. The desired behaviour in
    this case is just to show the error in the logs.

    Parameters
    ----------
    loop : Asyncio event loop object
        Event loop.
    context : dict
        Dictionary containing fields explained in
        https://docs.python.org/3/library/asyncio-eventloop.html#asyncio.loop.call_exception_handler.
    """
    logging.error(f"Unhandled exception: {context['exception']} {context['message']}\n"
                  ''.join(traceback.format_tb(context['exception'].__traceback__)))


class WazuhJSONEncoder(json.JSONEncoder):
    """
    Define special JSON encoder for Wazuh.
    """

    def default(self, obj):
        if callable(obj):
            result = {'__callable__': {}}
            attributes = result['__callable__']
            if hasattr(obj, '__name__'):
                attributes['__name__'] = obj.__name__
            if hasattr(obj, '__module__'):
                attributes['__module__'] = obj.__module__
            if hasattr(obj, '__qualname__'):
                attributes['__qualname__'] = obj.__qualname__
            if hasattr(obj, '__self__'):
                if isinstance(obj.__self__, Wazuh):
                    attributes['__wazuh__'] = obj.__self__.to_dict()
            attributes['__type__'] = type(obj).__name__
            return result
        elif isinstance(obj, exception.WazuhException):
            result = {'__wazuh_exception__': {'__class__': obj.__class__.__name__,
                                              '__object__': obj.to_dict()}}
            return result
        elif isinstance(obj, wresults.AbstractWazuhResult):
            result = {'__wazuh_result__': {'__class__': obj.__class__.__name__,
                                           '__object__': obj.encode_json()}
                      }
            return result
        elif isinstance(obj, (datetime.datetime, datetime.date)):
            return {'__wazuh_datetime__': obj.isoformat()}

        return json.JSONEncoder.default(self, obj)


def as_wazuh_object(dct: Dict):
    try:
        if '__callable__' in dct:
            encoded_callable = dct['__callable__']
            funcname = encoded_callable['__name__']
            if '__wazuh__' in encoded_callable:
                # Encoded Wazuh instance method.
                wazuh_dict = encoded_callable['__wazuh__']
                wazuh = Wazuh()
                return getattr(wazuh, funcname)
            else:
                # Encoded function or static method.
                qualname = encoded_callable['__qualname__'].split('.')
                classname = qualname[0] if len(qualname) > 1 else None
                module_path = encoded_callable['__module__']
                module = import_module(module_path)
                if classname is None:
                    return getattr(module, funcname)
                else:
                    return getattr(getattr(module, classname), funcname)
        elif '__wazuh_exception__' in dct:
            wazuh_exception = dct['__wazuh_exception__']
            return getattr(exception, wazuh_exception['__class__']).from_dict(wazuh_exception['__object__'])
        elif '__wazuh_result__' in dct:
            wazuh_result = dct['__wazuh_result__']
            return getattr(wresults, wazuh_result['__class__']).decode_json(wazuh_result['__object__'])
        elif '__wazuh_datetime__' in dct:
            return datetime.datetime.fromisoformat(dct['__wazuh_datetime__'])
        return dct

    except (KeyError, AttributeError):
        raise exception.WazuhInternalError(1000,
                                           extra_message=f"Wazuh object cannot be decoded from JSON {dct}",
                                           cmd_error=True)
