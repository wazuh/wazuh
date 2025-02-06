# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import ast
import asyncio
import contextlib
import datetime
import hashlib
import json
import logging
import os
import random
import re
import ssl
import struct
import time
import traceback
from importlib import import_module
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Tuple, Union
from uuid import uuid4

import wazuh.core.results as wresults
from wazuh import Wazuh
from wazuh.core import common, exception
from wazuh.core.cluster import cluster
from wazuh.core.cluster import utils as cluster_utils
from wazuh.core.config.models.server import ServerConfig


class Response:
    """Define and store a response from a request."""

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
    """Define a buffer to receive incoming requests."""

    divide_flag = b'd'  # flag used to indicate the message is divided

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
        self.flag_divided = b''  # request's command flag to indicate a msg division
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
        # The last Byte of the command is the flag indicating the division
        flag = cmd[-1:]
        self.flag_divided = flag if flag == InBuffer.divide_flag else b''

        # Command is the first 11 B of command without dashes (in case they were added)
        self.cmd = cmd[:-1].split(b' ')[0]
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
    """Create an asyncio task that can be identified by a task_id."""

    def __init__(self, wazuh_common, logger, task_id: bytes = b''):
        """Class constructor.

        Parameters
        ----------
        wazuh_common : WazuhCommon object
            Instance of WazuhCommon.
        logger : Logger object
            Logger to use during the reception process.
        task_id : bytes
            Pre-defined task_id to identify this object. If not specified, a random task_id will be used.
        """
        self.wazuh_common = wazuh_common
        self.coro = self.set_up_coro()
        self.task_id = task_id.decode() if task_id else str(uuid4())
        self.received_information = asyncio.Event()
        self.task = asyncio.create_task(self.coro(self.task_id, self.received_information))
        self.task.add_done_callback(self.done_callback)
        self.filename = ''
        self.logger = logger

    def __str__(self) -> str:
        """Magic method str.

        Returns
        -------
        str
            Task id of this object.
        """
        return self.task_id

    def set_up_coro(self) -> Callable:
        """Define set_up_coro method. It is implemented differently for master, workers and synchronization types.

        Raises
        ------
        NotImplementedError
            If the method is not implemented.
        """
        raise NotImplementedError

    def done_callback(self, future=None):
        """Function to call when the task is finished.

        Remove task_id (if exists) from sync_tasks dict. If task was not cancelled, raise stored exception.
        """
        if self.task_id in self.wazuh_common.sync_tasks:
            del self.wazuh_common.sync_tasks[self.task_id]
        if not self.task.cancelled():
            task_exc = self.task.exception()
            if task_exc:
                self.logger.error(task_exc, exc_info=False)


class Handler(asyncio.Protocol):
    """Define common methods for echo clients and servers."""

    def __init__(self, server_config: ServerConfig, logger: logging.Logger = None, tag: str = "Handler"):
        """Class constructor.

        Parameters
        ----------
        server_config : ServerConfig
            Object containing server internal variables.
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
        # The div_msg_box stores all divided messages under its IDs.
        self.div_msg_box = {}
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
        # Logging.Logger object used to write logs.
        self.logger = logging.getLogger('wazuh') if not logger else logger
        # Logging tag.
        self.tag = tag
        # Modify filter tags with context vars.
        cluster_utils.context_tag.set(self.tag)
        self.server_config = server_config
        # Transports in asyncio are an abstraction of sockets.
        self.transport = None
        # Tasks to be interrupted.
        self.interrupted_tasks = set()
        # Asyncio event loop object.
        self.loop = None
        # Abstract server object.
        self.server = None

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

    def msg_build(self, command: bytes, counter: int, data: bytes) -> List[bytearray]:
        """Build messages with header + payload.

        Each message contains a header in self.header_format format that includes self.counter, the data size and the
        command. The data is also encrypted and added to the bytearray starting from the position self.header_len.

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
        list
            List of Bytes, built messages.
        """
        cmd_len = len(command)
        # cmd_len must be 12 - 1 (Byte reserved for the flag used in message division)
        if cmd_len > self.cmd_len - len(InBuffer.divide_flag):
            raise exception.WazuhClusterError(3024, extra_message=command)

        # Adds - to command until it reaches cmd length
        command = command + b' ' + b'-' * (self.cmd_len - cmd_len - 1)
        message_size = self.header_len + len(data)

        # Message size is <= request_chunk, send the message
        if len(data) <= self.request_chunk:
            msg = bytearray(message_size)
            msg[:self.header_len] = struct.pack(self.header_format, counter, len(data), command)
            msg[self.header_len:message_size] = data
            return [msg]

        # Message size > request_chunk, send the message divided
        else:
            # Command with the flag d (divided)
            command = command[:-len(InBuffer.divide_flag)] + InBuffer.divide_flag
            msg_list = []
            partial_data_size = 0
            data_size = len(data)
            while partial_data_size < data_size:
                message_size = self.request_chunk \
                    if data_size - partial_data_size + self.header_len >= self.request_chunk \
                    else data_size - partial_data_size + self.header_len

                # Last divided message, remove the flag
                if message_size == data_size - partial_data_size + self.header_len:
                    command = command[:-len(InBuffer.divide_flag)] + b'-' * len(InBuffer.divide_flag)

                msg = bytearray(message_size)
                msg[:self.header_len] = struct.pack(self.header_format, counter, message_size - self.header_len,
                                                    command)
                msg[self.header_len:message_size] = data[
                                                    partial_data_size:partial_data_size + message_size - self.header_len
                                                    ]
                partial_data_size += message_size - self.header_len
                msg_list.append(msg)

            return msg_list

    def msg_parse(self) -> bool:
        """Parse an incoming message.

        Returns
        -------
        bool
            Whether a message was parsed or not.
        """
        if self.in_buffer:
            # Check if a new message was received.
            if self.in_msg.received == 0 and len(self.in_buffer) >= self.header_len:
                # A new message has been received. Both header and payload must be processed.
                self.in_buffer = self.in_msg.get_info_from_header(header=self.in_buffer,
                                                                  header_format=self.header_format,
                                                                  header_size=self.header_len)
                self.in_buffer = self.in_msg.receive_data(data=self.in_buffer)
                return True
            elif self.in_msg.received != 0:
                # The previous message has not been completely received yet. No header to parse, just payload.
                self.in_buffer = self.in_msg.receive_data(data=self.in_buffer)
                return True

        return False

    def get_messages(self) -> Tuple[bytes, int, bytes, bytes]:
        """Get received command, counter, payload and flag_divided.

        Called when data is received in the transport. It decrypts the received data and returns it using generators.
        If the data received in the transport contains multiple separated messages, it will return all of them in
        separate yields.

        Yields
        ------
        bytes
            Last received message command.
        int
            Counter.
        bytes
            Payload.
        bytes
            Flag_divided.
        """
        parsed = self.msg_parse()

        while parsed:
            if self.in_msg.received == self.in_msg.total:
                yield self.in_msg.cmd, self.in_msg.counter, bytes(self.in_msg.payload), self.in_msg.flag_divided
                self.in_msg = InBuffer()
            else:
                break
            parsed = self.msg_parse()

    async def send_request(self, command: bytes, data: bytes) -> Union[exception.WazuhClusterError, Any]:
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
        response = Response()
        msg_counter = self.next_counter()
        self.box[msg_counter] = response
        try:
            msgs = self.msg_build(command, msg_counter, data)
            for msg in msgs:
                self.push(msg)
        except MemoryError:
            self.request_chunk //= 2
            raise exception.WazuhClusterError(3026)
        except Exception as e:
            raise exception.WazuhClusterError(3018, extra_message=str(e))
        try:
            # A lock is hold until response.write() is called inside data_received() method.
            response_data = await asyncio.wait_for(response.read(),
                                                   timeout=self.server_config.communications.timeouts.cluster_request)

            del self.box[msg_counter]
        except asyncio.TimeoutError:
            self.box[msg_counter] = None
            raise exception.WazuhClusterError(3020, extra_message=command.decode())
        return response_data

    async def send_file(self, filename: str, task_id: bytes = None) -> int:
        """Send a file to peer, slicing it into chunks.

        Parameters
        ----------
        filename : str
            Full path of the file to send.
        task_id : bytes
            Task identifier to stop sending file if needed.

        Returns
        -------
        sent_size : int
            Number of bytes that were successfully sent.
        """
        if not os.path.exists(filename):
            raise exception.WazuhClusterError(3034, extra_message=filename)

        sent_size = 0
        filename = Path(filename)
        relative_path = str(filename.relative_to(common.WAZUH_RUN)).encode()
        try:
            # Tell to the destination node where (inside wazuh_path) the file has to be written.
            await self.send_request(command=b'new_file', data=relative_path)
        except exception.WazuhClusterError as e:
            if e.code != 3020:
                raise e

        # Send each chunk so it is updated in the destination.
        file_hash = hashlib.sha256()
        with open(filename, 'rb') as f:
            for chunk in iter(lambda: f.read(self.request_chunk - len(relative_path) - 1), b''):
                try:
                    await self.send_request(command=b'file_upd', data=relative_path + b' ' + chunk)
                except exception.WazuhClusterError as e:
                    if e.code != 3020:
                        raise e
                file_hash.update(chunk)
                sent_size += len(chunk)
                if task_id in self.interrupted_tasks:
                    break

        try:
            # Close the destination file descriptor so the file in memory is dumped to disk.
            await self.send_request(command=b'file_end', data=relative_path + b' ' + file_hash.digest())
        except exception.WazuhClusterError as e:
            if e.code != 3020:
                raise e

        return sent_size

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
        try:
            task_id = await self.send_request(command=b'new_str', data=str(total).encode())
        except exception.WazuhException as e:
            task_id = str(e).encode()
            self.logger.error(f'There was an error while trying to send a string: {str(e)}', exc_info=False)
            with contextlib.suppress(exception.WazuhClusterError):
                await self.send_request(command=b'err_str', data=str(total).encode())
        else:
            # Send chunks of the string to the destination node, indicating the ID of the string.
            local_req_chunk = self.request_chunk - len(task_id) - 1
            for c in range(0, total, local_req_chunk):
                with contextlib.suppress(exception.WazuhClusterError):
                    await self.send_request(command=b'str_upd', data=task_id + b' ' + my_str[c:c + local_req_chunk])

        return task_id

    def get_manager(self):
        """Get the manager object that created this Handler.

        Raises
        ------
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
            await self.get_manager().local_server.clients[client].send_request(b'dapi_res', res)
        except Exception as e:
            self.logger.error(f"Error sending API response to local client: {e}")
            if isinstance(e, exception.WazuhException):
                exc = json.dumps(e, cls=WazuhJSONEncoder)
            else:
                exc = json.dumps(exception.WazuhClusterError(1000, extra_message=str(e)), cls=WazuhJSONEncoder)
            with contextlib.suppress(Exception):
                await self.send_request(b'dapi_err', exc.encode())
        finally:
            # Remove the string after using it
            self.in_str.pop(string_id, None)

    def data_received(self, message: bytes) -> None:
        """Handle received data from other peer.

        This method overrides asyncio.protocols.Protocol.data_received. It parses the message received, process
        the response and notify that the corresponding Response object (inside self.box[counter]) is available.

        Parameters
        ----------
        message : bytes
            Received data.
        """
        self.in_buffer += message
        for command, counter, payload, flag_divided in self.get_messages():
            # If the message is a divided one
            if flag_divided == InBuffer.divide_flag:
                try:
                    self.div_msg_box[counter] = self.div_msg_box[counter] + payload
                except KeyError:
                    self.div_msg_box[counter] = payload
            else:
                # If the message is the last part of a division, join it.
                if counter in self.div_msg_box:
                    payload = bytes(self.div_msg_box[counter] + payload)
                    del self.div_msg_box[counter]

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
            msgs = self.msg_build(command, counter, payload)
            for msg in msgs:
                self.push(msg)

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
        elif command == b'err_str':
            return self.process_error_str(data)
        elif command == b'file_end':
            return self.end_file(data)
        elif command == b'cancel_task':
            return self.cancel_task(data)
        elif command == b'dapi_err':
            return self.process_dapi_error(data)
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

    def process_dapi_error(self, data: bytes) -> Tuple[bytes, bytes]:
        """Send DAPI error command to client.

        Parameters
        ----------
        data : bytes
            Bytes containing client and error message separated by ' '.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
        """
        dapi_client, error_msg = data.split(b' ', 1)
        if dapi_client.decode() in self.server.local_server.clients:
            asyncio.create_task(
                self.server.local_server.clients[dapi_client.decode()].send_request(b'dapi_err', error_msg)
            )
        else:
            raise exception.WazuhClusterError(3032, extra_message=dapi_client.decode())
        return b'ok', b'DAPI error forwarded to worker'

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
        self.in_file[data] = {'fd': open(common.WAZUH_RUN / data.decode(), 'wb'), 'checksum': hashlib.sha256()}
        return b"ok ", b"Ready to receive new file"

    def update_file(self, data: bytes) -> Tuple[bytes, bytes]:
        """Update file content.

        Parameters
        ----------
        data : bytes
            Bytes containing filepath and data separated by ' '.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
        """
        name, file_content = data.split(b' ', 1)
        self.in_file[name]['fd'].write(file_content)
        self.in_file[name]['checksum'].update(file_content)
        return b"ok", b"File updated"

    def end_file(self, data: bytes) -> Tuple[bytes, bytes]:
        """Close file descriptor (write file in disk) and check BLAKE2b.

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

    def cancel_task(self, data: bytes) -> Tuple[bytes, bytes]:
        """Add task_id to interrupted_tasks and log the error message.

        Parameters
        ----------
        data : bytes
            String containing task_id and WazuhJSONEncoded object with the exception details.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
        """
        task_id, error_details = data.split(b' ', 1)
        error_json = json.loads(error_details, object_hook=as_wazuh_object)
        if task_id != b'None':
            self.interrupted_tasks.add(task_id)
            self.logger.error(f'The task was canceled due to the following error on the remote node: {error_json}',
                              exc_info=False)
        else:
            self.logger.error(f'The task was requested to be canceled but no task_id was received: {error_json}',
                              exc_info=False)

        return b'ok', b'Request received correctly'

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
            Bytes containing string ID and data separated by ' '.

        Returns
        -------
        bytes
            Result.
        bytes
            String ID.
        """
        name, str_data = data.split(b' ', 1)
        self.in_str[name].receive_data(str_data)
        return b"ok", b"String updated"

    def process_error_str(self, expected_len: bytes) -> Tuple[bytes, bytes]:
        """Search and delete item inside self.in_str.

        If null byetearray is created inside self.in_str and its len is the same as 'expected_len', it can be
        inferred that said item is garbage consequence of an incorrect communication and should be deleted.

        Parameters
        ----------
        expected_len : bytes
            Expected length of bytearray. If any bytearray has this length and its content is null, it will be deleted.

        Returns
        -------
        bytes
            Result.
        bytes
            Task_id of deleted item, if found.
        """
        # Regex to find any character different to '\x00' (null) inside a string.
        regex = re.compile(b'[^\x00]')
        expected_len = int(expected_len.decode())

        for item in list(self.in_str):
            if self.in_str.get(item, None) and self.in_str.get(item).total == expected_len and not \
                    regex.match(self.in_str.get(item).payload):
                self.in_str.pop(item, None)
                return b'ok', item

        return b'ok', b'None'

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
        except json.JSONDecodeError:
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
        task_logger.addFilter(cluster_utils.ClusterFilter(tag=self.tag, subtag=task_tag))
        return task_logger

    async def wait_for_file(self, file, task_id):
        """Wait until asyncio event is set.

        Parameters
        ----------
        file : asyncio.Event
            Event that will be set when a file is completely received.
        task_id : str
            ID of the task related to the file received.

        Raises
        ------
        exc : WazuhClusterError
            Timeout exception.
        """
        try:
            await asyncio.wait_for(file.wait(), timeout=self.server_config.communications.timeouts.receiving_file)

        except Exception as e:
            if isinstance(e, asyncio.TimeoutError):
                exc = exception.WazuhClusterError(3039)
            else:
                exc = exception.WazuhClusterError(3040, extra_message=str(e))
            # Notify the sending node to stop its task.
            with contextlib.suppress(Exception):
                await self.send_request(command=b"cancel_task",
                                        data=f"{task_id} {json.dumps(exc, cls=WazuhJSONEncoder)}".encode())
            raise exc

    async def log_exceptions(self, f):
        """Catch and log any exception raised while calling 'f'.

        Parameters
        ----------
        f : Coroutine
            Function to run.
        """
        try:
            return await f
        except Exception as e:
            self.logger.error(str(e))


class WazuhCommon:
    """Task implementing common methods for both clients and servers that are Wazuh specific."""

    def __init__(self):
        """Class constructor."""
        self.sync_tasks = {}

    def get_logger(self, logger_tag: str = '') -> logging.Logger:
        """Get a logger object.

        Parameters
        ----------
        logger_tag : str
            Logger task to return. If empty, it will return main class logger.

        Raises
        ------
        NotImplementedError
            If the method is not implemented.
        """
        raise NotImplementedError

    def setup_receive_file(self, receive_task_class: Callable, data: bytes = b'', logger_tag: str = ''):
        """Create ReceiveTaskClass object and add it to sync_tasks dict.

        Parameters
        ----------
        receive_task_class : Callable
            Class used to create an object.
        data : bytes
            Information used to create the object.
        logger_tag : str
            Logger task to use. If empty, it will use main class logger.

        Returns
        -------
        bytes
            Result.
        bytes
            Task ID.
        """
        my_task = receive_task_class(self, self.get_logger(logger_tag), data)
        self.sync_tasks[my_task.task_id] = my_task
        return b'ok', str(my_task).encode()

    def end_receiving_file(self, task_and_file_names: str, logger_tag: str = '') -> Tuple[bytes, bytes]:
        """Store full path to the received file in task_id and notify its availability.

        Parameters
        ----------
        task_and_file_names : str
            String containing task ID and relative filepath separated by ' '.
        logger_tag : str
            Logger task to use. If empty, it will use main class logger.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
        """
        task_id, filename = task_and_file_names.split(' ', 1)
        if task_id not in self.sync_tasks:
            # Remove filename if task_id does not exist, before raising exception.
            if os.path.exists(os.path.join(common.WAZUH_RUN, filename)):
                try:
                    os.remove(os.path.join(common.WAZUH_RUN, filename))
                except Exception as e:
                    self.get_logger(logger_tag).error(
                        f"Attempt to delete file {os.path.join(common.WAZUH_RUN, filename)} failed: {e}")
            raise exception.WazuhClusterError(3027, extra_message=task_id)

        # Set full path to file for task 'task_id' and notify it is ready to be read, so the lock is released.
        self.sync_tasks[task_id].filename = os.path.join(common.WAZUH_RUN, filename)
        self.sync_tasks[task_id].received_information.set()
        return b'ok', b'File correctly received'

    def error_receiving_file(self, task_id_and_error_details: str, logger_tag: str = '') -> Tuple[bytes, bytes]:
        """Handle reported error by peer in the send file process.

        Remove received file if taskname was specified. Replace filepath with the received error details and notify
        its availability.

        Parameters
        ----------
        task_id_and_error_details : str
             WazuhJSONEncoded object with the exception details.
        logger_tag : str
            Logger task to use. If empty, it will use main class logger.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
        """
        task_id, error_details = task_id_and_error_details.split(' ', 1)
        error_details_json = json.loads(error_details, object_hook=as_wazuh_object)
        if task_id in self.sync_tasks:
            # Remove filename if exists
            if os.path.exists(self.sync_tasks[task_id].filename):
                try:
                    os.remove(self.sync_tasks[task_id].filename)
                except Exception as e:
                    self.get_logger(logger_tag).error(f"Attempt to delete file {self.sync_tasks[task_id].filename} "
                                                      f"failed: {e}")
            self.sync_tasks[task_id].filename = error_details_json
            self.sync_tasks[task_id].received_information.set()
        else:
            self.get_logger(logger_tag).error(f"Error in synchronization process: {error_details_json}")
        return b'ok', b'Error received'

    def get_node(self):
        """Get basic information about the node.

        Returns
        -------
        dict
            Basic node information.
        """
        return self.get_manager().get_node()


class SyncTask:
    """Common class for master/worker sync tasks."""

    def __init__(self, cmd: bytes, logger, manager):
        """Class constructor.

        Parameters
        ----------
        cmd : bytes
            Request command to send to the master/worker.
        logger : Logger object
            Logger to use during synchronization process.
        manager : MasterHandler/WorkerHandler object
            The MasterHandler/WorkerHandler object that creates this one.
        """
        self.cmd = cmd
        self.logger = logger
        self.server = manager

    async def request_permission(self):
        """Request permission to start synchronization process with the master.

        Returns
        -------
        bool
            Whether permission is granted.
        """
        try:
            result = await self.server.send_request(command=self.cmd + b'_p', data=b'')
        except Exception as e:
            self.logger.error(f"Error asking for permission: {e}")
        else:
            if result == b'True':
                self.logger.debug("Permission to synchronize granted.")
                return True
            else:
                self.logger.debug(f"Master didn't grant permission to start a new synchronization: {result}")

        return False

    async def sync(self, *args, **kwargs):
        """Define sync() method. It is implemented differently for files and strings synchronization.

        Parameters
        ----------
        args
            Positional arguments for parent constructor class.
        kwargs
            Keyword arguments for parent constructor class.

        Raises
        ------
        NotImplementedError
            If the method is not implemented.
        """
        raise NotImplementedError


class SyncFiles(SyncTask):
    """Define methods to synchronize files with a remote node."""

    async def sync(self, files: Iterable, files_metadata: Dict, metadata_len: int, task_pool=None,
                   zip_limit: int = None):
        """Send metadata and files to other node.

        Parameters
        ----------
        files : Iterable
            File paths which will be zipped and sent to the receiving node.
        files_metadata : dict
            Paths (keys) and metadata (values) of the files to be sent. This dict is included as a JSON
            named "files_metadata.json".
        metadata_len : int
            Number of files inside 'files_metadata'.
        zip_limit : int
            Maximum size in the zip. No new files are added to the zip when this limit is about to be exceeded.
        task_pool : ProcessPoolExecutor or None
            Process pool object in charge of running compress function.

        Returns
        -------
        bool
            True if files were correctly sent to the remote node, None otherwise.
        """
        task_id = b'None'
        sent_size = 0
        time_to_send = 0
        min_zip_size = self.server.server_config.communications.zip.min_size
        max_zip_size = self.server.server_config.communications.zip.max_size
        zip_limit_tolerance = self.server.server_config.communications.zip.limit_tolerance
        timeout_receiving_file = self.server.server_config.communications.timeouts.receiving_file

        self.logger.debug(f"Compressing {'files and ' if files else ''}"
                          f"'files_metadata.json' of {metadata_len} files.")
        compressed_data, logs = await cluster.run_in_pool(self.server.loop, task_pool, cluster.compress_files,
                                                          self.server.name, files, files_metadata, zip_limit)

        cluster_utils.log_subprocess_execution(self.logger, logs)

        try:
            # Start the synchronization process with peer node and get a taskID.
            try:
                task_id = await self.server.send_request(command=self.cmd, data=b'')
            except Exception:
                task_id = b'None'
                raise

            # Send zip file to the master into chunks.
            self.logger.debug("Sending zip file.")
            time_to_send = time.perf_counter()
            sent_size = await self.server.send_file(compressed_data, task_id)
            time_to_send = time.perf_counter() - time_to_send
            self.logger.debug("Zip file sent.")

            # Notify what is the zip path for the current taskID.
            await self.server.send_request(
                command=self.cmd + b'_e',
                data=task_id + b' ' + os.path.relpath(compressed_data, common.WAZUH_RUN).encode()
            )
        except Exception as e:
            self.logger.error(f"Error sending zip file: {e}")
            if isinstance(e, exception.WazuhException):
                exc = json.dumps(e, cls=WazuhJSONEncoder).encode()
            else:
                exc = json.dumps(exception.WazuhClusterError(1000, extra_message=str(e)), cls=WazuhJSONEncoder).encode()
            with contextlib.suppress(Exception):
                # Notify error to master and delete its received file.
                await self.server.send_request(command=self.cmd + b'_r', data=task_id + b' ' + exc)
        finally:
            try:
                # Decrease max zip size if task was interrupted (otherwise, KeyError exception raised).
                self.server.interrupted_tasks.remove(task_id)
                self.server.current_zip_limit = max(min_zip_size, sent_size * (1 - zip_limit_tolerance))
                self.logger.debug(f"Decreasing sync size limit to {self.server.current_zip_limit / (1024**2):.2f} MB.")
            except KeyError:
                # Increase max zip size if two conditions are met:
                #   1. Current zip limit is lower than default.
                #   2. Time to send zip was far under timeout_receiving_file.
                if (self.server.current_zip_limit < max_zip_size and
                        time_to_send < timeout_receiving_file * (1 - zip_limit_tolerance)):
                    self.server.current_zip_limit = min(max_zip_size,
                                                        self.server.current_zip_limit * (1 / (1 - zip_limit_tolerance)))
                    self.logger.debug(f"Increasing sync size limit to {self.server.current_zip_limit / (1024**2):.2f}"
                                      f" MB.")

            try:
                # Remove local file.
                os.unlink(compressed_data)
            except FileNotFoundError:
                self.logger.error(f"File {compressed_data} could not be removed/not found. "
                                  f"May be due to a lost connection.")


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
    """Define special JSON encoder for Wazuh."""

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
        elif isinstance(obj, Exception):
            return {'__unhandled_exc__': {'__class__': obj.__class__.__name__,
                                          '__args__': obj.args}}

        return json.JSONEncoder.default(self, obj)


def as_wazuh_object(dct: Dict):
    try:
        if '__callable__' in dct:
            encoded_callable = dct['__callable__']
            funcname = encoded_callable['__name__']
            if '__wazuh__' in encoded_callable:
                # Encoded Wazuh instance method.
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
        elif '__unhandled_exc__' in dct:
            exc_data = dct['__unhandled_exc__']
            exc_dict = {exc_data['__class__']: exc_data['__args__']}
            return ast.literal_eval(json.dumps(exc_dict))
        return dct

    except (KeyError, AttributeError):
        raise exception.WazuhInternalError(1000,
                                           extra_message=f"Wazuh object cannot be decoded from JSON {dct}",
                                           cmd_error=True)


def create_ssl_context(
    logger: logging.Logger,
    purpose: ssl.Purpose,
    cafile: str,
    certfile: str,
    keyfile: str,
    keyfile_password: str = '',
) -> ssl.SSLContext:
    """Create a SSLContext with the key and certificates provided.

    Parameters
    ----------
    logger : logging.Logger
        Node instance logger.
    purpose : ssl.Purpose
        Context purpose.
    cafile : str
        Root certificate file path.
    certfile : str
        Node certificate file path.
    keyfile : str
        Node key file path.
    keyfile_password : str
        Node key file password. Default is no password.
    """
    try:
        ssl_context = ssl.create_default_context(
            purpose=purpose,
            cafile=cafile
        )
        ssl_context.load_cert_chain(
            certfile=certfile,
            keyfile=keyfile,
            password=keyfile_password
        )
    except ssl.SSLError as exc:
        logger.error(f'Failed loading SSL context: {exc}. Using default one.')
        ssl_context = ssl.create_default_context(purpose=purpose)

    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3

    return ssl_context
