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
import re
import struct
import traceback
from importlib import import_module
from time import perf_counter
from typing import Tuple, Dict, Callable, List
from uuid import uuid4

import cryptography.fernet

import wazuh.core.cluster.utils
import wazuh.core.results as wresults
from wazuh import Wazuh
from wazuh.core import common, exception
from wazuh.core import utils
from wazuh.core.cluster import cluster
from wazuh.core.common import decimals_date_format
from wazuh.core.wdb import WazuhDBConnection


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


class SendStringTask:
    """
    Create an asyncio task that can be identified by a task_id specified in advance.
    """

    def __init__(self, wazuh_common, logger):
        """Class constructor.

        Parameters
        ----------
        wazuh_common : WazuhCommon object
            Instance of WazuhCommon.
        logger : Logger object
            Logger to use during the receive process.
        """
        self.wazuh_common = wazuh_common
        self.coro = self.set_up_coro()
        self.task = asyncio.create_task(self.coro())
        self.task.add_done_callback(self.done_callback)
        self.logger = logger

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

        Remove string and task_id (if exist) from sync_tasks dict. If task was not cancelled, raise stored exception.
        """
        if not self.task.cancelled():
            task_exc = self.task.exception()
            if task_exc:
                self.logger.error(task_exc)


class ReceiveStringTask:
    """
    Create an asyncio task that can be identified by a task_id specified in advance.
    """

    def __init__(self, wazuh_common, logger, task_id, info_type='agent-info'):
        """Class constructor.

        Parameters
        ----------
        wazuh_common : WazuhCommon object
            Instance of WazuhCommon.
        logger : Logger object
            Logger to use during the receive process.
        task_id : bytes
            Pre-defined task_id to identify this object.
        info_type : str
            Information type handled.
        """
        self.wazuh_common = wazuh_common
        self.coro = self.set_up_coro()
        self.task_id = task_id
        self.info_type = info_type
        self.task = asyncio.create_task(self.coro(self.task_id, self.info_type))
        self.task.add_done_callback(self.done_callback)
        self.logger = logger

    def __str__(self) -> str:
        """Magic method str.

        Returns
        -------
        str
            Task id of this object.
        """
        return self.task_id.decode()

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

        Remove string and task_id (if exist) from sync_tasks dict. If task was not cancelled, raise stored exception.
        """
        if self.task_id in self.wazuh_common.in_str:
            # pop() is used instead of 'del' so an exception is never raised here
            self.wazuh_common.in_str.pop(self.task_id, None)
        if self.task_id in self.wazuh_common.sync_tasks:
            del self.wazuh_common.sync_tasks[self.task_id]
        if not self.task.cancelled():
            task_exc = self.task.exception()
            if task_exc:
                self.logger.error(task_exc)


class ReceiveFileTask:
    """
    Create an asyncio task that can be identified by a task_id.
    """

    def __init__(self, wazuh_common, logger, task_id: bytes = b''):
        """Class constructor.

        Parameters
        ----------
        wazuh_common : WazuhCommon object
            Instance of WazuhCommon.
        logger : Logger object
            Logger to use during the receive process.
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
        -------
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
        # Object use to encrypt and decrypt requests.
        self.my_fernet = cryptography.fernet.Fernet(base64.b64encode(fernet_key.encode())) if fernet_key else None
        # Logging.Logger object used to write logs.
        self.logger = logging.getLogger('wazuh') if not logger else logger
        # Logging tag.
        self.tag = tag
        # Modify filter tags with context vars.
        wazuh.core.cluster.utils.context_tag.set(self.tag)
        self.cluster_items = cluster_items
        # Transports in asyncio are an abstraction of sockets.
        self.transport = None
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
        encrypted_data = self.my_fernet.encrypt(data) if self.my_fernet is not None else data
        encrypted_message_size = self.header_len + len(encrypted_data)

        # Message size is <= request_chunk, send the message
        if len(data) <= self.request_chunk:
            msg = bytearray(encrypted_message_size)
            msg[:self.header_len] = struct.pack(self.header_format, counter, len(encrypted_data), command)
            msg[self.header_len:encrypted_message_size] = encrypted_data
            return [msg]

        # Message size > request_chunk, send the message divided
        else:
            # Command with the flag d (divided)
            command = command[:-len(InBuffer.divide_flag)] + InBuffer.divide_flag
            msg_list = []
            partial_data_size = 0
            data_size = len(encrypted_data)
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
                msg[self.header_len:message_size] = encrypted_data[
                                                    partial_data_size:partial_data_size + message_size - self.header_len]
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
        -------
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
                # Decrypt received message if it is not a part of a divided message
                try:
                    decrypted_payload = \
                        self.my_fernet.decrypt(bytes(self.in_msg.payload)) \
                            if self.my_fernet is not None and not self.in_msg.flag_divided and \
                               self.in_msg.counter not in self.div_msg_box \
                            else bytes(self.in_msg.payload)
                except cryptography.fernet.InvalidToken:
                    raise exception.WazuhClusterError(3025)
                yield self.in_msg.cmd, self.in_msg.counter, decrypted_payload, self.in_msg.flag_divided
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
                                                   timeout=self.cluster_items['intervals']['communication'][
                                                       'timeout_cluster_request'])
            del self.box[msg_counter]
        except asyncio.TimeoutError:
            self.box[msg_counter] = None
            return b'Error sending request: timeout expired.'
        return response_data

    async def get_chunks_in_task_id(self, task_id: bytes, error_command: bytes) -> dict:
        """Function in charge of collecting the chunks stored under task_id.

        Parameters
        ----------
        task_id : bytes
            Pre-defined task_id to identify this object.
        error_command : bytes
            Command sent to the sender node in case of error.

        Returns
        -------
        data : dict
            Chunks collected through task_id.
        """
        try:
            # Chunks were stored under 'task_id' as an string.
            received_string = self.in_str[task_id].payload
            data = json.loads(received_string.decode())
        except KeyError as e:
            print(str(e))
            await self.send_request(command=error_command,
                                    data=f'error while trying to access string under task_id {str(e)}.'.encode())
            raise exception.WazuhClusterError(3035,
                                              extra_message=f"it should be under task_id {str(e)}, but it's empty.")
        except ValueError as e:
            await self.send_request(command=error_command, data=f'error while trying to load JSON: {str(e)}'.encode())
            raise exception.WazuhClusterError(3036, extra_message=str(e))

        return data

    async def update_chunks_wdb(self, data: dict, info_type: str, logger: logging.Logger, error_command: bytes,
                                timeout: int) -> dict:
        """Send the received data to WDB and returns the result of the operation.

        Parameters
        ----------
        data : dict
            Dict containing command and list of chunks to be sent to wazuh-db.
        info_type : str
            Information type handled.
        logger : Logger object
            Logger to use.
        error_command : bytes
            Command sent to the sender node in case of error.
        timeout : int
            Seconds to wait before stopping the task.

        Returns
        -------
        result : dict
            Dict containing number of updated chunks, error messages (if any) and time spent.
        """
        try:
            result = await cluster.run_in_pool(self.loop, self.server.task_pool, send_data_to_wdb, data,
                                               timeout, info_type=info_type)
        except Exception as e:
            print(f'error processing {info_type} chunks in process pool: {str(e)}'.encode())
            await self.send_request(command=error_command,
                                    data=f'error processing {info_type} chunks in process pool: {str(e)}'.encode())
            raise exception.WazuhClusterError(3037, extra_message=str(e))

        # Log information about the results
        for error in result['error_messages']['others']:
            logger.error(error)

        for error in result['error_messages']['chunks']:
            logger.debug2(f'Chunk {error[0] + 1}/{len(data["chunks"])}: {data["chunks"][error[0]]}')
            logger.error(
                f'Wazuh-db response for chunk {error[0] + 1}/{len(data["chunks"])} was not "ok": {error[1]}')

        logger.debug(f'{result["updated_chunks"]}/{len(data["chunks"])} chunks updated in wazuh-db '
                     f'in {result["time_spent"]:3f}s.')
        result['error_messages'] = [error[1] for error in result['error_messages']['chunks']]

        return result

    async def send_result_to_manager(self, command: bytes, result: dict) -> bytes:
        """Send the results to the manager with the specified command.

        Parameters
        ----------
        command : bytes
            Command sent to the sender node.
        result : dict
            Insertion operation result.

        Returns
        -------
        response : bytes
            Response from the receiving node to the sender node of the task.
        """
        response = await self.send_request(command=command, data=json.dumps(result).encode())

        return response

    async def sync_wazuh_db_information(self, task_id: bytes, info_type: str, logger: logging.Logger,
                                        command: bytes, error_command: bytes, timeout: int,
                                        sync_dict: dict = None) -> bytes:
        """Create a process to send to the local wazuh-db the chunks of data received from a master/worker node.

        Parameters
        ----------
        task_id : bytes
            Pre-defined task_id to identify this object.
        info_type : str
            Information type handled.
        logger : Logger object
            Logger to use.
        command : bytes
            Command sent to the sender node.
        error_command : bytes
            Command sent to the sender node in case of error.
        timeout : int
            Seconds to wait before stopping the wdb update task.
        sync_dict : dict
            Dictionary with general cluster information.

        Returns
        -------
        response : bytes
            Response from the receiving node to the sender node of the task.
        """
        sync_dict = sync_dict if sync_dict is not None else {}
        logger.info('Starting.')

        start_time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
        data = await self.get_chunks_in_task_id(task_id, error_command)
        result = await self.update_chunks_wdb(data, info_type, logger, error_command, timeout)
        response = await self.send_result_to_manager(command, result)
        end_time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)

        sync_dict.update({'date_start_master': start_time.strftime(decimals_date_format),
                          'date_end_master': end_time.strftime(decimals_date_format),
                          'n_synced_chunks': result['updated_chunks']})
        logger.info(f'Finished in {(end_time - start_time).total_seconds():.3f}s. '
                    f'Updated {result["updated_chunks"]} chunks.')

        return response

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
        relative_path = filename.replace(common.wazuh_path.encode(), b'')
        # Tell to the destination node where (inside wazuh_path) the file has to be written.
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

        if task_id.startswith(b'Error'):
            self.logger.error(f'There was an error while trying to send a string: {task_id}')
            await self.send_request(command=b'err_str', data=str(total).encode())
        else:
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
            exc_info = json.dumps(exception.WazuhClusterError(1000, extra_message=str(e)),
                                  cls=WazuhJSONEncoder).encode()
            res = await self.send_request(b'dapi_err', exc_info)
        finally:
            # Remove the string after using it
            self.in_str.pop(string_id, None)

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
            await self.send_request(b'sendsyn_err', json.dumps(e, cls=WazuhJSONEncoder).encode())
        except Exception as e:
            self.logger.error(f"Error sending send sync response to local client: {e}")
            exc_info = json.dumps(exception.WazuhClusterError(1000, extra_message=str(e)),
                                  cls=WazuhJSONEncoder).encode()
            await self.send_request(b'sendsync_err', exc_info)
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
                    payload = self.div_msg_box[counter] + payload
                    del self.div_msg_box[counter]
                    # Decrypt the joined payload
                    try:
                        payload = self.my_fernet.decrypt(bytes(payload)) if self.my_fernet is not \
                                                                            None else bytes(payload)
                    except cryptography.fernet.InvalidToken:
                        raise exception.WazuhClusterError(3025)

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
        self.in_file[data] = {'fd': open(common.wazuh_path + data.decode(), 'wb'), 'checksum': hashlib.sha256()}
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

    def setup_send_info(self, SendTaskClass: Callable, data: bytes = b''):
        """Create SendTaskClass object.

        Parameters
        ----------
        SendTaskClass : Callable
            Class used to create an object.
        data : bytes
            Information used to create the object.

        Returns
        -------
        bytes
            Result.
        bytes
            Task ID.
        """
        my_task = SendTaskClass(self, self.get_logger(self.logger_tag))
        return b'ok', str(my_task).encode()

    def setup_receive_file(self, ReceiveTaskClass: Callable, data: bytes = b''):
        """Create ReceiveTaskClass object and add it to sync_tasks dict.

        Parameters
        ----------
        ReceiveTaskClass : Callable
            Class used to create an object.
        data : bytes
            Information used to create the object.

        Returns
        -------
        bytes
            Result.
        bytes
            Task ID.
        """
        my_task = ReceiveTaskClass(self, self.get_logger(self.logger_tag), data)
        self.sync_tasks[my_task.task_id] = my_task
        return b'ok', str(my_task).encode()

    def end_receiving_file(self, task_and_file_names: str) -> Tuple[bytes, bytes]:
        """Store full path to the received file in task_id and notify its availability.

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
        task_id, filename = task_and_file_names.split(' ', 1)
        if task_id not in self.sync_tasks:
            # Remove filename if task_id does not exists, before raising exception.
            if os.path.exists(os.path.join(common.wazuh_path, filename)):
                try:
                    os.remove(os.path.join(common.wazuh_path, filename))
                except Exception as e:
                    self.get_logger(self.logger_tag).error(
                        f"Attempt to delete file {os.path.join(common.wazuh_path, filename)} failed: {e}")
            raise exception.WazuhClusterError(3027, extra_message=task_id)

        # Set full path to file for task 'task_id' and notify it is ready to be read, so the lock is released.
        self.sync_tasks[task_id].filename = os.path.join(common.wazuh_path, filename)
        self.sync_tasks[task_id].received_information.set()
        return b'ok', b'File correctly received'

    def error_receiving_file(self, task_id_and_error_details: str) -> Tuple[bytes, bytes]:
        """Handle reported error by peer in the send file process.

        Remove received file if taskname was specified. Replace filepath with the received error details and notify
        its availability.

        Parameters
        ----------
        task_id_and_error_details : str
             WazuhJSONEncoded object with the exception details.

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
                    self.get_logger(self.logger_tag).error(f"Attempt to delete file {self.sync_tasks[task_id].filename}"
                                                           f" failed: {e}")
            self.sync_tasks[task_id].filename = error_details_json
            self.sync_tasks[task_id].received_information.set()
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


class SyncTask:
    """
    Common class for master/worker sync tasks.
    """

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
        result = await self.server.send_request(command=self.cmd + b'_p', data=b'')

        if isinstance(result, Exception):
            self.logger.error(f"Error asking for permission: {result}")
        elif result == b'True':
            self.logger.debug("Permission to synchronize granted.")
            return True
        else:
            self.logger.debug(f"Master didn't grant permission to start a new synchronization: {result}")

        return False


class SyncWazuhdb(SyncTask):
    """
    Define methods to send information to the master/worker node (wazuh-db) through send_string protocol.
    """

    def __init__(self, manager, logger, data_retriever: Callable, cmd: bytes = b'', get_data_command: str = '',
                 set_data_command: str = '', get_payload: dict = None, set_payload: dict = None, pivot_key: str = ''):
        """Class constructor.

        Parameters
        ----------
        manager : MasterHandler/WorkerHandler object
            The MasterHandler/WorkerHandler object that creates this one.
        cmd : bytes
            Request command to send to the master/worker.
        get_data_command : str
            Command to retrieve data from local wazuh-db.
        set_data_command : str
            Command to set data in master/worker's wazuh-db.
        logger : Logger object
            Logger to use during synchronization process.
        data_retriever : Callable
            Function to be called to obtain chunks of data. It must return a list of chunks.
        get_payload : dict
            Payload to request information with "get" command.
        set_payload : dict
            Payload to write the information with the "set" command.
        pivot_key : str
            Key to request the information from the database in case it is not fully contained in a single request.
        """
        super().__init__(manager=manager, logger=logger, cmd=cmd)
        self.get_data_command = get_data_command
        if get_payload is None:
            get_payload = {}
        self.get_payload = get_payload
        self.set_data_command = set_data_command
        if set_payload is None:
            set_payload = {}
        self.set_payload = set_payload
        self.pivot_key = pivot_key
        self.data_retriever = data_retriever

    async def retrieve_information(self):
        """Collect the required information from the local node's database. This function will collect
        information until the status is 'ok' or 'err', in which case an exception will be raised.

        The function will determine when it is necessary to use a parameter in the request payload
        to specify the first value to get in the next query to WDB.

        Returns
        -------
        chunks : list
            List of results obtained from WDB.
        """
        pivoting = self.get_payload != {} and self.pivot_key != ''
        status = ''
        chunks = []
        last_pivot_value = 0
        if pivoting:
            self.get_payload[self.pivot_key] = last_pivot_value

        try:
            # Retrieve information from local wazuh-db
            get_chunks_start_time = perf_counter()
            while status != 'ok':
                command = self.get_data_command + json.dumps(self.get_payload)
                result = self.data_retriever(command=command)
                status = result[0]
                chunks.append(result[1])
                if pivoting:
                    try:
                        last_pivot_value = json.loads(result[1])[-1]['data'][-1]['id']
                        self.get_payload[self.pivot_key] = last_pivot_value
                    except (IndexError, KeyError):
                        pass
        except exception.WazuhException as e:
            self.logger.error(f"Error obtaining data from wazuh-db: {e}")
            return []

        self.logger.debug(f"Obtained {len(chunks)} chunks of data in {(perf_counter() - get_chunks_start_time):.3f}s.")
        return chunks

    async def sync(self, start_time: float, chunks: List):
        """Start sending information to master/worker node.

        Parameters
        ----------
        start_time : float
            Start time to be used when logging task duration if master/worker's response is not expected.
        chunks : list
            Data gathered from the database.

        Returns
        -------
        bool
            True if data was correctly sent to the master/worker node, None otherwise.
        """
        if chunks:
            # Send list of chunks as a JSON string
            data = json.dumps({'set_data_command': self.set_data_command,
                               'payload': self.set_payload, 'chunks': chunks}).encode()
            task_id = await self.server.send_string(data)
            if task_id.startswith(b'Error'):
                raise exception.WazuhClusterError(3016, extra_message=f'String with agents information could '
                                                                      f'not be sent to the master node: {task_id}')

            # Specify under which task_id the JSON can be found in the master/worker.
            await self.server.send_request(command=self.cmd, data=task_id)
            self.logger.debug(f"All chunks sent.")
        else:
            self.logger.info(f"Finished in {(perf_counter() - start_time):.3f}s (0 chunks sent).")
        return True


def end_sending_agent_information(logger, start_time, response) -> Tuple[bytes, bytes]:
    """Function called when the master/worker sends the "syn_m_a_e", "syn_m_g_e" or "syn_w_g_e" command.

    This method is called once the master finishes processing the agent-info/agent-groups. It logs
    information like the number of chunks that were updated and any error message.

    Parameters
    ----------
    logger : Logger object
        Logger to use during synchronization process.
    start_time : float
        Timestamp collected at the start of the end process of a task of type agent-information.
    response : str
        JSON containing information about agent-info/agent-groups sync status.

    Returns
    -------
    bytes
        Result.
    bytes
        Response message.
    """
    data = json.loads(response)
    msg = f"Finished in {(perf_counter() - start_time):.3f}s ({data['updated_chunks']} " \
          f"chunks updated)."
    logger.info(msg) if not data['error_messages'] else logger.error(
        msg + f" There were {len(data['error_messages'])} chunks with errors: {data['error_messages']}")

    return b'ok', b'Thanks'


def error_receiving_agent_information(logger, response, info_type):
    """Function called when the master/worker sends the
    "syn_m_a_err", "syn_m_g_err", "syn_w_g_err" or "syn_w_g_err" command.

    Parameters
    ----------
    logger : Logger object
        Logger to use.
    response : str
        Message with extra information of the error.
    info_type : str
        Information type handled.

    Returns
    -------
    bytes
        Result.
    bytes
        Response message.
    """
    logger.error(f"There was an error while processing {info_type} on the master: {response}")

    return b'ok', b'Thanks'


def send_data_to_wdb(data, timeout, info_type='agent-info'):
    """Send chunks of data to Wazuh-db socket.

    Parameters
    ----------
    data : dict
        Dict containing command and list of chunks to be sent to wazuh-db.
    timeout : int
        Seconds to wait before stopping the task.
    info_type : str
        Information type handled.

    Returns
    -------
    result : dict
        Dict containing number of updated chunks, error messages (if any) and time spent.
    """
    result = {'updated_chunks': 0, 'error_messages': {'chunks': [], 'others': []}, 'time_spent': 0}
    wdb_conn = WazuhDBConnection()
    before = perf_counter()

    try:
        with utils.Timeout(timeout):
            for i, chunk in enumerate(data['chunks']):
                try:
                    if info_type == 'agent-info':
                        wdb_conn.send(f"{data['set_data_command']} {chunk}", raw=True)
                    elif info_type == 'agent-groups':
                        data['payload']['data'] = json.loads(chunk)[0]['data']
                        wdb_conn.send(f"{data['set_data_command']} {json.dumps(data['payload'])}", raw=True)
                    result['updated_chunks'] += 1
                except TimeoutError as e:
                    raise e
                except Exception as e:
                    result['error_messages']['chunks'].append((i, str(e)))
    except TimeoutError:
        result['error_messages']['others'].append(f'Timeout while processing {info_type} chunks.')
    except Exception as e:
        result['error_messages']['others'].append(f'Error while processing {info_type} chunks: {e}')

    result['time_spent'] = perf_counter() - before
    wdb_conn.close()
    return result


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
