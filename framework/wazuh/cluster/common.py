# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import base64
import hashlib
import json
import logging
import os
import random
import struct
import traceback
import cryptography.fernet
from typing import Tuple, Dict, Callable
from wazuh import exception, common, Wazuh
from wazuh.cluster import cluster
import wazuh.results as wresults
from importlib import import_module


class Response:
    """
    Defines and stores a response from a request
    """

    def __init__(self):
        # Event object which will be set when the response is received
        self.received_response = asyncio.Event()
        # Response content
        self.content = None

    async def read(self) -> bytes:
        await self.received_response.wait()
        return self.content

    def write(self, content):
        self.content = content
        self.received_response.set()


class InBuffer:
    """
    Defines a buffer to receive incoming requests
    """

    def __init__(self, total=0):
        self.payload = bytearray(total)  # array to store the message's data
        self.total = total  # total of bytes to receive
        self.received = 0  # number of received bytes
        self.cmd = ''  # request's command in header
        self.counter = 0  # request's counter in the box

    def get_info_from_header(self, header: bytes, header_format: str, header_size: int) -> bytes:
        """
        Gets information contained in the request's header

        :param header: raw header to process
        :param header_format: struct format of the header
        :param header_size: Size in bytes of the header
        :return: updated buffer
        """
        self.counter, self.total, cmd = struct.unpack(header_format, header[:header_size])
        self.cmd = cmd.split(b' ')[0]
        self.payload = bytearray(self.total)
        return header[header_size:]

    def receive_data(self, data: bytes) -> bytes:
        """
        Adds received data to payload bytearray

        :param data: Received data
        :return: updated data buffer
        """
        len_data = len(data[:self.total - self.received])
        self.payload[self.received:len_data + self.received] = data[:self.total - self.received]
        self.received += len_data
        return data[len_data:]


class ReceiveFileTask:
    """
    Implements an asyncio task but including a name or ID for it.
    """

    def __init__(self, wazuh_common, logger):
        """
        Class constructor

        :param coro: asyncio coroutine to run in the task
        """
        self.wazuh_common = wazuh_common
        self.coro = self.set_up_coro()
        self.name = str(random.randint(0, 2**32))
        self.received_information = asyncio.Event()
        self.task = asyncio.create_task(self.coro(self.name, self.received_information))
        self.task.add_done_callback(self.done_callback)
        self.filename = ''
        self.logger = logger

    def __str__(self) -> str:
        """
        Magic method str.
        :return: task name
        """
        return self.name

    def set_up_coro(self) -> Callable:
        raise NotImplementedError

    def done_callback(self, future=None):
        """
        Function to call when the task is finished
        :return:
        """
        if self.name in self.wazuh_common.sync_tasks:
            del self.wazuh_common.sync_tasks[self.name]
        if not self.task.cancelled():
            task_exc = self.task.exception()
            if task_exc:
                self.logger.error(task_exc)


class Handler(asyncio.Protocol):
    """
    Defines common methods for echo clients and servers
    """

    def __init__(self, fernet_key: str, logger: logging.Logger, cluster_items: Dict, tag: str = "Handler"):
        """
        Class constructor

        :param fernet_key: 32 length string used as key to initialize cryptography's Fernet.
        :param tag: logging tag to use
        """
        super().__init__()
        # The counter is used to identify each message. If an incoming request has a known ID,
        # it is processed as a response
        self.counter = random.SystemRandom().randint(0, 2 ** 32 - 1)
        # The box stores all sent messages IDs
        self.box = {}
        # defines command length
        self.cmd_len = 12
        # defines header length
        self.header_len = self.cmd_len + 8  # 4 bytes of counter and 4 bytes of message size
        # defines header format
        self.header_format = '!2I{}s'.format(self.cmd_len)
        # stores received data
        self.in_buffer = b''
        # stores last received message
        self.in_msg = InBuffer()
        # stores incoming file information from file commands
        self.in_file = {}
        # stores incoming string information from string commands
        self.in_str = {}
        # maximum message length to send in a single request
        self.request_chunk = 5242880
        # stores message to be sent
        self.out_msg = bytearray(self.header_len + self.request_chunk*2)
        # object use to encrypt and decrypt requests
        self.my_fernet = cryptography.fernet.Fernet(base64.b64encode(fernet_key.encode())) if fernet_key else None
        # logging.Logger object used to write logs
        self.logger = logger.getChild(tag)
        # logging tag
        self.tag = tag
        self.logger_filter = cluster.ClusterFilter(tag=self.tag, subtag="Main")
        self.logger.addFilter(self.logger_filter)
        self.cluster_items = cluster_items
        # transports in asyncio are an abstraction of sockets
        self.transport = None

    def push(self, message: bytes):
        """
        Sends a message to peer

        :param message: message to send
        """
        self.transport.write(message)

    def next_counter(self) -> int:
        """
        Increases the message ID counter

        :return: new counter
        """
        self.counter = (self.counter + 1) % (2 ** 32)
        return self.counter

    def msg_build(self, command: bytes, counter: int, data: bytes) -> bytes:
        """
        Builds a message with header + payload

        :param command: command to send
        :param counter: message id
        :param data: data to send
        :return: built message
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
        """
        Parses an incoming message

        :return: whether a message was parsed or not.
        """
        if self.in_buffer:
            if self.in_msg.received == 0:
                # a new message has been received. Both header and payload must be processed.
                self.in_buffer = self.in_msg.get_info_from_header(header=self.in_buffer,
                                                                  header_format=self.header_format,
                                                                  header_size=self.header_len)
                self.in_buffer = self.in_msg.receive_data(data=self.in_buffer)
            else:
                # the previous message has not been completely received yet. No header to parse, just payload.
                self.in_buffer = self.in_msg.receive_data(data=self.in_buffer)
            return True
        else:
            return False

    def get_messages(self) -> Tuple[bytes, int, bytes]:
        """
        Called when data is received in the transport. It decrypts the received data and returns it using generators.
        If the data received in the transport contains multiple separated messages, it will return all of them in
        separate yields.

        :return: Last received message command, counter and payload
        """
        parsed = self.msg_parse()

        while parsed:
            # self.logger.debug("Received message: {} / {}".format(self.in_msg['received'], self.in_msg['total_size']))
            if self.in_msg.received == self.in_msg.total:
                # the message was correctly received
                # decrypt received message
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
        """
        Sends a request to peer

        :param command: command to send
        :param data: data to send
        :return: response from peer.
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
            response_data = await asyncio.wait_for(response.read(), timeout=self.cluster_items['intervals']['communication']['timeout_cluster_request'])
        except asyncio.TimeoutError:
            raise exception.WazuhClusterError(3020)

        return response_data

    async def send_file(self, filename: str) -> bytes:
        """
        Sends a file to peer.

        :param filename: File path to send
        :return: response message.
        """
        if not os.path.exists(filename):
            raise exception.WazuhClusterError(3034, extra_message=filename)

        filename = filename.encode()
        relative_path = filename.replace(common.ossec_path.encode(), b'')
        response = await self.send_request(command=b'new_file', data=relative_path)

        file_hash = hashlib.sha256()
        with open(filename, 'rb') as f:
            for chunk in iter(lambda: f.read(self.request_chunk - len(relative_path) - 1), b''):
                response = await self.send_request(command=b'file_upd', data=relative_path + b' ' + chunk)
                file_hash.update(chunk)

        response = await self.send_request(command=b'file_end', data=relative_path + b' ' + file_hash.digest())

        return b'File sent'

    async def send_string(self, my_str: bytes) -> bytes:
        """
        Sends a large string to peer.

        :param my_str: String to send.
        :param chunk: number of elements each slide will have
        :return: whether sending was successful or not.
        """
        total = len(my_str)
        task_id = await self.send_request(command=b'new_str', data=str(total).encode())

        local_req_chunk = self.request_chunk - len(task_id) - 1
        for c in range(0, total, local_req_chunk):
            response = await self.send_request(command=b'str_upd', data=task_id + b' ' +
                                                                        my_str[c:c + local_req_chunk])

        return task_id

    def get_manager(self):
        """
        Returns the manager object
        :return: a manager object
        """
        raise NotImplementedError

    async def forward_dapi_response(self, data: bytes):
        """
        Forwards a distributed API response from master node.

        :param data: Bytes containing local client name and string id separated by ' '
        :return: sucess/error message
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
            exc_info = json.dumps(exception.WazuhClusterError(code=1000, extra_message=str(e)), cls=WazuhJSONEncoder).encode()
            res = await self.send_request(b'dapi_err', exc_info)

    def data_received(self, message: bytes) -> None:
        """
        Handles received data from other peer.

        :param message: data received
        """
        self.in_buffer = message
        for command, counter, payload in self.get_messages():
            if counter in self.box:
                self.box[counter].write(self.process_response(command, payload))
            else:
                self.dispatch(command, counter, payload)

    def dispatch(self, command: bytes, counter: int, payload: bytes) -> None:
        """
        Processes a received message and sends a response

        :param command: command received
        :param counter: message id
        :param payload: data received
        """
        try:
            command, payload = self.process_request(command, payload)
        except exception.WazuhException as e:
            self.logger.error("Internal error processing request '{}': {}".format(command, e))
            command, payload = b'err', json.dumps(e, cls=WazuhJSONEncoder).encode()
        except Exception as e:
            self.logger.error("Unhandled error processing request '{}': {}".format(command, e), exc_info=True)
            command, payload = b'err', json.dumps(exception.WazuhInternalError(1000, extra_message=str(e)),
                                                  cls=WazuhJSONEncoder).encode()

        self.push(self.msg_build(command, counter, payload))

    def close(self):
        """
        Closes connection
        """
        self.transport.close()

    def process_request(self, command: bytes, data: bytes) -> Tuple[bytes, bytes]:
        """
        Defines commands for both master and clients.

        :param command: Received command from other peer.
        :param data: Received data from other peer.
        :return: message to send.
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
        """
        Defines response commands for both master and client

        :param command: response command received
        :param payload: data received
        :return:
        """
        if command == b'ok':
            return payload
        elif command == b'err':
            return self.process_error_from_peer(payload)
        else:
            return b"Unkown response command received: " + command

    def echo(self, data: bytes) -> Tuple[bytes, bytes]:
        """
        Defines command "echo"

        :param data: message to echo
        :return: message to send
        """
        return b'ok', data

    def receive_file(self, data: bytes) -> Tuple[bytes, bytes]:
        """
        Defines behaviour of command "new_file". This behaviour is to create a file descriptor to store the incoming
        file.

        :param data: File name
        :return: Message
        """
        self.in_file[data] = {'fd': open(common.ossec_path + data.decode(), 'wb'), 'checksum': hashlib.sha256()}
        return b"ok ", b"Ready to receive new file"

    def update_file(self, data: bytes) -> Tuple[bytes, bytes]:
        """
        Defines behaviour of command "file_upd" which consists in updating file contents.

        :param data: file content
        :return: Message
        """
        name, chunk = data.split(b' ', 1)
        self.in_file[name]['fd'].write(chunk)
        self.in_file[name]['checksum'].update(chunk)
        return b"ok", b"File updated"

    def end_file(self, data: bytes) -> Tuple[bytes, bytes]:
        """
        Defines behaviour of command "end_file" which consists in closing file descriptor and check its md5.

        :param data: file sha256
        :return: Message
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
        """
        Defines behaviour of command "recv_str". This behaviour is to append to resize a bytearray with the string size.

        :param data: Request data: string size
        :return: Message
        """
        name = str(random.SystemRandom().randint(0, 2 ** 32 - 1)).encode()
        self.in_str[name] = InBuffer(total=int(data))
        return b"ok", name

    def str_upd(self, data: bytes) -> Tuple[bytes, bytes]:
        """
        Defines behaviour of command "str_upd". This behaviour is to update string contents.

        :param data: String contents
        :return: Message
        """
        name, str_data = data.split(b' ', 1)
        self.in_str[name].receive_data(str_data)
        # self.logger.debug("Length: {}/{}".format(self.in_str[name].received, self.in_str[name].total))
        return b"ok", b"Chunk received"

    def process_unknown_cmd(self, command: bytes) -> Tuple[bytes, bytes]:
        """
        Defines message when an unknown command is received

        :param command: command received from peer
        :return: message to send
        """
        return b'err', "unknown command '{}'".format(command).encode()

    def process_error_from_peer(self, data: bytes) -> bytes:
        """
        Handles errors in requests

        :param data: error message from peer
        :return: Nothing
        """
        try:
            exc = json.loads(data.decode(), object_hook=as_wazuh_object)
        except json.JSONDecodeError as e:
            exc = exception.WazuhClusterError(3000, extra_message=data.decode())

        return exc

    def setup_task_logger(self, task_tag: str):
        task_logger = self.logger.getChild(task_tag)
        task_logger.addFilter(cluster.ClusterFilter(tag=self.tag, subtag=task_tag))
        return task_logger


class WazuhCommon:
    """
    Task implementing common methods for both clients and servers that are Wazuh specific.
    """
    def __init__(self):
        self.sync_tasks = {}
        self.logger_tag = ''

    def get_logger(self, logger_tag: str = '') -> logging.Logger:
        raise NotImplementedError

    def setup_receive_file(self, ReceiveTaskClass: Callable):
        my_task = ReceiveTaskClass(self, self.get_logger(self.logger_tag))
        self.sync_tasks[my_task.name] = my_task
        return b'ok', str(my_task).encode()

    def end_receiving_file(self, task_and_file_names: str) -> Tuple[bytes, bytes]:
        task_name, filename = task_and_file_names.split(' ', 1)
        if task_name not in self.sync_tasks:
            raise exception.WazuhClusterError(3027, extra_message=task_name)

        self.sync_tasks[task_name].filename = os.path.join(common.ossec_path, filename)
        self.sync_tasks[task_name].received_information.set()
        return b'ok', b'File correctly received'

    def error_receiving_file(self, taskname_and_error_details: str) -> Tuple[bytes, bytes]:
        """
        Peer reported an error in the send file process
        :param taskname_and_error_details: WazuhJSONEncoded object with the exception details
        :return: confirmation response
        """
        taskname, error_details = taskname_and_error_details.split(' ', 1)
        error_details_json = json.loads(error_details, object_hook=as_wazuh_object)
        if taskname != 'None':
            self.sync_tasks[taskname].filename = error_details_json
            self.sync_tasks[taskname].received_information.set()
        else:
            self.get_logger(self.logger_tag).error(f"Error in synchronization process: {error_details_json}")
        return b'ok', b'Error received'

    def get_node(self):
        return self.get_manager().get_node()


def asyncio_exception_handler(loop, context: Dict):
    """
    Exception handler used in the protocol. Asyncio's default raises an exception and closes the transport.
    The desired behaviour in this case is just to show the error in the logs.

    :param loop: Event loop
    :param context: A dictionary containing fields explained in
                    https://docs.python.org/3/library/asyncio-eventloop.html#asyncio.loop.call_exception_handler
    """
    logging.error(f"Unhandled exception: {context['exception']} {context['message']}\n"
                  ''.join(traceback.format_tb(context['exception'].__traceback__)))


class WazuhJSONEncoder(json.JSONEncoder):
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
        elif isinstance(obj, wresults.WazuhResult):
            result = {'__wazuh_result__': {'__class__': obj.__class__.__name__,
                                           '__object__': obj.to_dict()}
                      }
            return result
        return json.JSONEncoder.default(self, obj)


def as_wazuh_object(dct: Dict):
    try:
        if '__callable__' in dct:
            encoded_callable = dct['__callable__']
            funcname = encoded_callable['__name__']
            if '__wazuh__' in encoded_callable:
                # Encoded Wazuh instance method
                wazuh_dict = encoded_callable['__wazuh__']
                wazuh = Wazuh(ossec_path=wazuh_dict.get('path', '/var/ossec'))
                return getattr(wazuh, funcname)
            else:
                # Encoded function or static method
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
            return getattr(wresults, wazuh_result['__class__']).from_dict(wazuh_result['__object__'])
        return dct

    except (KeyError, AttributeError):
        raise exception.WazuhInternalError(1000,
                                           extra_message=f"Wazuh object cannot be decoded from JSON {dct}",
                                           cmd_error=True)
