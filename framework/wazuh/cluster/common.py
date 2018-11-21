import asyncio
import hashlib
import logging
import os
import random
import struct
import traceback
from typing import Tuple, Dict


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

    def __init__(self):
        self.payload = bytearray()  # array to store the message's data
        self.total = 0  # total of bytes to receive
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
        self.total, self.counter, cmd = struct.unpack(header_format, header[:header_size])
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


class Handler(asyncio.Protocol):
    """
    Defines common methods for echo clients and servers
    """

    def __init__(self):
        super().__init__()
        # The counter is used to identify each message. If an incoming request has a known ID,
        # it is processed as a response
        self.counter = random.SystemRandom().randint(0, 2 ** 32 - 1)
        # The box stores all sent messages IDs
        self.box = {}
        # defines command length
        self.cmd_len = 10
        # defines header length
        self.header_len = self.cmd_len + 8  # 4 bytes of counter and 4 bytes of message size
        # defines header format
        self.header_format = '!2I{}s'.format(self.cmd_len)
        # stores received data
        self.in_buffer = b''
        # stores last received message
        self.in_msg = InBuffer()
        # stores incoming file information from file commands
        self.in_file = {'filename': '', 'fd': None, 'checksum': None}
        # stores incoming string information from string commands
        self.in_str = InBuffer()
        # maximum message length to send in a single request
        self.request_chunk = 524288
        # stores message to be sent
        self.out_msg = bytearray(self.header_len + self.request_chunk)

    def push(self, message: bytes):
        """
        Sends a message to peer

        :param message: message to send
        """
        self.transport.write(message)

    def next_counter(self) -> int:
        """
        Increases the message ID counter
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
            return b"Length of command '" + command + b"' exceeds limit."

        # adds - to command until it reaches cmd length
        command = command + b' ' + b'-' * (self.cmd_len - cmd_len - 1)
        self.out_msg[:self.header_len] = struct.pack(self.header_format, len(data), counter, command)
        self.out_msg[self.header_len:self.header_len + len(data)] = data

        return self.out_msg[:self.header_len + len(data)]

    def msg_parse(self) -> bool:
        """
        Parses an incoming message

        :return: command, counter and payload
        """
        if self.in_buffer:
            # a new message has been received
            if self.in_msg.received == 0:
                self.in_buffer = self.in_msg.get_info_from_header(header=self.in_buffer,
                                                                  header_format=self.header_format,
                                                                  header_size=self.header_len)
                self.in_buffer = self.in_msg.receive_data(data=self.in_buffer)
            else:
                self.in_buffer = self.in_msg.receive_data(data=self.in_buffer)
            return True
        else:
            return False

    def get_messages(self) -> Tuple[bytes, int, bytes]:
        parsed = self.msg_parse()

        while parsed:
            # logging.debug("Received message: {} / {}".format(self.in_msg['received'], self.in_msg['total_size']))
            if self.in_msg.received == self.in_msg.total:
                # the message was correctly received
                yield self.in_msg.cmd, self.in_msg.counter, bytes(self.in_msg.payload)
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
            return b"Error: Max msg length exceeded."

        response = Response()
        msg_counter = self.next_counter()
        self.box[msg_counter] = response
        self.push(self.msg_build(command, msg_counter, data))
        response_data = await response.read()
        return response_data

    async def send_file(self, filename: str) -> bytes:
        """
        Sends a file to peer.

        :param filename: File path to send
        :return: response message.
        """
        try:
            if not os.path.exists(filename):
                return "File {} not found.".format(filename).encode()

            response = await self.send_request(command=b'new_file', data=filename.encode())
            if response.startswith(b"Error"):
                return response

            file_hash = hashlib.sha256()
            with open(filename, 'rb') as f:
                for chunk in iter(lambda: f.read(self.request_chunk), b''):
                    response = await self.send_request(command=b'file_upd', data=chunk)
                    if response.startswith(b"Error"):
                        return response
                    file_hash.update(chunk)

            response = await self.send_request(command=b'file_end', data=file_hash.digest())
            if response.startswith(b"Error"):
                return response

            return b'File sent'
        except Exception as e:
            return str(e).encode()

    async def send_string(self, my_str: bytes) -> bytes:
        """
        Sends a large string to peer.

        :param my_str: String to send.
        :param chunk: number of elements each slide will have
        :return: whether sending was successful or not.
        """
        try:
            total = len(my_str)
            response = await self.send_request(command=b'new_str', data=str(total).encode())
            if response.startswith(b"Error"):
                return response

            for c in range(0, total, self.request_chunk):
                response = await self.send_request(command=b'str_upd', data=my_str[c:c + self.request_chunk])
                if response.startswith(b"Error"):
                    return response

            return b"String correctly sent"
        except Exception as e:
            return str(e).encode()

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
        except Exception as e:
            logging.error("Error processing request '{}': {}".format(command, e))
            command, payload = b'err', str(e).encode()

        self.push(self.msg_build(command, counter, payload))

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
        self.in_file['fd'] = open(data, 'wb')
        self.in_file['filename'] = data
        self.in_file['checksum'] = hashlib.sha256()
        return b"ok ", b"Ready to receive new file"

    def update_file(self, data: bytes) -> Tuple[bytes, bytes]:
        """
        Defines behaviour of command "file_upd" which consists in updating file contents.

        :param data: file content
        :return: Message
        """
        self.in_file['fd'].write(data)
        self.in_file['checksum'].update(data)
        return b"ok", b"File updated"

    def end_file(self, data: bytes) -> Tuple[bytes, bytes]:
        """
        Defines behaviour of command "end_file" which consists in closing file descriptor and check its md5.

        :param data: file sha256
        :return: Message
        """
        self.in_file['fd'].close()
        if self.in_file['checksum'].digest() != data:
            self.in_file = {'filename': '', 'fd': None, 'checksum': None}
            return b"ok", b"File received correctly"
        else:
            self.in_file = {'filename': '', 'fd': None, 'checksum': None}
            return b"err", b"File wasn't correctly received. Checksums aren't equal."

    def receive_str(self, data: bytes) -> Tuple[bytes, bytes]:
        """
        Defines behaviour of command "recv_str". This behaviour is to append to resize a bytearray with the string size.

        :param data: Request data: string size
        :return: Message
        """
        self.in_str.total = int(data)
        self.in_str.payload = bytearray(self.in_str.total)
        return b"ok", b"Ready to receive string"

    def str_upd(self, data: bytes) -> Tuple[bytes, bytes]:
        """
        Defines behaviour of command "str_upd". This behaviour is to update string contents.

        :param data: String contents
        :return: Message
        """
        self.in_str.receive_data(data)
        logging.debug("Length: {}/{}".format(self.in_str.received, self.in_str.total))
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
        return b"Error processing request: " + data


def asyncio_exception_handler(loop, context: Dict):
    """
    Exception handler used in the protocol. Asyncio's default raises an exception and closes the transport.
    The desired behaviour in this case is just to show the error in the logs.

    :param loop: Event loop
    :param context: A dictionary containing fields explained in
                    https://docs.python.org/3/library/asyncio-eventloop.html#asyncio.loop.call_exception_handler
    """
    logging.error("Unhandled exception: " + str(context['exception']))
    logging.debug(traceback.format_exc())
