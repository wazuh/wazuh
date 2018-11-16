import asyncio
import logging
import random
import struct
from wazuh import utils

class Response:
    """
    Defines and stores a response from a request
    """
    def __init__(self):
        # Event object which will be set when the response is received
        self.received_response = asyncio.Event()
        # Response content
        self.content = None

    async def read(self):
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
        self.total = 0              # total of bytes to receive
        self.received = 0           # number of received bytes
        self.cmd = ''               # request's command in header
        self.counter = 0            # request's counter in the box

    def get_info_from_header(self, header, header_format, header_size):
        """
        Gets information contained in the request's header

        :param header: raw header to process
        :param header_format: struct format of the header
        :param header_size: Size in bytes of the header
        :return: updated buffer
        """
        self.total, self.counter, cmd = struct.unpack(header_format, header[:header_size])
        self.cmd = cmd.decode().split(' ')[0]
        self.payload = bytearray(self.total)
        return header[header_size:]

    def receive_data(self, data):
        """
        Adds received data to payload bytearray

        :param data: Received data
        :return: updated data buffer
        """
        len_data = len(data[:self.total - self.received])
        self.payload[self.received:len_data+self.received] = data[:self.total - self.received]
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
        self.header_len = self.cmd_len + 8 # 4 bytes of counter and 4 bytes of message size
        # defines header format
        self.header_format = '!2I{}s'.format(self.cmd_len)
        # stores received data
        self.in_buffer = b''
        # stores last received message
        self.in_msg = InBuffer()
        # stores incoming file information from file commands
        self.in_file = {'filename': '', 'fd': None}
        # stores incoming string information from string commands
        self.in_str = ''


    def push(self, message):
        """
        Sends a message to peer

        :param message: message to send
        """
        self.transport.write(message)


    def next_counter(self):
        """
        Increases the message ID counter
        """
        self.counter = (self.counter + 1) % (2 ** 32)
        return self.counter


    def msg_build(self, command, counter, data):
        """
        Builds a message with header + payload

        :param command: command to send
        :param counter: message id
        :param data: data to send
        :return: built message
        """
        cmd_len = len(command)
        if cmd_len > self.cmd_len:
            raise Exception("Length of command '{}' exceeds limit ({}/{})".format(command, cmd_len, self.cmd_len))

        # adds - to command until it reaches cmd length
        command = '{} {}'.format(command, '-'*(self.cmd_len - cmd_len - 1))

        return struct.pack(self.header_format, len(data), counter, command.encode()) + data.encode()


    def msg_parse(self):
        """
        Parses an incoming message

        :return: command, counter and payload
        """
        if self.in_buffer:
            # a new message has been received
            if self.in_msg.received == 0:
                self.in_buffer = self.in_msg.get_info_from_header(header=self.in_buffer, header_format=self.header_format,
                                                 header_size=self.header_len)
                self.in_buffer = self.in_msg.receive_data(data=self.in_buffer)
            else:
                self.in_buffer = self.in_msg.receive_data(data=self.in_buffer)
            return True
        else:
            return False

    def get_messages(self):
        parsed = self.msg_parse()

        while parsed:
            # logging.debug("Received message: {} / {}".format(self.in_msg['received'], self.in_msg['total_size']))
            if self.in_msg.received == self.in_msg.total:
                # the message was correctly received
                yield self.in_msg.cmd, self.in_msg.counter, self.in_msg.payload.decode()
                self.in_msg = InBuffer()
            else:
                break
            parsed = self.msg_parse()


    async def send_request(self, command, data):
        """
        Sends a request to peer

        :param command: command to send
        :param data: data to send
        :return: response from peer.
        """
        response = Response()
        msg_counter = self.next_counter()
        self.box[msg_counter] = response
        self.push(self.msg_build(command, msg_counter, data))
        response_data = await response.read()
        return response_data


    async def send_file(self, filename):
        """
        Sends a file to peer.

        :param filename: File path to send
        :return: whether sending was successful or not
        """
        response = await self.send_request(command='new_file', data=filename)
        logging.debug("Response new_file: {}".format(response))
        with open(filename, 'r') as f:
            for chunk in iter(lambda: f.read(1), ''):
                response = await self.send_request(command='file_upd', data=chunk)
                logging.debug("Response file_upd: {}".format(response))
        response = await self.send_request(command='file_end', data=utils.get_hash(filename, 'sha256'))
        logging.debug("Respnse file_end: {}".format(response))
        return 'ok ', 'File sent'


    def data_received(self, message):
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


    def dispatch(self, command, counter, payload):
        """
        Processes a received message and sends a response

        :param command: command received
        :param counter: message id
        :param payload: data received
        """
        try:
            command, payload = self.process_request(command, payload)
        except Exception as e:
            logging.error("Error processing request: {}".format(e))
            command, payload = 'err ', str(e)

        self.push(self.msg_build(command, counter, payload))


    def process_request(self, command, data):
        """
        Defines commands for both master and clients.

        :param command: Received command from other peer.
        :param data: Received data from other peer.
        :return: message to send.
        """
        if command == 'echo':
            return self.echo(data)
        elif command == 'new_file':
            return self.receive_file(data)
        elif command == 'file_upd':
            return self.update_file(data)
        elif command == "file_end":
            return self.end_file(data)
        else:
            return self.process_unknown_cmd(command)


    def process_response(self, command, payload):
        """
        Defines response commands for both master and client

        :param command: response command received
        :param payload: data received
        :return:
        """
        if command == 'ok':
            return payload
        elif command == 'err':
            return self.process_error_from_peer(payload)
        else:
            return "Unkown response command received: '{}'".format(command)


    def echo(self, data):
        """
        Defines command "echo"

        :param data: message to echo
        :return: message to send
        """
        return 'ok ', data


    def receive_file(self, data):
        """
        Defines behaviour of command "new_file". This behaviour is to create a file descriptor to store the incoming
        file.

        :param data: File name
        :return: Message
        """
        self.in_file['fd'] = open(data, 'w+')
        self.in_file['filename'] = data
        return "ok ", "Ready to receive new file"


    def update_file(self, data):
        """
        Defines behaviour of command "file_upd" which consists in updating file contents.

        :param data: file content
        :return: Message
        """
        self.in_file['fd'].write(data)
        return "ok ", "File updated"


    def end_file(self, data):
        """
        Defines behaviour of command "end_file" which consists in closing file descriptor and check its md5.

        :param data: file sha256
        :return: Message
        """
        self.in_file['fd'].close()
        if utils.get_hash(self.in_file['filename'], hash_algorithm='sha256') == data:
            self.in_file = {'filename': '', 'fd': None}
            return "ok ", "File received correctly"
        else:
            self.in_file = {'filename': '', 'fd': None}
            return "err ", "File wasn't correctly received"


    def process_unknown_cmd(self, command):
        """
        Defines message when an unknown command is received

        :param command: command received from peer
        :return: message to send
        """
        return 'err ', "unknown command '{}'".format(command)


    def process_error_from_peer(self, data):
        """
        Handles errors in requests

        :param data: error message from peer
        :return: Nothing
        """
        logging.error("Peer reported an error: {}".format(data))
        raise Exception(data)
