#!/usr/bin/env python

import asyncore
import threading
import random
import struct
import socket
import hashlib
import os
import time
import logging
import json

max_msg_size = 1000000
cmd_size = 12


def msgbuild(counter, command, payload=None):
    try:
        if payload:
            payload = payload.encode()
        else:
            payload = b''.encode()
    except UnicodeDecodeError:
        pass

    cmd_len = len(command)
    if cmd_len > cmd_size:
        raise Exception("Command of length {} exceeds maximum allowed {}".format(cmd_len, cmd_size))

    padding_command = command + ' ' + '-' * (cmd_size - cmd_len - 1)

    payload_len = len(payload)
    if payload_len > max_msg_size:
        raise Exception("Data of length {} exceeds maximum allowed {}".format(payload_len, max_msg_size))

    header = struct.pack('!2I{}s'.format(cmd_size), counter, len(payload), padding_command)
    return header + payload


def msgparse(buf):
    header_size = 8 + cmd_size
    if len(buf) >= header_size:
        counter, size, command = struct.unpack('!2I{}s'.format(cmd_size), buf[:header_size])
        command = command.split(' ',1)[0]
        if len(buf) >= size + header_size:
            payload = buf[header_size:size + header_size]
            return size + header_size, counter, command, payload

    return None


class Response:

    def __init__(self):
        self.cond = threading.Condition()
        self.data = None


    def read(self):
        with self.cond:
            while not self.data:
                self.cond.wait()

        return self.data


    def write(self, data):
        with self.cond:
            self.data = data
            self.cond.notify()


class Handler(asyncore.dispatcher_with_send):

    def __init__(self, sock=None, map=None):
        asyncore.dispatcher_with_send.__init__(self, sock=sock, map=map)
        self.box = {}
        self.counter = random.SystemRandom().randint(0, 2 ** 32 - 1)
        self.inbuffer = b''
        self.lock = threading.Lock()

    def compute_md5(self, file, blocksize=2**20):
        hash_algorithm = hashlib.md5()
        with open(file, 'rb') as f:
            for chunk in iter(lambda: f.read(blocksize), ''):
                hash_algorithm.update(chunk)

        return hash_algorithm.hexdigest()


    def file_send(self, file):
        """
        To send a file without collapsing the network, two special commands
        are defined:
            - file_send_open <node_name> <file_name>
            - file_send_update <node_name> <file_name> <file_content>
            - file_send_close <node_name> <file_name> <md5>
        Every 1MB sent, this function sleeps for 1s. This way, other network
        packages can be sent while a file is being sent

        :param file: filename (path)
        """

        response = self.execute("file_open", "{} {}".format(self.name, file))
        print("RESPONSE: {0}".format(response))
        # TO-DO remove ossec_path from sent filepath
        base_msg = "{} {} ".format(self.name,file).encode()
        chunk_size = max_msg_size - len(base_msg)

        with open(file, 'rb') as f:
            # read chunks of chunk_size
            counter = 0
            for chunk in iter(lambda: f.read(chunk_size), ''):
                counter = counter + 1
                response = self.execute("file_update", base_msg + chunk)
                print("RESPONSE: {0}".format(response))
                # for every chunk sent, sleep 0.1 s to prevent network from collapsing
                #time.sleep(0.1)

        response = self.execute("file_close", "{} {} {}".format(self.name, file, self.compute_md5(file)))
        return response

    def file_open(self, data):
        """
        Start the protocol of receiving a file. Create a new file

        :parm data: data received from socket

        This data must be:
            - node name
            - filename

        and must be separated by a white space
        """
        node_name, file_name = data.split(' ')
        # Create the file
        tmp_file = "{0}.{1}.tmp".format(file_name, node_name)
        open(tmp_file, 'w')
        return "ok", "File {} created successfully".format(tmp_file)


    def file_update(self, data):
        """
        Continue the protocol of receiving a file. Append data

        :parm data: data received from socket

        This data must be:
            - node name
            - filename
            - chunk

        and must be separated by a white space
        """
        node_name, file_name, chunk = data.split(b' ')
        node_name = node_name.decode()
        file_name = file_name.decode()
        # Open the file
        tmp_file = "{0}.{1}.tmp".format(file_name, node_name)
        with open(tmp_file, 'a') as f:
            f.write(chunk)
        return "ok", "Chunk wrote to {} successfully".format(file_name)


    def file_close(self, data):
        """
        Ends the protocol of receiving a file

        :parm data: data received from socket

        This data must be:
            - node name
            - filename
            - MD5 sum

        and must be separated by a white space
        """
        node_name, file_name, md5_sum = data.split(' ')

        # compare local file's sum with received sum
        tmp_file = "{0}.{1}.tmp".format(file_name, node_name)
        local_md5_sum = self.compute_md5(tmp_file)
        if local_md5_sum != md5_sum:
            error_msg = "Checksum of received file {} is not correct. Expected {} / Found {}".\
                            format(tmp_file, md5_sum, local_md5_sum)
            return error_msg
            #os.remove(file_name)
            raise Exception(error_msg)

        return "ok", "File {} received successfully".format(tmp_file)


    def execute(self, command, payload):
        response = Response()
        counter = self.nextcounter()

        with self.lock:
            self.box[counter] = response

        self.push(counter, command, payload)
        response = response.read()

        with self.lock:
            del self.box[counter]

        return response


    def handle_read(self):
        data = self.recv(4096)

        if data:
            self.inbuffer += data

            for counter, command, payload in self.get_messages():

                with self.lock:
                    if counter in self.box:
                        response = self.box[counter]
                    else:
                        response = None

                if response:
                    response.write(command + ' ' + payload)
                else:
                    res_data = self.dispatch(command, payload)

                    if res_data:
                        command = res_data[0]
                        data = res_data[1] if len(res_data) > 1 else None
                        self.push(counter, command, data)


    def handle_close(self):
        self.close()

        for response in self.box.values():
            response.write(None)


    def handle_write(self):
        with self.lock:
            self.initiate_send()


    def get_messages(self):
        parsed = msgparse(self.inbuffer)

        while parsed:
            offset, counter, command, payload = parsed
            self.inbuffer = self.inbuffer[offset:]
            yield counter, command, payload
            parsed = msgparse(self.inbuffer)


    def push(self, counter, command, payload):
        message = msgbuild(counter, command, payload)

        with self.lock:
            self.send(message)


    def nextcounter(self):
        with self.lock:
            counter = self.counter
            self.counter = (self.counter + 1) % (2 ** 32)

        return counter


    @staticmethod
    def split_data(data):
        try:
            pair = data.split(' ', 1)
            cmd = pair[0]
            payload = pair[1] if len(pair) > 1 else None
        except:
            cmd = "err"
            payload = "Error splitting data"

        return cmd, payload

    def dispatch(self, command, payload):
        try:
            return self.process_request(command, payload)
        except Exception as e:
            error_msg = "Error processing command: {}".format(str(e))
            return 'err ', error_msg


    def process_request(self, command, data):
        if command == 'echo':
            return 'ok ', data.decode()
        elif command == "file_open":
            return self.file_open(data.decode())
        elif command == "file_update":
            return self.file_update(data)
        elif command == "file_close":
            return self.file_close(data.decode())
        else:
            logging.error("[Transport] Unknown command received: '{0}'.".format(command))
            message = "'{0}': Unknown command '{1}'".format(self.name, command)
            return "err", message


    @staticmethod
    def process_response(response):
        answer, payload = Handler.split_data(response)

        final_response = None

        if answer == 'ok':
            final_response = 'answered: {}.'.format(payload)
        elif answer == 'ack':
            final_response = 'Confirmation received: {}'.format(payload)
        elif answer == 'json':
            final_response = json.loads(payload)
        elif answer == 'err':
            final_response = None
            logging.error("[Transport] Error received: {0}.".format(payload.decode()))
        else:
            final_response = None
            print("ERROR: Unknown answer: '{}'. Payload: '{}'.".format(answer, payload))

        return final_response


class ServerHandler(Handler):

    def __init__(self, sock, server, map):
        Handler.__init__(self, sock, map)
        self.map = map
        self.name = None
        self.server = server


    def handle_close(self):
        if self.name:
            self.server.remove_client(self.name)
            logging.info("[Transport-S] Node '{0}' disconnected.".format(self.name))
        else:
            print("Connection closed.")

        Handler.handle_close(self)


    def process_request(self, command, data):
        if command == 'hello':
            return self.hello(data.decode())
        else:
            return Handler.process_request(self, command, data)


    def hello(self, data):
        self.name = data
        self.server.add_client(data, self)
        logging.info("[Transport-S] Node '{0}' connected.".format(data))
        return None


class Server(asyncore.dispatcher):

    def __init__(self, host, port, handle_type, map = {}):
        asyncore.dispatcher.__init__(self, map=map)
        self.map = map
        self.clients = {}
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((host, port))
        self.listen(5)
        self.handle_type = handle_type


    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, addr = pair
            logging.debug("[Transport-S] Incoming connection from {0}.".format(repr(addr)))
            handler = self.handle_type(sock, self, self.map)



    def add_client(self, name, handler):
        self.clients[name] = handler


    def remove_client(self, name):
        del self.clients[name]


    def get_connected_clients(self):
        return self.clients


    def send_request(self, client_name, command, data=None):
        response = None

        if client_name in self.clients:
            response = self.clients[client_name].execute(command, payload)
        else:
            print("Error: Trying to send and the client is not connected.")

        return response

    def send_request_broadcast(self, command, data=None):
        message = "{0} {1}".format(command, data)

        for c_name in self.clients:
            response = self.clients[c_name].execute(command, data)
            yield c_name, response


class ClientHandler(Handler):

    def __init__(self, host, port, name, map = {}):
        Handler.__init__(self, map=map)
        self.map = map
        self.host = host
        self.port = port
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        ok = self.connect( (host, port) )
        self.name = name
        self.my_connected = False


    def handle_connect(self):
        logging.info("[Client] Connecting to {0}:{1}.".format(self.host, self.port))
        counter = self.nextcounter()
        payload = msgbuild(counter, 'hello', self.name)
        self.send(payload)
        self.my_connected = True
        logging.info("[Client] Connected.")


    def handle_close(self):
        Handler.handle_close(self)
        self.my_connected = False
        print("Client disconnected")


    def send_request(self, command, data=None):
        response = None

        if self.my_connected:
            response = self.execute(command, data)
        else:
            print("Error: Trying to send and the client is not connected.")

        return response

    def is_connected(self):
        return self.my_connected



class InternalSocketHandler(Handler):

    def __init__(self, sock, manager, map):
        Handler.__init__(self, sock=sock, map=map)
        self.manager = manager

    def process_request(self, command, data):
        logging.debug("[Transport-I] Forwarding request to cluster '{0}' - '{1}'".format(command, data))

        response = None

        # master manager
        # ToDo ?

        # client manager
        response = self.manager.send_request(command = command, data=data).split(' ', 1)
        return response


class InternalSocket(asyncore.dispatcher):

    def __init__(self, socket_name, manager, map = {}):
        asyncore.dispatcher.__init__(self, map=map)
        self.map = map
        self.socket_name = socket_name
        self.manager = manager
        self.socket_address = "{}/{}.sock".format("/var/ossec/queue", self.socket_name)
        self.__create_socket()

    def __create_socket(self):
        print("[Transport-I]  Creating UDS socket...")

        # Make sure the socket does not already exist
        try:
            os.unlink(self.socket_address)
        except OSError:
            if os.path.exists(self.socket_address):
                print('[Transport-I] err {} already exits'.format(self.socket_address))
                raise

        self.create_socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.set_reuse_addr()
        try:
            self.bind(self.socket_address)
            print("[Transport-I] Starting up on {}. Listening...".format(self.socket_address))
            self.listen(5)
        except Exception as e:
            error_msg = "Cannot create UDS socket {}".format(e)
            print('err ' + error_msg)

    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, addr = pair
            print("[Transport-I] New connection in internal socket")
            handler = InternalSocketHandler(sock=sock, manager=self.manager, map=self.map)

def send_to_internal_socket(socket_name, message):
    # Create a UDS socket
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    socket_address = "{}/{}.sock".format("/var/ossec/queue", socket_name)
    print("[Transport-I] Starting up on {}".format(socket_address))
    response = ""

    # Connect to UDS socket
    try:
        sock.connect(socket_address)
    except Exception as e:
        print('{}'.format(e))
        return response

    # Send message
    print("[Transport-I] Sending request to SI: '{0}'.".format(message))
    message = message.split(" ")
    message_built = msgbuild(random.SystemRandom().randint(0, 2 ** 32 - 1), message[0], message[1])
    sock.sendall(message_built)
    print("[Transport-I] Sent")

    # Receive response
    buf = ""
    buf_size = 4096
    try:
        while not response:
            buf += sock.recv(buf_size)
            offset, counter, command, response = msgparse(buf)

        print("[Transport-I] Received: answer: '{0}'. Data: '{1}'.".format(command, response))

    except Exception as e:
        print("[Transport-I] err {}".format(e))
    finally:
        print("[Transport-I] Closing socket...")
        sock.close()

    return response
