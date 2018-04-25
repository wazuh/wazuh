#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh import common
from wazuh.cluster.cluster import check_cluster_status, get_cluster_items, get_cluster_items_communication_intervals
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

try:
    from Queue import Queue, Empty
except ImportError:
    from queue import Queue, Empty


if check_cluster_status():
    try:
        from cryptography.fernet import Fernet, InvalidToken, InvalidSignature
    except ImportError as e:
        raise ImportError("Could not import cryptography module. Install it using:\n\
                        - pip install cryptography\n\
                        - yum install python-cryptography python-setuptools\n\
                        - apt install python-cryptography")


max_msg_size = 1000000
cmd_size = 12
logger = logging.getLogger(__name__)

def msgbuild(counter, command, my_fernet, payload=None):

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

    if my_fernet:
        payload = my_fernet.encrypt(payload) if payload_len > 0 else payload

    header = struct.pack('!2I{}s'.format(cmd_size), counter, len(payload), padding_command)
    return header + payload


def msgparse(buf, my_fernet):
    header_size = 8 + cmd_size
    if len(buf) >= header_size:
        counter, size, command = struct.unpack('!2I{}s'.format(cmd_size), buf[:header_size])
        command = command.split(' ',1)[0]
        if len(buf) >= size + header_size:
            payload = buf[header_size:size + header_size]
            if payload and my_fernet:
                try:
                    payload = my_fernet.decrypt(payload)
                except InvalidToken as e:
                    raise Exception("Could not decrypt message. Check the key is correct.")
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


class ClusterThread(threading.Thread):
    def __init__(self, stopper):
        threading.Thread.__init__(self)
        self.daemon = True
        self.running = True

        # An event that tells the thread to stop
        self.stopper = stopper


    def stop(self):
        self.running = False


    def run(self):
        # while not self.stopper.is_set() and self.running:
        raise NotImplementedError


    def sleep(self, delay):
        exit = False
        count = 0
        while not exit and not self.stopper.is_set() and self.running:
            time.sleep(1)
            if count == delay:
                exit = True
            else:
                count += 1

        return count


class Handler(asyncore.dispatcher_with_send):

    def __init__(self, key, sock=None, map=None):
        asyncore.dispatcher_with_send.__init__(self, sock=sock, map=map)
        self.box = {}
        self.counter = random.SystemRandom().randint(0, 2 ** 32 - 1)
        self.inbuffer = b''
        self.lock = threading.Lock()  # Box lock
        self.workers_lock = threading.Lock()
        self.workers = {}
        self.stopper = threading.Event()
        self.my_fernet = Fernet(key.encode('base64','strict')) if key else None


    def exit(self):
        logger.debug("[Transport-Handler] Cleaning handler threads. Start.")
        self.stopper.set()

        with self.workers_lock:
            worker_ids = self.workers.keys()

        for worker_id in worker_ids:
            logger.debug2("[Transport-Handler] Cleaning handler thread: '{0}'.".format(worker_id))

            with self.workers_lock:
                my_worker = self.workers[worker_id]

            try:
                my_worker.join(timeout=2)
            except Exception as e:
                logger.error("[Transport-Handler] Cleaning '{0}' thread. Error: '{1}'.".format(worker_id, str(e)))

            if my_worker.isAlive():
                logger.warning("[Transport-Handler] Cleaning '{0}' thread. Timeout.".format(worker_id))
            else:
                logger.debug2("[Transport-Handler] Cleaning '{0}' thread. Terminated.".format(worker_id))

        logger.debug("[Transport-Handler] Cleaning handler threads. End.")


    def set_worker(self, command, worker, filename):
        thread_id = '{}-{}-{}'.format(command, worker.ident, os.path.basename(filename))
        with self.workers_lock:
            self.workers[thread_id] = worker
        worker.id = thread_id
        return thread_id


    def del_worker(self, worker_id):
        with self.workers_lock:
            if worker_id in self.workers:
                del self.workers[worker_id]


    def get_worker(self, data):
        # the worker id will be the first element spliting the data by spaces
        id = data.split(' ', 1)[0]
        with self.workers_lock:
            if id in self.workers:
                return self.workers[id], 'ack', 'Command received for {}'.format(id)
            else:
                return None, 'err', 'Worker {} not found. Please, send me the reason first'.format(id)


    def compute_md5(self, file, blocksize=2**20):
        hash_algorithm = hashlib.md5()
        with open(file, 'rb') as f:
            for chunk in iter(lambda: f.read(blocksize), ''):
                hash_algorithm.update(chunk)

        return hash_algorithm.hexdigest()


    def send_file(self, reason, file, remove=False, interval_file_transfer_send=0.1):
        """
        To send a file without collapsing the network, two special commands
        are defined:
            - send_file_open <node_name> <file_name>
            - send_file_update <node_name> <file_name> <file_content>
            - send_file_close <node_name> <file_name> <md5>
        Every 1MB sent, this function sleeps for 1s. This way, other network
        packages can be sent while a file is being sent

        Before sending the file, a request with a "reason" is sent. This way,
        the server will get prepared to receive the file.

        :param file: filename (path)
        :param reason: command to send before starting to send the file
        :param remove: whether to remove the file after sending it or not
        """
        # response will be of form 'ack id'
        _, id = self.execute(reason, os.path.basename(file)).split(' ',1)

        try:
            res, data = self.execute("file_open", "{}".format(id)).split(' ', 1)
            if res == "err":
                raise Exception(data)

            # TO-DO remove ossec_path from sent filepath
            base_msg = "{} ".format(id).encode()
            chunk_size = max_msg_size - len(base_msg)

            with open(file, 'rb') as f:
                for chunk in iter(lambda: f.read(chunk_size), ''):
                    res, data = self.execute("file_update", base_msg + chunk).split(' ', 1)
                    if res == "err":
                        raise Exception(data)
                    time.sleep(interval_file_transfer_send)

            res, data = self.execute("file_close", "{} {}".format(id, self.compute_md5(file))).split(' ', 1)
            if res == "err":
                raise Exception(data)

        except Exception as e:
            logger.error("[Transport-Handler] Error sending file: '{}'.".format(str(e)))

        if remove:
            os.remove(file)

        return res + ' ' + data


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


    def handle_error(self):
        nil, t, v, tbinfo = asyncore.compact_traceback()

        try:
            self_repr = repr(self)
        except:
            self_repr = '<__repr__(self) failed for object at %0x>' % id(self)

        self.handle_close()
        logger.error("[Transport-Handler] Error: '{}'.".format(v))
        logger.debug("[Transport-Handler] Error: '{}' - '{}'.".format(t, tbinfo))


    def handle_close(self):
        self.close()

        for response in self.box.values():
            response.write(None)


    def handle_write(self):
        with self.lock:
            self.initiate_send()


    def get_messages(self):
        parsed = msgparse(self.inbuffer, self.my_fernet)

        while parsed:
            offset, counter, command, payload = parsed
            self.inbuffer = self.inbuffer[offset:]
            yield counter, command, payload
            parsed = msgparse(self.inbuffer, self.my_fernet)


    def push(self, counter, command, payload):
        try:
            message = msgbuild(counter, command, self.my_fernet, payload)
        except Exception as e:
            logger.error("[Transport-Handler] Error sending a request/response (command: '{}') due to '{}'.".format(command, str(e)))
            message = msgbuild(counter, "err", self.my_fernet, str(e))

        with self.lock:
            self.send(message)


    def nextcounter(self):
        with self.lock:
            counter = self.counter
            self.counter = (self.counter + 1) % (2 ** 32)

        return counter


    def split_data(self, data):
        try:
            pair = data.split(' ', 1)
            cmd = pair[0]
            payload = pair[1] if len(pair) > 1 else None
        except Exception as e:
            logger.error("[Transport-Handler] Error splitting data: '{}'.".format(str(e)))
            cmd = "err"
            payload = "Error splitting data"

        return cmd, payload


    def dispatch(self, command, payload):
        try:
            return self.process_request(command, payload)
        except Exception as e:
            error_msg = "Error processing command '{0}': '{1}'.".format(command, str(e))

            logger.debug("[Transport-Handler] {0}".format(error_msg))
            return 'err ', error_msg


    def process_request(self, command, data):
        if command == 'echo':
            return 'ok ', data.decode()
        elif command == "file_open" or command == "file_update" or command == "file_close":
            # At this moment, the thread should exists
            worker, cmd, message = self.get_worker(data)
            if worker:
                worker.set_command(command, data)
            return cmd, message
        else:
            message = "'{0}' - Unknown command received '{1}'.".format(self.name, command)
            logger.error("[Transport-Handler] {}".format(message))
            return "err", message


    def process_response(self, response):
        answer, payload = self.split_data(response)

        final_response = None

        if answer == 'ok':
            final_response = 'answered: {}.'.format(payload)
        elif answer == 'ack':
            final_response = 'Confirmation received: {}'.format(payload)
        elif answer == 'json':
            final_response = json.loads(payload)
        elif answer == 'err':
            final_response = None
            logger.debug("[Transport-Handler] Error received: '{0}'.".format(payload.decode()))
        else:
            final_response = None
            logger.error("[Transport-Handler] Error - Unknown answer: '{}'. Payload: '{}'.".format(answer, payload))

        return final_response


class ServerHandler(Handler):

    def __init__(self, sock, server, map, addr=None):
        Handler.__init__(self, server.config['key'], sock, map)
        self.map = map
        self.name = None
        self.server = server
        self.addr = addr


    def handle_close(self):
        if self.name:
            self.server.remove_client(self.name)
            logger.info("[Master] [{0}]: Disconnected.".format(self.name))
        else:
            logger.info("[Transport-ServerHandler] Connection with {} closed.".format(self.name))

        Handler.handle_close(self)


    def process_request(self, command, data):
        if command == 'hello':
            return self.hello(data.decode())
        else:
            return Handler.process_request(self, command, data)


    def hello(self, data):
        try:
            id = self.server.add_client(data, self.addr, self)
            self.name = id  # TO DO: change self.name to self.id
            logger.info("[Master] [{0}]: Connected.".format(id))
        except Exception as e:
            logger.error("[Transport-ServerHandler] Error accepting connection from {}: {}".format(self.addr, str(e)))
        return None


    def get_client(self):
        return self.name


class Server(asyncore.dispatcher):

    def __init__(self, host, port, handle_type, map = {}):
        asyncore.dispatcher.__init__(self, map=map)
        self._clients = {}
        self._clients_lock = threading.Lock()

        self.map = map
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((host, port))
        self.listen(5)
        self.handle_type = handle_type
        self.interval_file_transfer_send = get_cluster_items_communication_intervals()['file_transfer_send']


    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, addr = pair
            logger.debug("[Transport-Server] Incoming connection.")

            if self.find_client_by_ip(addr[0]):
                sock.close()
                logger.warning("[Transport-Server] Incoming connection from '{0}' rejected: Client is already connected.".format(repr(addr)))
                return

            # addr is a tuple of form (ip, port)
            handler = self.handle_type(sock, self, self.map, addr[0])


    def handle_error(self):
        nil, t, v, tbinfo = asyncore.compact_traceback()

        try:
            self_repr = repr(self)
        except:
            self_repr = '<__repr__(self) failed for object at %0x>' % id(self)

        self.handle_close()

        logger.error("[Transport-Server] Error: '{}'.".format(v))
        logger.debug("[Transport-Server] Error: '{}' - '{}'.".format(t, tbinfo))


    def find_client_by_ip(self, client_ip):

        with self._clients_lock:
            for client in self._clients:
                if self._clients[client]['info']['ip'] == client_ip:
                    return client

        return None


    def add_client(self, data, ip, handler):
        name, type = data.split(' ')
        id = name
        with self._clients_lock:
            self._clients[id] = {
                'handler': handler,
                'info': {
                    'name': name,
                    'ip': ip,
                    'type': type
                },
                'status': {
                    'sync_integrity_free': True,
                    'sync_agentinfo_free': True,
                    'last_sync_integrity': {
                        'date_start_master':'n/a',
                        'date_end_master':'n/a',
                        'total_files':{
                            'missing':0,
                            'shared':0,
                            'extra':0
                        }
                    },
                    'last_sync_agentinfo': {
                        'date_start_master':'n/a',
                        'date_end_master':'n/a',
                        'total_agentinfo':0
                    }
                }
            }
        return id


    def remove_client(self, id):
        with self._clients_lock:
            try:
                # Remove threads
                self._clients[id]['handler'].exit()

                del self._clients[id]
            except KeyError:
                logger.error("[Transport-Server] Client '{}'' is already disconnected.".format(id))


    def get_connected_clients(self):
        with self._clients_lock:
            return self._clients


    def get_client_info(self, client_name):
        with self._clients_lock:
            try:
                return self._clients[client_name]
            except KeyError:
                error_msg = "Client {} is disconnected.".format(client_name)
                logger.error("[Transport-Server] {}".format(error_msg))
                raise Exception(error_msg)


    def send_file(self, client_name, reason, file, remove = False):
        return self.get_client_info(client_name)['handler'].send_file(reason, file, remove, self.interval_file_transfer_send)


    def send_request(self, client_name, command, data=None):
        response = None

        if client_name in self.get_connected_clients():
            response = self.get_client_info(client_name)['handler'].execute(command, data)
        else:
            error_msg = "Trying to send and the client '{0}' is not connected.".format(client_name)
            logger.error("[Transport-Server] {0}.".format(error_msg))
            response = "err " + error_msg

        return response


    def send_request_broadcast(self, command, data=None):
        message = "{0} {1}".format(command, data)

        for c_name in self.get_connected_clients():
            response = self.get_client_info(c_name)['handler'].execute(command, data)
            yield c_name, response


class ClientHandler(Handler):

    def __init__(self, key, host, port, name, map = {}):
        Handler.__init__(self, key=key, map=map)
        self.map = map
        self.host = host
        self.port = port
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        ok = self.connect( (host, port) )
        self.name = name
        self.my_connected = False


    def handle_connect(self):
        logger.info("[Client] Connecting to {0}:{1}.".format(self.host, self.port))
        counter = self.nextcounter()
        payload = msgbuild(counter, 'hello', self.my_fernet, '{} {}'.format(self.name, 'client'))
        self.send(payload)
        self.my_connected = True
        logger.info("[Client] Connected.")


    def handle_close(self):
        Handler.handle_close(self)
        self.my_connected = False
        logger.info("[Client] Disconnected.")


    def send_request(self, command, data=None):
        response = None

        if self.my_connected:
            response = self.execute(command, data)
        else:
            error_msg = "Trying to send and there is no connection with the server"
            logger.error("[Transport-ClientHandler] {0}.".format(error_msg))
            response = "err " + error_msg

        return response


    def is_connected(self):
        return self.my_connected



class InternalSocketHandler(Handler):

    def __init__(self, sock, manager, map):
        Handler.__init__(self, key=None, sock=sock, map=map)
        self.manager = manager


    def process_request(self, command, data):
        raise NotImplementedError


class InternalSocket(asyncore.dispatcher):

    def __init__(self, socket_name, manager, handle_type, map = {}):
        asyncore.dispatcher.__init__(self, map=map)
        self.handle_type = handle_type
        self.map = map
        self.socket_name = socket_name
        self.manager = manager
        self.socket_address = "{}/{}.sock".format("/var/ossec/queue/cluster", self.socket_name)
        self.__create_socket()


    def __create_socket(self):
        logger.debug2("[Transport-InternalSocket] Creating.")

        # Make sure the socket does not already exist
        try:
            os.unlink(self.socket_address)
        except OSError:
            if os.path.exists(self.socket_address):
                logger.error("[Transport-InternalSocket] Error: '{}' already exits".format(self.socket_address))
                raise

        self.create_socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.set_reuse_addr()
        try:
            self.bind(self.socket_address)
            self.listen(5)
            logger.debug2("[Transport-InternalSocket] Listening.")
        except Exception as e:
            logger.error("[Transport-InternalSocket] Cannot create the socket: '{}'.".format(str(e)))

        logger.debug2("[Transport-InternalSocket] Created.")


    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, addr = pair
            logger.debug("[Transport-InternalSocket] Incoming connection from '{0}'.".format(repr(addr)))
            handler = self.handle_type(sock=sock, manager=self.manager, map=self.map)


    def handle_error(self):
        nil, t, v, tbinfo = asyncore.compact_traceback()

        try:
            self_repr = repr(self)
        except:
            self_repr = '<__repr__(self) failed for object at %0x>' % id(self)

        self.handle_close()

        logger.error("[Transport-InternalSocket] Error: '{}'.".format(v))
        logger.debug("[Transport-InternalSocket] Error: '{}' - '{}'.".format(t, tbinfo))


#
# Internal Socket thread
#
class InternalSocketThread(threading.Thread):
    def __init__(self, socket_name, tag="[InternalSocketThread]"):
        threading.Thread.__init__(self)
        self.daemon = True
        self.manager = None
        self.running = True
        self.internal_socket = None
        self.socket_name = socket_name
        self.thread_tag = tag
        self.interval_connection_retry = 5

    def setmanager(self, manager, handle_type):
        try:
            self.internal_socket = InternalSocket(socket_name=self.socket_name, manager=manager, handle_type=handle_type)
        except Exception as e:
            logger.error("{0} [Internal-S ]: Error initializing: '{1}'.".format(self.thread_tag, str(e)))
            self.internal_socket = None

    def run(self):
        while self.running:
            if self.internal_socket:
                logger.info("{0} [Internal-S ]: Ready.".format(self.thread_tag))

                asyncore.loop(timeout=1, use_poll=False, map=self.internal_socket.map, count=None)

                logger.info("{0} [Internal-S ]: Disconnected. Trying to connect again in {}s.".format(self.thread_tag, self.interval_connection_retry))

                time.sleep(self.interval_connection_retry)
            time.sleep(2)


def send_to_internal_socket(socket_name, message):
    # Create a UDS socket
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    socket_address = "{}/{}/{}.sock".format(common.ossec_path, "/queue/cluster", socket_name)
    logger.debug("[Transport-InternalSocketSend] Starting: {}.".format(socket_address))
    response = ""

    # Connect to UDS socket
    try:
        sock.connect(socket_address)
    except Exception as e:
        logger.error('{}'.format(e))
        return response

    # Send message
    logger.debug("[Transport-InternalSocketSend] Sending request: '{0}'.".format(message))

    message = message.split(" ", 1)
    cmd = message[0]
    data = message[1] if len(message) > 1 else None
    message_built = msgbuild(random.SystemRandom().randint(0, 2 ** 32 - 1), cmd, None, data)
    sock.sendall(message_built)

    logger.debug("[Transport-InternalSocketSend] Request sent.")

    # Receive response
    buf = ""
    buf_size = 4096
    try:
        while not response:
            buf += sock.recv(buf_size)
            parse = msgparse(buf, None)
            if parse:
                offset, counter, command, response = parse

        logger.debug("[Transport-InternalSocketSend] Answer received: '{0}'.".format(command))

    except Exception as e:
        logger.error("[Transport-InternalSocketSend] Error: {}.".format(str(e)))
    finally:
        logger.debug("[Transport-InternalSocketSend] Closing socket.")
        sock.close()
        logging.debug("[Transport-InternalSocketSend] Socket closed.")

    return response


class ProcessFiles(ClusterThread):

    def __init__(self, manager_handler, filename, client_name, stopper):
        """
        Abstract class which defines the necessary methods to receive a file
        """
        ClusterThread.__init__(self, stopper)

        self.manager_handler = manager_handler  # handler object
        self.filename = filename                # filename of the file to receive
        self.name = client_name                 # name of the sender
        self.command_queue = Queue()            # queue to store received file commands
        self.received_all_information = False   # flag to indicate whether all file has been received
        self.received_error = False             # flag to indicate there has been an error in receiving process
        self.f = None                           # file object that is being received
        self.id = None                          # id of the thread doing the receiving process
        self.thread_tag = "[FileThread]"        # logger tag of the thread
        self.n_get_timeouts = 0                 # number of times Empty exception is raised

        #Intervals
        self.interval_file_transfer_receive = get_cluster_items_communication_intervals()['file_transfer_receive']
        self.max_time_receiving_file = get_cluster_items_communication_intervals()['max_time_receiving_file']


    # Overridden methods
    def stop(self):
        """
        Stops the thread
        """
        if self.id:
            self.manager_handler.del_worker(self.id)
        ClusterThread.stop(self)


    def run(self):
        """
        Receives the file and processes it.
        """
        logger.info("{0}: Start.".format(self.thread_tag))

        while not self.stopper.is_set() and self.running:
            self.lock_status(True)

            if not self.check_connection():
                continue

            if self.received_all_information:
                logger.info("{0}: Reception completed.".format(self.thread_tag))
                try:
                    result = self.process_file()
                    if result:
                        logger.info("{0}: Result: Successfully.".format(self.thread_tag))
                    else:
                        logger.error("{0}: Result: Error.".format(self.thread_tag))

                    self.unlock_and_stop(reason="task performed", send_err_request=False)
                except Exception as e:
                    logger.error("{0}: Result: Unknown error: {1}.".format(self.thread_tag, str(e)))
                    self.unlock_and_stop(reason="error")

            elif self.received_error:
                logger.error("{0}: An error took place during file reception.".format(self.thread_tag))
                self.unlock_and_stop(reason="error")

            else:  # receiving file
                try:
                    try:
                        command, data = self.command_queue.get(block=True, timeout=1)
                        self.n_get_timeouts = 0
                    except Empty as e:
                        self.n_get_timeouts += 1
                        # wait before raising the exception but
                        # check while conditions every second
                        # to stop the thread if a Ctrl+C is received
                        if self.n_get_timeouts > self.max_time_receiving_file:
                            raise Exception("No file command was received")
                        else:
                            continue

                    self.process_file_cmd(command, data)
                except Exception as e:
                    logger.error("{0}: Unknown error in process_file_cmd: {1}.".format(self.thread_tag, str(e)))
                    self.unlock_and_stop(reason="error")

            time.sleep(self.interval_file_transfer_receive)

        logger.info("{0}: End.".format(self.thread_tag))


    # New methods
    def unlock_and_stop(self, reason, send_err_request=None):
        """
        Releases a lock before stopping the thread

        :param reason: Reason why this function was called. Only for logger purposes.
        :param send_err_request: Whether to send an error request. Only used in master nodes.
        """
        logger.info("{0}: Unlocking '{1}' due to {2}.".format(self.thread_tag, self.status_type, reason))
        self.lock_status(False)
        self.stop()


    def check_connection(self):
        """
        Check if the node is connected. Only defined in client nodes.
        """
        raise NotImplementedError


    def lock_status(self, status):
        """
        Acquires / Releases a lock.

        :param status: flag to indicate whether release or acquire the lock.
        """
        raise NotImplementedError


    def process_file(self):
        """
        Method which defines how to process a file once it's been received.
        """
        raise NotImplementedError


    def set_command(self, command, data):
        """
        Adds a received command to the command queue

        :param command: received command
        :param data: received data (filename, file chunk, file md5...)
        """
        split_data = data.split(' ',1)
        local_data = split_data[1] if len(split_data) > 1 else None
        self.command_queue.put((command, local_data))


    def process_file_cmd(self, command, data):
        """
        Process the commands received in the command queue
        """
        try:
            if command == "file_open":
                logger.debug("{0}: Opening file.".format(self.thread_tag))
                command = ""
                self.file_open()
            elif command == "file_update":
                logger.debug("{0}: Updating file.".format(self.thread_tag))
                command = ""
                self.file_update(data)
            elif command == "file_close":
                logger.debug("{0}: Closing file.".format(self.thread_tag))
                self.file_close(data)
                logger.debug("{0}: File closed.".format(self.thread_tag))
                self.received_all_information = True
                command = ""
        except Exception as e:
            logger.error("{0}: '{1}'.".format(self.thread_tag, str(e)))
            self.received_error = True


    def file_open(self):
        """
        Start the protocol of receiving a file. Create a new file
        """
        # Create the file
        self.filename = "{}/queue/cluster/{}/{}.tmp".format(common.ossec_path, self.name, self.id)
        logger.debug2("{0}: Creating file {1}".format(self.thread_tag, self.filename))  # debug2
        self.f = open(self.filename, 'w')
        logger.debug2("{}: File {} created successfully.".format(self.thread_tag, self.filename))  # debug2


    def file_update(self, chunk):
        """
        Continue the protocol of receiving a file. Append data

        :parm data: data received from socket

        This data must be:
            - chunk
        """
        # Open the file
        self.f.write(chunk)


    def file_close(self, md5_sum):
        """
        Ends the protocol of receiving a file

        :parm data: data received from socket

        This data must be:
            - MD5 sum
        """
        # compare local file's sum with received sum
        self.f.close()
        local_md5_sum = self.manager_handler.compute_md5(self.filename)
        if local_md5_sum != md5_sum:
            error_msg = "Checksum of received file {} is not correct. Expected {} / Found {}".\
                            format(self.filename, md5_sum, local_md5_sum)
            #return 'err', error_msg
            os.remove(self.filename)
            raise Exception(error_msg)

        logger.debug2("{0}: File {1} received successfully".format(self.thread_tag, self.filename))
