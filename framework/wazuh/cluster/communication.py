#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh import common, WazuhException
from wazuh.cluster.cluster import check_cluster_status, get_cluster_items_communication_intervals
from wazuh.cluster import __version__
from wazuh.utils import WazuhVersion
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
import sys

# Python 2/3 compability
if sys.version_info[0] == 2:
    from Queue import Queue, Empty

    def base64_encoding(msg):
        return msg.encode('base64', 'strict')
else:
    from queue import Queue, Empty
    import base64
    unicode = str

    def base64_encoding(msg):
        return base64.b64encode(msg.encode())


if check_cluster_status():
    try:
        from cryptography.fernet import Fernet, InvalidToken, InvalidSignature
    except ImportError as e:
        raise ImportError("Could not import cryptography module. Install it using one of the following commands:\n\
 - pip install cryptography\n\
 - yum install python-cryptography python-setuptools\n\
 - apt install python-cryptography")


max_msg_size = 1000000
cmd_size = 12
max_string_send_size = 100000000
logger = logging.getLogger(__name__)

def msgbuild(counter, command, my_fernet, payload=None):

    try:
        if payload:
            payload_type = type(payload)
            if payload_type is str or payload_type is unicode:
                payload = payload.encode()
        else:
            payload = b''
    except UnicodeDecodeError:
        pass

    cmd_len = len(command)
    if cmd_len > cmd_size:
        raise Exception("Command of length {} exceeds maximum allowed {}".format(cmd_len, cmd_size))

    padding_command = (command + ' ' + '-' * (cmd_size - cmd_len - 1)).encode()

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

        command = command.decode().split(' ',1)[0]

        if len(buf) >= size + header_size:
            payload = buf[header_size:size + header_size]
            if payload and my_fernet:
                try:
                    payload = my_fernet.decrypt(payload)
                except InvalidToken:
                    raise Exception("Could not decrypt message. Check the key is correct.")

            if payload and len(payload) > max_msg_size:
                raise Exception("Received message exceeds max allowed length. Command: {}. Received: {}. Max: {}.".format(command, size, max_msg_size))

            return size + header_size, counter, command, payload
    return None


class Response:

    def __init__(self):
        self.cond = threading.Condition()
        self.data = None
        self.response_timeout = get_cluster_items_communication_intervals()['timeout_cluster_request']

    def read(self):
        def frange(start, stop, step):
            r = start
            while r < stop:
                yield r
                r += step

        with self.cond:
            # wait for a response for common.cluster_timeout_msg seconds
            for _ in frange(1,self.response_timeout,0.5):
                self.cond.wait(timeout=0.5)
                if self.data is not None:
                    break
            else:
                raise Exception("Timeout expired while waiting for a response")
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
        must_exit = False
        count = 0
        while not must_exit and not self.stopper.is_set() and self.running:
            if count == delay:
                must_exit = True
            else:
                count += 1
                time.sleep(1)

        return count


class Handler(asyncore.dispatcher_with_send):

    def __init__(self, key, sock=None, asyncore_map=None):
        asyncore.dispatcher_with_send.__init__(self, sock=sock, map=asyncore_map)
        self.box = {}
        self.counter = random.SystemRandom().randint(0, 2 ** 32 - 1)
        self.inbuffer = b''
        self.lock = threading.Lock()  # Box lock
        self.worker_threads_lock = threading.Lock()
        self.worker_threads = {}
        self.stopper = threading.Event()
        self.my_fernet = Fernet(base64_encoding(key)) if key else None
        self.tag = "[Cluster]"


    def exit(self):
        logger.debug("{} Cleaning handler threads. Start.".format(self.tag))
        self.stopper.set()

        with self.worker_threads_lock:
            worker_thread_ids = self.worker_threads.keys()

        for worker_thread_id in worker_thread_ids:
            logger.debug2("{0} Cleaning handler thread: '{1}'.".format(self.tag, worker_thread_id))

            with self.worker_threads_lock:
                my_worker_thread = self.worker_threads[worker_thread_id]

            try:
                my_worker_thread.join(timeout=2)
            except Exception as e:
                logger.error("{0} Cleaning '{1}' thread. Error: '{2}'.".format(self.tag, worker_thread_id, str(e)))

            if my_worker_thread.isAlive():
                logger.warning("{0} Cleaning '{1}' thread. Timeout.".format(self.tag, worker_thread_id))
            else:
                logger.debug2("{0} Cleaning '{1}' thread. Terminated.".format(self.tag, worker_thread_id))

        logger.debug("{} Cleaning handler threads. End.".format(self.tag))


    def set_worker_thread(self, command, worker_thread, filename=None):
        thread_id = '{}-{}'.format(command, worker_thread.ident)
        if filename:
            thread_id = "{}-{}".format(thread_id, os.path.basename(filename))

        with self.worker_threads_lock:
            self.worker_threads[thread_id] = worker_thread
        worker_thread.id = thread_id
        return thread_id


    def del_worker_thread(self, worker_thread_id):
        with self.worker_threads_lock:
            if worker_thread_id in self.worker_threads:
                del self.worker_threads[worker_thread_id]


    def get_worker_thread(self, data):
        # the worker_thread worker_thread_id will be the first element spliting the data by spaces
        worker_thread_id = data.split(b' ', 1)[0].decode()
        with self.worker_threads_lock:
            if worker_thread_id in self.worker_threads:
                return self.worker_threads[worker_thread_id], 'ack', 'Command received for {}'.format(worker_thread_id)
            else:
                return None, 'err', 'Worker {} not found. Please, send me the reason first'.format(worker_thread_id)


    def compute_file_md5(self, my_file, blocksize=2 ** 20):
        hash_algorithm = hashlib.md5()
        with open(my_file, 'rb') as f:
            for chunk in iter(lambda: f.read(blocksize), b''):
                hash_algorithm.update(chunk)

        return hash_algorithm.hexdigest()


    def compute_string_md5(self, my_str):
        return hashlib.md5(my_str).hexdigest()


    def send_file(self, reason, file_to_send, remove=False, interval_file_transfer_send=0.1):
        """
        To send a file without collapsing the network, three special commands
        are defined:
            - send_file_open <node_name> <file_name>
            - send_file_update <node_name> <file_name> <file_content>
            - send_file_close <node_name> <file_name> <md5>
        Every 1MB sent, this function sleeps for 1s. This way, other network
        packages can be sent while a file is being sent

        Before sending the file, a request with a "reason" is sent. This way,
        the server will get prepared to receive the file.

        :param interval_file_transfer_send: Time to sleep between each chunk sent
        :param file_to_send: filename (path)
        :param reason: command to send before starting to send the file_to_send
        :param remove: whether to remove the file_to_send after sending it or not
        """
        # response will be of form 'ack worker_thread_id'
        _, worker_thread_id = self.execute(reason, os.path.basename(file_to_send)).split(' ', 1)

        try:
            res, data = self.execute("new_f_r", "{}".format(worker_thread_id)).split(' ', 1)

            if res == "err":
                raise Exception(data)

            base_msg = "{} ".format(worker_thread_id).encode()
            chunk_size = max_msg_size - len(base_msg)

            with open(file_to_send, 'rb') as f:
                for chunk in iter(lambda: f.read(chunk_size), b''):
                    res, data = self.execute("update_f_r", base_msg + chunk).split(' ', 1)
                    if res == "err":
                        raise Exception(data)
                    time.sleep(interval_file_transfer_send)

            res, data = self.execute("end_f_r", "{} {}".format(worker_thread_id, self.compute_file_md5(file_to_send))).split(' ', 1)

            if res == "err":
                raise Exception(data)
            response = res + " " + data

        except Exception as e:
            error_msg = "Error sending file ({}): '{}'".format(reason, str(e))
            logger.error("{} {}.".format(self.tag, error_msg))
            response = "err" + " " + error_msg

        if remove:
            os.remove(file_to_send)

        return response


    def send_string(self, reason, string_data=None, interval_string_transfer_send=0.1, new_req="new_f_r",
                    upd_req="update_f_r", end_req="end_f_r", extra_data=""):
        """
        Every chunk sent, this function sleeps for interval_string_transfer_send seconds.
        This way, other network packages can be sent while a long string is being sent.

        Before sending the string, a request with a "reason" is sent. This way,
        the server will get prepared to receive the data.

        The max B that is possible to send is max_string_send_size.

        :param end_req: Request for ending a request
        :param upd_req: Request for string updating
        :param new_req: Request name for new incoming request
        :param interval_string_transfer_send: Time to sleep between each chunk sent.
        :param reason: Command to send before starting to send the file_to_send.
        :param string_data: String data to send to the worker.
        :param extra_data: Extra information to add to the "reason" request.
        """
        try:
            # Check string size
            data_size = len(string_data)
            if data_size > max_string_send_size:
                raise Exception(
                    "String exceeds max allowed length. Received: {}. Max: {}".format(data_size, max_string_send_size))

            # Send reason
            res, data = self.execute(reason, extra_data).split(' ', 1)
            if res == "err":
                raise Exception(data)
            else:
                worker_id = data

            # Process worker id
            base_msg = "{} ".format(worker_id)
            chunk_size = max_msg_size - len(base_msg)

            # Start to send
            res, data = self.execute(new_req, worker_id).split(' ', 1)
            if res == "err":
                raise Exception(data)

            # Send string
            for current_size_read in range(0, data_size, chunk_size):
                res, data = self.execute(upd_req, "{}{}".format(base_msg,
                                            string_data[current_size_read:current_size_read+chunk_size])).split(' ', 1)
                if res == "err":
                    raise Exception(data)
                time.sleep(interval_string_transfer_send)

            # End
            res, data = self.execute(end_req, "{} {}".format(worker_id, self.compute_string_md5(string_data.encode()))).split(' ', 1)
            if res == "err":
                raise Exception(data)
            response = res + " " + data

        except Exception as e:
            error_msg = "Error sending string ({}): {}".format(reason, e)
            logger.error("{} {}.".format(self.tag, error_msg))
            raise Exception(error_msg)

        return response


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
                    response.write(command + ' ' + payload.decode())
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
        logger.error("{} Error: '{}'.".format(self.tag, v))
        logger.debug("{} Error: '{}' - '{}'.".format(self.tag, t, tbinfo))


    def handle_close(self):
        self.close()

        # before closing all responses, wait to let the response be written.
        n_retries = 0
        while len(self.box) > 0 and n_retries < 5:
            logger.debug("{}: There are {} pending responses. Waiting 0.1s.".format(self.tag, len(self.box)))
            time.sleep(0.1)
            n_retries += 1

        for response_id, response in self.box.items():
            logger.debug("{}: Closing pending response with id {}.".format(self.tag, response_id))
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
            logger.error("{} Error sending a request/response (command: '{}') due to '{}'.".format(self.tag, command, str(e)))
            message = msgbuild(counter, "err", self.my_fernet, str(e))

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
        except Exception as e:
            logger.error("[Cluster] Error splitting data: '{}'.".format(e))
            cmd = "err"
            payload = "Error splitting data"

        return cmd, payload


    def dispatch(self, command, payload):
        try:
            return self.process_request(command, payload)
        except WazuhException as e:
            logger.error("{} {}".format(self.tag, e.message))
            return 'err', str(e)
        except Exception as e:
            error_msg = "Error processing command '{0}': '{1}'.".format(command, e)
            logger.error("{1} {0}".format(error_msg, self.tag))
            return 'err', error_msg


    def process_request(self, command, data):

        fragmented_requests_commands = {"new_f_r", "update_f_r", "end_f_r", "fwd_new", "fwd_upd", "fwd_end"}

        if command == 'echo':
            return 'ok ', data.decode()
        elif command in fragmented_requests_commands:
            # At this moment, the thread should exists
            worker_thread, cmd, message = self.get_worker_thread(data)
            if worker_thread:
                worker_thread.set_command(command, data)
            return cmd, message
        else:
            message = "'{0}' - Unknown command received '{1}'.".format(self.name, command)
            logger.error("{} {}".format(self.tag, message))
            return "err", message


    def process_response(self, response):
        answer, payload = Handler.split_data(response)

        if answer == 'ok':
            final_response = payload
        elif answer == 'ack':
            final_response = 'Confirmation received: {}'.format(payload)
        elif answer == 'json':
            final_response = json.loads(payload)
        elif answer == 'err':
            final_response = None
            logger.debug("{0} Error received: '{1}'.".format(self.tag, payload))
        else:
            final_response = None
            logger.error("{} Error - Unknown answer: '{}'. Payload: '{}'.".format(self.tag, answer, payload))

        return final_response


class ServerHandler(Handler):

    def __init__(self, sock, server, asyncore_map, addr=None, tag="[Master ]"):
        Handler.__init__(self, server.config['key'], sock, asyncore_map)
        self.map = asyncore_map
        self.name = None
        self.server = server
        self.addr = addr[0] if addr else addr
        self.tag = tag


    def handle_close(self):
        if self.name:
            self.server.remove_worker(self.name)
            logger.info("{0} [{1}]: Disconnected.".format(self.tag, self.name))
        else:
            logger.info("{} Connection with {} closed.".format(self.tag, self.addr))

        Handler.handle_close(self)


    def process_request(self, command, data):
        if command == 'hello':
            return self.hello(data.decode())
        else:
            return Handler.process_request(self, command, data)


    def hello(self, data):

        try:
            # Check worker version
            worker_version = WazuhVersion(data.split(' ')[2])
            server_version = WazuhVersion(__version__)
            if server_version.to_array()[0] != worker_version.to_array()[0] or server_version.to_array()[1] != worker_version.to_array()[1]:
                raise Exception("Incompatible worker version ({})".format(worker_version))

            worker_id = self.server.add_worker(data, self.addr, self)

            self.name = worker_id  # TO DO: change self.name to self.worker_id
            logger.info("[Master ] [{0}]: Connected.".format(worker_id))
        except Exception as e:
            logger.error("[Master ] Error accepting connection from {}: {}".format(self.addr, e))
            self.handle_close()

        return None


    def get_worker(self):
        return self.name


class AbstractServer(asyncore.dispatcher):

    def __init__(self, addr, handle_type, socket_type, socket_family, tag, asyncore_map = {}):
        asyncore.dispatcher.__init__(self, map=asyncore_map)
        self.handle_type = handle_type
        self.map = asyncore_map
        self._workers = {}
        self.tag = tag
        self._workers_lock = threading.Lock()
        self.create_socket(socket_family, socket_type)
        self.set_reuse_addr()
        self.bind(addr)
        self.listen(128)  # number of pending connections the queue will hold
        self.interval_file_transfer_send = get_cluster_items_communication_intervals()['file_transfer_send']
        self.interval_string_transfer_send = get_cluster_items_communication_intervals()['string_transfer_send']


    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, addr = pair
            logger.debug("{0} Incoming connection from {1}.".format(self.tag, addr))

            if self.find_worker_by_ip(addr):
                sock.close()
                logger.warning("{0} Incoming connection from '{0}' rejected: Worker is already connected.".format(self.tag, repr(addr)))
                return

            # addr is a tuple of form (ip, port)
            handler = self.handle_type(sock, self, self.map, addr)


    def handle_error(self):
        nil, t, v, tbinfo = asyncore.compact_traceback()

        try:
            self_repr = repr(self)
        except:
            self_repr = '<__repr__(self) failed for object at %0x>' % id(self)

        self.handle_close()

        logger.error("{} Error: '{}'.".format(self.tag, v))
        logger.debug("{} Error: '{}' - '{}'.".format(self.tag, t, tbinfo))


    def find_worker_by_ip(self, worker_ip):

        with self._workers_lock:
            for worker in self._workers:
                if self._workers[worker]['info']['ip'] == worker_ip:
                    return worker

        return None


    def add_worker(self, data, ip, handler):
        raise NotImplementedError


    def remove_worker(self, worker_id):
        with self._workers_lock:
            try:
                # Remove threads
                self._workers[worker_id]['handler'].exit()

                del self._workers[worker_id]
            except KeyError:
                logger.error("{} Worker '{}'' is already disconnected.".format(self.tag, worker_id))


    def get_connected_workers(self):
        with self._workers_lock:
            return self._workers


    def get_worker_info(self, worker_name):
        with self._workers_lock:
            try:
                return self._workers[worker_name]
            except KeyError:
                error_msg = "Worker {} is disconnected.".format(worker_name)
                logger.error("{} {}".format(self.tag, error_msg))
                raise Exception(error_msg)


    def send_request_broadcast(self, command, data=None):

        for w_name in self.get_connected_workers():
            response = self.get_worker_info(w_name)['handler'].execute(command, data)
            yield w_name, response


    def send_request(self, worker_name, command, data=None):

        if worker_name in self.get_connected_workers():
            response = self.get_worker_info(worker_name)['handler'].execute(command, data)
        else:
            error_msg = "Trying to send and the worker '{0}' is not connected.".format(worker_name)
            logger.error("{0} {1}.".format(self.tag, error_msg))
            response = "err " + error_msg

        return response


    def send_file(self, worker_name, reason, file_to_send, remove = False):
        return self.get_worker_info(worker_name)['handler'].send_file(reason, file_to_send, remove, self.interval_file_transfer_send)


    def send_string(self, worker_name, reason, string_to_send, new_req="new_f_r", upd_req="update_f_r", end_req="end_f_r", extra_data=""):
        if worker_name in self.get_connected_workers():
            response = self.get_worker_info(worker_name)['handler'].send_string(reason, string_to_send,
                                                                                self.interval_string_transfer_send,
                                                                                new_req, upd_req, end_req, extra_data)
        else:
            error_msg = "Trying to send and the worker '{0}' is not connected.".format(worker_name)
            logger.error("[Cluster] {0}.".format(error_msg))
            response = "err " + error_msg
        return response


class Server(AbstractServer):

    def __init__(self, host, port, handle_type, asyncore_map = {}):
        AbstractServer.__init__(self, addr=(host,port), handle_type=handle_type, asyncore_map=asyncore_map,
                                socket_family=socket.AF_INET, socket_type=socket.SOCK_STREAM, tag="[Cluster]")


    def add_worker(self, data, ip, handler):
        name, node_type, version = data.split(' ')
        name, cluster_name = name.split('*')
        node_id = name

        if cluster_name != handler.server.config['name']:
            raise Exception("Incoming connection from '{0}' rejected: cluster name is different ({1}/{2}).".format(
                                ip, cluster_name, handler.server.config['name']))

        with self._workers_lock:
            if node_id in self._workers or node_id == handler.server.config['node_name']:
                raise Exception("Incoming connection from '{0}' rejected: There is already a node with the same ID ('{1}') connected.".format(ip, node_id))

            self._workers[node_id] = {
                'handler': handler,
                'info': {
                    'name': name,
                    'ip': ip,
                    'type': node_type,
                    'version': version
                },
                'status': {
                    'sync_integrity_free': True,
                    'sync_agentinfo_free': True,
                    'sync_extravalid_free': True,
                    'last_sync_integrity': {
                        'date_start_master':'n/a',
                        'date_end_master':'n/a',
                        'total_files':{
                            'missing':0,
                            'shared':0,
                            'extra':0,
                            'extra_valid': 0
                        }
                    },
                    'last_sync_agentinfo': {
                        'date_start_master':'n/a',
                        'date_end_master':'n/a',
                        'total_agentinfo':0
                    },
                    'last_sync_agentgroups': {
                        'date_start_master':'n/a',
                        'date_end_master':'n/a',
                        'total_agentgroups':0
                    },
                    'last_keep_alive': 0
                }
            }
        return node_id


class AbstractClient(Handler):

    def __init__(self, key, addr, name, socket_family, socket_type, connect_query, tag, asyncore_map = {}):
        Handler.__init__(self, key=key, asyncore_map=asyncore_map)
        self.connect_query = connect_query
        self.map = asyncore_map
        self.my_connected = False
        self.tag = tag
        self.create_socket(socket_family, socket_type)
        self.name = name
        ok = self.connect(addr)


    def handle_connect(self):
        counter = self.nextcounter()
        payload = msgbuild(counter, 'hello', self.my_fernet, self.connect_query)
        self.send(payload)
        self.my_connected = True
        logger.info("{} Connected.".format(self.tag))


    def handle_close(self):
        Handler.handle_close(self)
        self.my_connected = False
        logger.info("{} Disconnected.".format(self.tag))


    def send_request(self, command, data=None):

        if self.my_connected:
            response = self.execute(command, data)
        else:
            error_msg = "Trying to send and there is no connection with the server"

            logger.error("{0} {1}.".format(self.tag, error_msg))

            response = "err " + error_msg
        return response


    def is_connected(self):
        return self.my_connected


class ClientHandler(AbstractClient):

    def __init__(self, key, host, port, name, cluster_name, asyncore_map = {}):
        connect_query = '{}*{} {} {}'.format(name, cluster_name, 'worker', __version__)
        AbstractClient.__init__(self, key, (host, port), name, socket.AF_INET, socket.SOCK_STREAM, connect_query,
                                "[Worker ]", asyncore_map)
        self.host = host
        self.cluster_name = cluster_name
        self.port = port
        self.interval_string_transfer_send = get_cluster_items_communication_intervals()['string_transfer_send']


    def handle_connect(self):
        logger.info("[Worker ] Connecting to {0}:{1}.".format(self.host, self.port))
        AbstractClient.handle_connect(self)


class FragmentedRequestReceiver(ClusterThread):

    def __init__(self, manager_handler, stopper):
        """
        Abstract class which defines the necessary methods to receive a fragmented request
        """
        ClusterThread.__init__(self, stopper)

        self.manager_handler = manager_handler  # handler object
        self.command_queue = Queue()            # queue to store received commands
        self.received_all_information = False   # flag to indicate whether all request has been received
        self.received_error = ""                # flag to indicate there has been an error in receiving process
        self.id = None                          # id of the thread doing the receiving process
        self.n_get_timeouts = 0                 # number of times Empty exception is raised

        #Debug
        self.thread_tag = "[ReceiveFR]"         # logger tag of the thread
        self.start_time = 0                     # debug: start receiving time
        self.end_time = 0                       # debug: end time
        self.total_time = 0                     # debug: total time receiving
        self.size_received = 0                  # debug: total bytes received

        #Intervals
        self.interval_transfer_receive = 30
        self.max_time_receiving = 0.1


    def run(self):
        """
        Receives the request and processes it.
        """
        logger.info("{0}: Start.".format(self.thread_tag))

        while not self.stopper.is_set() and self.running:
            self.lock_status(True)

            if not self.check_connection():
                continue

            if self.received_all_information:
                logger.debug("{0}: Reception completed: ({1:.2f}s / {1}B)".format(self.thread_tag, self.total_time, self.size_received))

                try:
                    result = self.process_received_data()
                    if result:
                        logger.info("{0}: Result: Successfully.".format(self.thread_tag))
                    else:
                        logger.error("{0}: Result: Error.".format(self.thread_tag))

                    self.unlock_and_stop(reason="task performed", send_err_request=False)
                except Exception as e:
                    logger.error("{0}: Result: Unknown error: {1}.".format(self.thread_tag, e))
                    self.unlock_and_stop(reason="error", send_err_request=str(e))

            elif self.received_error:
                logger.error("{0}: An error took place during request reception.".format(self.thread_tag))
                self.unlock_and_stop(reason="error", send_err_request=self.received_error)
                self.received_error = ""

            else:  # receiving request
                try:
                    try:
                        command, data = self.command_queue.get(block=True, timeout=1)
                        self.n_get_timeouts = 0
                    except Empty:
                        self.n_get_timeouts += 1
                        # wait before raising the exception but
                        # check while conditions every second
                        # to stop the thread if a Ctrl+C is received
                        if self.n_get_timeouts > self.max_time_receiving:
                            raise Exception("No command was received")
                        else:
                            continue

                    self.process_cmd(command, data)
                except Exception as e:
                    logger.error("{0}: Unknown error in process_cmd: {1}.".format(self.thread_tag, e))
                    self.unlock_and_stop(reason="error", send_err_request=str(e))

            time.sleep(self.interval_transfer_receive)

        logger.info("{0}: End.".format(self.thread_tag))


    def stop(self):
        """
        Stops the thread
        """
        if self.id:
            self.manager_handler.del_worker_thread(self.id)
        ClusterThread.stop(self)


    def unlock_and_stop(self, reason, send_err_request=None):
        """
        Releases a lock before stopping the thread

        :param reason: Reason why this function was called. Only for logger purposes.
        :param send_err_request: Whether to send an error request. Only used in master nodes.
        """
        self.lock_status(False)
        self.stop()


    def set_command(self, command, data):
        """
        Adds a received command to the command queue

        :param command: received command
        :param data: received data (name, chunk, md5...)
        """
        split_data = data.split(b' ',1)
        local_data = split_data[1] if len(split_data) > 1 else None
        self.command_queue.put((command, local_data))


    def process_cmd(self, command, data):
        """
        Process the commands received in the command queue
        """
        logger.debug("{} Received command: {}".format(self.thread_tag, command))
        try:
            if command == "new_f_r":
                self.start_time = time.time()
                self.start_reception()

            elif command == "update_f_r":
                self.update(data)

            elif command == "end_f_r":
                self.close_reception(data)
                self.end_time = time.time()
                self.total_time = self.end_time - self.start_time

        except Exception as e:
            logger.error("{0}: '{1}'.".format(self.thread_tag, e))
            self.received_error = str(e)


    def start_reception(self):
        """
        Start the protocol of receiving a string.
        """
        raise NotImplementedError

    def update(self, chunk):
        """
        Continue the protocol of receiving a request. Append data

        :parm data: data received from socket

        This data must be:
            - chunk
        """
        raise NotImplementedError


    def close_reception(self, md5_sum):
        """
        Ends the protocol of receiving a request
        """
        raise NotImplementedError


    def check_connection(self):
        """
        Check if the node is connected. Only defined in worker nodes.
        """
        raise NotImplementedError


    def lock_status(self, status):
        """
        Acquires / Releases a lock.

        :param status: flag to indicate whether release or acquire the lock.
        """
        raise NotImplementedError


    def process_received_data(self):
        """
        Method which defines how to process a file once it's been received.
        """
        raise NotImplementedError



class FragmentedFileReceiver(FragmentedRequestReceiver):

    def __init__(self, manager_handler, filename, worker_name, stopper):
        """
        Abstract class which defines the necessary methods to receive and process a fragmented file
        """
        FragmentedRequestReceiver.__init__(self, manager_handler, stopper)

        self.filename = filename                # filename of the file to receive
        self.name = worker_name                 # name of the sender
        self.f = None                           # file object that is being received

        #Debug
        self.thread_tag = "[FileThread]"        # logger tag of the thread

        #Intervals
        self.interval_transfer_receive = get_cluster_items_communication_intervals()['file_transfer_receive']
        self.max_time_receiving = get_cluster_items_communication_intervals()['max_time_receiving_file']


    def __create_and_open_file(self):
        # Create the file
        self.filename = "{}/queue/cluster/{}/{}.tmp".format(common.ossec_path, self.name, self.id)
        logger.debug2("{0}: Creating file {1}".format(self.thread_tag, self.filename))
        logger.debug("{0}: Opening file.".format(self.thread_tag))
        self.f = open(self.filename, 'wb')
        logger.debug2("{}: File {} created successfully.".format(self.thread_tag, self.filename))


    def __check_file_md5(self, md5_sum):
        local_md5_sum = self.manager_handler.compute_file_md5(self.filename)
        if local_md5_sum != md5_sum.decode():
            error_msg = "Checksum of received file {} is not correct. Expected {} / Found {}".\
                            format(self.filename, md5_sum, local_md5_sum)
            os.remove(self.filename)
            raise Exception(error_msg)


    def start_reception(self):
        self.__create_and_open_file()


    def update(self, chunk):
        logger.debug("{0}: Updating file.".format(self.thread_tag))
        self.f.write(chunk)
        self.size_received += len(chunk)


    def close_reception(self, md5_sum):
        logger.debug("{0}: Closing file.".format(self.thread_tag))
        self.f.close()
        logger.debug("{0}: File closed.".format(self.thread_tag))
        self.__check_file_md5(md5_sum)
        logger.debug2("{0}: File {1} received successfully".format(self.thread_tag, self.filename))
        self.received_all_information = True


    def process_received_data(self):
        return self.process_file()


    def process_file(self):
        raise NotImplementedError



class FragmentedStringReceiver(FragmentedRequestReceiver):

    def __init__(self, manager_handler, stopper):
        """
        Abstract class which defines the necessary methods to receive a fragmented string request
        """
        FragmentedRequestReceiver.__init__(self, manager_handler, stopper)

        self.sting_received = b""

        #Debug
        self.thread_tag = "[StringThread]" # logger tag of the thread

        #Intervals
        self.interval_transfer_receive = get_cluster_items_communication_intervals()['string_transfer_receive']
        self.max_time_receiving = get_cluster_items_communication_intervals()['max_time_receiving_string']


    def start_reception(self):
        logger.debug("{0}: Receiving new string.".format(self.thread_tag))


    def update(self, chunk):
        logger.debug("{0}: Updating string.".format(self.thread_tag))
        self.sting_received += chunk
        self.size_received += len(chunk)


    def __check_md5(self, md5_sum):
        local_md5_sum = self.manager_handler.compute_string_md5(self.sting_received)
        if local_md5_sum != md5_sum.decode():
            error_msg = "Checksum of received string is not correct. Expected {} / Found {}".\
                            format(md5_sum, local_md5_sum)
            raise Exception(error_msg)


    def close_reception(self, md5_sum):
        self.__check_md5(md5_sum)
        logger.debug("{0}: Complete string reception.".format(self.thread_tag))
        self.received_all_information = True


    def lock_status(self, status):
        pass # Receive string doesn't need lock the status


    def process_received_data(self):
        return True


class FragmentedStringReceiverWorker(FragmentedStringReceiver):

    def __init__(self, manager_handler, stopper):
        FragmentedStringReceiver.__init__(self, manager_handler, stopper)
        self.thread_tag = "[Worker ] [{0}] [String-R     ]".format(self.manager_handler.name)


    def check_connection(self):
        if not self.manager_handler.is_connected():
            logger.info("{0}: Worker is not connected. Waiting {1}s".format(self.thread_tag, 2))
            self.sleep(2)
            return False

        return True
