#!/usr/bin/env python

from wazuh import common
from wazuh.cluster.cluster import clean_up
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
    from Queue import Queue
except ImportError:
    from queue import Queue

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


class Handler(asyncore.dispatcher_with_send):

    def __init__(self, sock=None, map=None):
        asyncore.dispatcher_with_send.__init__(self, sock=sock, map=map)
        self.box = {}
        self.counter = random.SystemRandom().randint(0, 2 ** 32 - 1)
        self.inbuffer = b''
        self.lock = threading.Lock()
        self.workers_lock = threading.Lock()
        self.workers = {}
        self.stopper = threading.Event()


    def exit(self):
        logging.debug("[Transport] Cleaning connection")
        self.stopper.set()

        with self.workers_lock:
            worker_ids = self.workers.keys()


        for worker_id in worker_ids:
            logging.debug("[Transport] Cleaning thread: '{0}'".format(worker_id))

            with self.workers_lock:
                my_worker = self.workers[worker_id]

            my_worker.join(timeout=5)
            if my_worker.isAlive():
                logging.warning("[Transport] Cleaning thread. Timeout for: '{0}'.".format(worker_id))
            else:
                logging.debug("[Transport] Cleaning main threads. Terminated: '{0}'.".format(worker_id))


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


    def send_file(self, reason, file, remove = False):
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


        response = self.execute("file_open", "{}".format(id))
        #logging.debug("RESPONSE: {0}".format(response))
        # TO-DO remove ossec_path from sent filepath
        base_msg = "{} ".format(id).encode()
        chunk_size = max_msg_size - len(base_msg)

        with open(file, 'rb') as f:
            for chunk in iter(lambda: f.read(chunk_size), ''):
                response = self.execute("file_update", base_msg + chunk)
                #logging.debug("RESPONSE: {0}".format(response))
                # for every chunk sent, sleep 0.1 s to prevent network from collapsing
                #time.sleep(0.1)

        response = self.execute("file_close", "{} {}".format(id, self.compute_md5(file)))

        if remove:
            os.remove(file)

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
        logging.error("[Transport] err {}".format(v))



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
        try:
            message = msgbuild(counter, command, payload)
        except Exception as e:
            logger.error("[Transport] Error sending a request/response due to '{}'.".format(str(e)))
            message = msgbuild(counter, "err", str(e))

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
            error_msg = "Error processing command '{0}': {1}".format(command, str(e))

            logging.debug("[Transport] {0}.".format(error_msg))
            return 'err ', error_msg


    def process_request(self, command, data):
        if command == 'echo':
            return 'ok ', data.decode()
        elif command == "file_open" or command == "file_update":
            worker, cmd, message = self.get_worker(data)
            if worker:
                worker.set_command(command, data)
            return cmd, message
        elif command == "file_close":
            worker, cmd, message = self.get_worker(data)
            if worker:
                worker.set_command(command, data)
                logging.debug("[Transport] Acquiring lock...")
                worker.close_lock.acquire()
                worker.close_lock.wait()
                worker.close_lock.release()
                logging.debug("[Transport] Releasing lock... ({})".format(worker.result))

                return worker.result

            return cmd, message
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
            logging.debug("[Transport] Error received: {0}.".format(payload.decode()))
        else:
            final_response = None
            logging.error("ERROR: Unknown answer: '{}'. Payload: '{}'.".format(answer, payload))

        return final_response


class ServerHandler(Handler):

    def __init__(self, sock, server, map, addr=None):
        Handler.__init__(self, sock, map)
        self.map = map
        self.name = None
        self.server = server
        self.addr = addr


    def handle_close(self):
        if self.name:
            self.server.remove_client(self.name)
            logging.info("[Transport-S] Node '{0}' disconnected.".format(self.name))
        else:
            logging.info("Connection with {} closed.".format(self.name))

        Handler.handle_close(self)


    def process_request(self, command, data):
        if command == 'hello':
            return self.hello(data.decode())
        else:
            return Handler.process_request(self, command, data)


    def hello(self, data):
        id = self.server.add_client(data, self.addr, self)
        self.name = id  # TO DO: change self.name to self.id
        logging.info("[Transport-S] Node '{0}' connected.".format(id))
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


    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, addr = pair
            logging.info("[Transport-S] Incoming connection from {0}.".format(repr(addr)))

            if self.find_client_by_ip(addr[0]):
                sock.close()
                logging.error("[Transport-S] Incoming connection from {0} rejected: Client already connected.".format(repr(addr)))
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
        logging.error("[Transport-S] err {}".format(v))


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
                    'sync_agentinfo_free': True
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
                logging.error("Client {} is already disconnected.".format(id))


    def get_connected_clients(self):
        with self._clients_lock:
            return self._clients


    def get_client_info(self, client_name):
        with self._clients_lock:
            try:
                return self._clients[client_name]
            except KeyError:
                error_msg = "Client {} is disconnected.".format(client_name)
                logging.error(error_msg)
                raise Exception(error_msg)


    def send_file(self, client_name, reason, file, remove = False):
        return self.get_client_info(client_name)['handler'].send_file(reason, file, remove)


    def send_request(self, client_name, command, data=None):
        response = None

        if client_name in self.get_connected_clients():
            response = self.get_client_info(client_name)['handler'].execute(command, data)
        else:
            error_msg = "Trying to send and the client '{0}' is not connected.".format(client_name)
            logging.error("[Transport-S] {0}.".format(error_msg))
            response = "err " + error_msg

        return response


    def send_request_broadcast(self, command, data=None):
        message = "{0} {1}".format(command, data)

        for c_name in self.get_connected_clients():
            response = self.get_client_info(c_name)['handler'].execute(command, data)
            yield c_name, response


class ClientHandler(Handler):

    def __init__(self, host, port, name, map = {}):
        Handler.__init__(self, map=map)
        self.map = map
        self.host = host
        self.port = port
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            ok = self.connect( (host, port) )
        except socket.gaierror as e:
            error_msg = "[Client] Could not connect to master: {}. Review if the master's hostname or IP is correct.".format(str(e))
            raise Exception(error_msg)  # TO DO: Raise a Cluster Exception
        self.name = name
        self.my_connected = False


    def handle_connect(self):
        logging.info("[Client] Connecting to {0}:{1}.".format(self.host, self.port))
        counter = self.nextcounter()
        payload = msgbuild(counter, 'hello', '{} {}'.format(self.name, 'client'))
        self.send(payload)
        self.my_connected = True
        logging.info("[Client] Connected.")


    def handle_close(self):
        Handler.handle_close(self)
        self.my_connected = False
        logging.info("Client disconnected")


    def send_request(self, command, data=None):
        response = None

        if self.my_connected:
            response = self.execute(command, data)
        else:
            error_msg = "Trying to send and there is no connection with the server"
            logging.error("[Transport-C] {0}.".format(error_msg))
            response = "err " + error_msg

        return response


    def is_connected(self):
        return self.my_connected



class InternalSocketHandler(Handler):

    def __init__(self, sock, manager, map):
        Handler.__init__(self, sock=sock, map=map)
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
        logging.info("[Transport-I] Creating UDS socket...")

        # Make sure the socket does not already exist
        try:
            os.unlink(self.socket_address)
        except OSError:
            if os.path.exists(self.socket_address):
                logging.error('[Transport-I] err {} already exits'.format(self.socket_address))
                raise

        self.create_socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.set_reuse_addr()
        try:
            self.bind(self.socket_address)
            logging.info("[Transport-I] Starting up on {}. Listening...".format(self.socket_address))
            self.listen(5)
        except Exception as e:
            error_msg = "Cannot create UDS socket {}".format(e)
            logging.error('err ' + error_msg)


    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, addr = pair
            logging.debug("[Transport-I] New connection in internal socket")
            handler = self.handle_type(sock=sock, manager=self.manager, map=self.map)


    def handle_error(self):
        nil, t, v, tbinfo = asyncore.compact_traceback()

        try:
            self_repr = repr(self)
        except:
            self_repr = '<__repr__(self) failed for object at %0x>' % id(self)

        self.handle_close()
        logging.error("[Transport-I] err {}".format(v))

#
# Internal Socket thread
#
class InternalSocketThread(threading.Thread):
    def __init__(self, socket_name):
        threading.Thread.__init__(self)
        self.daemon = True
        self.manager = None
        self.running = True
        self.internal_socket = None
        self.socket_name = socket_name

    def setmanager(self, manager, handle_type):
        try:
            self.internal_socket = InternalSocket(socket_name=self.socket_name, manager=manager, handle_type=handle_type)
        except Exception as e:
            logging.error("[Transport-I] err initializing internal socket {}".format(e))
            self.internal_socket = None

    def run(self):
        while self.running:
            if self.internal_socket:
                logging.debug("[Transport-I] Ready")
                asyncore.loop(timeout=1, use_poll=False, map=self.internal_socket.map, count=None)
                logging.info("[Transport-I] Disconnected")
                time.sleep(5)
            time.sleep(1)


def send_to_internal_socket(socket_name, message):
    # Create a UDS socket
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    socket_address = "{}/{}.sock".format("/var/ossec/queue/cluster", socket_name)
    logging.debug("[Transport-I] Starting up on {}".format(socket_address))
    response = ""

    # Connect to UDS socket
    try:
        sock.connect(socket_address)
    except Exception as e:
        logging.error('{}'.format(e))
        return response

    # Send message
    logging.debug("[Transport-I] Sending request to SI: '{0}'.".format(message))
    message = message.split(" ", 1)
    cmd = message[0]
    data = message[1] if len(message) > 1 else None
    message_built = msgbuild(random.SystemRandom().randint(0, 2 ** 32 - 1), cmd, data)
    sock.sendall(message_built)
    logging.debug("[Transport-I] Sent")

    # Receive response
    buf = ""
    buf_size = 4096
    try:
        while not response:
            buf += sock.recv(buf_size)
            parse = msgparse(buf)
            if parse:
                offset, counter, command, response = parse

        logging.debug("[Transport-I] Received: answer: '{0}'. Data: '{1}'.".format(command, response))

    except Exception as e:
        logging.error("[Transport-I] err {}".format(e))
    finally:
        logging.debug("[Transport-I] Closing socket...")
        sock.close()

    return response


class ProcessFiles(ClusterThread):

    def __init__(self, manager_handler, filename, client_name, stopper):
        """

        """
        ClusterThread.__init__(self, stopper)

        self.manager_handler = manager_handler
        self.filename = filename
        self.name = client_name
        self.data = None
        self.command_queue = Queue()
        self.received_all_information = False
        self.received_error = False
        self.close_lock = threading.Condition()
        self.f = None
        self.id = None
        self.thread_tag = "[FileThread]"


    # Overridden methods
    def stop(self):
        if self.id:
            self.manager_handler.del_worker(self.id)
        ClusterThread.stop(self)


    def run(self):
        while not self.stopper.is_set() and self.running:
            self.lock_status(True)

            if not self.check_connection():
                continue

            if self.received_all_information:
                logging.debug("{0}: File reception completed.".format(self.thread_tag))
                try:
                    result = self.process_file()
                    if result:
                        logging.info("{0}: Result: Successfully.".format(self.thread_tag))
                    else:
                        logging.error("{0}: Result: Error.".format(self.thread_tag))

                    self.unlock_clean_and_stop(reason="task performed", clean=False, send_err_request=False)
                except Exception as e:
                    logging.error("{0}: Result: Unknown error: {1}.".format(self.thread_tag, str(e)))
                    self.unlock_clean_and_stop(reason="error")

            elif self.received_error:
                logging.debug("{0}: An error took place during file reception.".format(self.thread_tag))
                self.unlock_clean_and_stop(reason="error")

            else:  # receiving file
                try:
                    self.process_file_cmd()
                except Exception as e:
                    logging.error("{0}: Unknown error in process_file_cmd: {1}".format(self.thread_tag, str(e)))
                    self.unlock_clean_and_stop(reason="error")

            time.sleep(0.1)


    # New methods
    def unlock_clean_and_stop(self, reason, clean=True, send_err_request=None):
        logging.info("{0}: Unlocking '{1}' due to {2}.".format(self.thread_tag, self.status_type, reason))
        self.lock_status(False)
        if clean:
            clean_up(self.name)
        self.stop()


    def check_connection(self):
        raise NotImplementedError


    def lock_status(self, status):
        raise NotImplementedError


    def process_file(self):
        raise NotImplementedError


    def set_command(self, command, data):
        split_data = data.split(' ',1)
        local_data = split_data[1] if len(split_data) > 1 else None
        self.command_queue.put((command, local_data))


    def process_file_cmd(self):
        command, data = self.command_queue.get(block=True)
        if command == "file_open":
            logging.debug("{0}: Opening file".format(self.thread_tag))
            command = ""
            self.file_open()
        elif command == "file_update":
            logging.debug("{0}: Updating file".format(self.thread_tag))
            command = ""
            self.file_update(data)
        elif command == "file_close":
            self.close_lock.acquire()
            logging.debug("{0}: Closing file".format(self.thread_tag))
            try:
                self.result = self.file_close(data)
                logging.debug("{0}: File closed".format(self.thread_tag))
                self.received_all_information = True
            except Exception as e:
                logging.error("{0}: {1}".format(self.thread_tag, str(e)))
                self.received_error = True
                self.result = "err", str(e)
            finally:
                command = ""
                self.close_lock.notify()
                self.close_lock.release()


    def file_open(self):
        """
        Start the protocol of receiving a file. Create a new file

        :parm data: data received from socket

        This data must be:
            - thread id

        and must be separated by a white space
        """
        # Create the file
        self.filename = "{}/queue/cluster/{}/{}.tmp".format(common.ossec_path, self.name, self.id)
        logging.debug("{0}: Creating file {1}".format(self.thread_tag, self.filename))
        self.f = open(self.filename, 'w')
        return "ok", "File {} created successfully".format(self.filename)


    def file_update(self, chunk):
        """
        Continue the protocol of receiving a file. Append data

        :parm data: data received from socket

        This data must be:
            - thread id
            - filename
            - chunk

        and must be separated by a white space
        """
        # Open the file
        self.f.write(chunk)
        return "ok", "Chunk wrote to {} successfully".format(self.filename)


    def file_close(self, md5_sum):
        """
        Ends the protocol of receiving a file

        :parm data: data received from socket

        This data must be:
            - thread id
            - filename
            - MD5 sum

        and must be separated by a white space
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

        return "ok", "File {} received successfully".format(self.filename)
