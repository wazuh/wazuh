#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncore
import asynchat
import socket
import logging
import json
import struct

from os import kill
from signal import SIGUSR1

from wazuh import common
from wazuh.exception import WazuhException
from wazuh.cluster.cluster import check_cluster_status, get_node, decompress_files, get_localhost_ips, read_config, get_files_status, compress_files

if check_cluster_status():
    try:
        from cryptography.fernet import Fernet, InvalidToken, InvalidSignature
    except ImportError as e:
        print("Error importing cryptography module. Please install it with pip, yum (python-cryptography & python-setuptools) or apt (python-cryptography)")
        exit(-1)


def check_cluster_cmd(cmd, node_type):
    # cmd must be a list
    if not isinstance(cmd, list):
        return False

    # check cmd len list
    if len(cmd) != 2:
        return False

    # check cmd len
    if len(' '.join(cmd)) != common.cluster_protocol_plain_size:
        return False

    # 'ready' cmd can only be sent by a master node to a client node
    if cmd[0] == 'ready' and node_type == 'client':
        return True

    if cmd[0] == 'finished' and node_type == 'master':
        return True

    # check command type
    if not cmd[0] in ['zip', 'node']:
        return False

    # second argument of zip is a number
    if cmd[0] == 'zip' and not re.compile('\d+').match(cmd[1]):
        return False

    return True


class WazuhClusterHandler(asynchat.async_chat):
    def __init__(self, sock, addr, key, node_type, requests_queue, child_pid):
        asynchat.async_chat.__init__(self, sock)
        self.addr = addr
        self.f = Fernet(key.encode('base64','strict'))
        self.set_terminator('\n\t\t\n')
        self.received_data = []
        self.data = ""
        self.counter = 0
        self.node_type = node_type
        self.requests_queue = requests_queue
        self.command = []
        self.socket.setblocking(1)
        self.child_pid = child_pid

    def handle_close(self):
        self.requests_queue[self.addr] = False
        self.received_data = []

    def collect_incoming_data(self, data):
        self.requests_queue[self.addr] = True
        self.received_data.append(data)

    def found_terminator(self):
        res_is_zip = False
        response = b''.join(self.received_data)
        error = 0

        response_decrypted = self.f.decrypt(response)

        cmd = response_decrypted[:common.cluster_protocol_plain_size].decode()
        self.command = cmd.split(" ")

        logging.debug("[Server] Command received: {0}".format(self.command))

        # if not check_cluster_cmd(self.command, self.node_type):
        #     logging.error("Received invalid cluster command {0} from {1}".format(
        #                     self.command[0], self.addr))
        #     error = 1
        #     res = "Received invalid cluster command {0}".format(self.command[0])

        if error == 0:

            # node: Information about node
            if self.command[0] == 'node':
                res = get_node()
            # m_c_sync: The client initiates the sync process with the master
            elif self.command[0] == 'm_c_sync':
                zip_bytes = response_decrypted[common.cluster_protocol_plain_size:]
                unzip = decompress_files(zip_bytes)
                res = process_files_from_client(unzip)

                res_is_zip = True
                # Continuing working on master node
                kill(self.child_pid, SIGUSR1)
            # file_status: The client returns information about its files
            elif self.command[0] == 'file_status':
                res = get_files_status('master') # Get 'master files' in a client node
            # force_sync: The master requests the client to start the sync (m_c_sync)
            elif self.command[0] == 'force_sync':
                cluster_config = read_config()
                send_client_files_to_master(cluster_config, "Master required")
                res = 1

            logging.debug("[Server] Command {0} executed for {1}".format(self.command[0], self.addr))
        if res_is_zip:
            self.data = res
        else:
            self.data = json.dumps({'error': error, 'data': res})
        self.handle_write()


    def handle_error(self):
        nil, t, v, tbinfo = asyncore.compact_traceback()

        if t == socket.error and (v.args[0] == socket.errno.EPIPE or
                                  v.args[0] == socket.errno.EBADF):
            # there is an error in the connection with the other node.
            logging.error("[Server] Error in connection with {}: {}".format(self.addr, str(v)))
            self.handle_close()
            self.close()
            self.socket.close()
            return 1

        if t == InvalidToken or t == InvalidSignature:
            error = "Could not decrypt message from {0}".format(self.addr)
        else:
            error = str(v)

        logging.error("[Server] Error handling client request: {0}".format(error))
        self.data = json.dumps({'error': 1, 'data': error})
        self.handle_write()


    def handle_write(self):
        msg = self.f.encrypt(self.data) + '\n'
        i = 0
        msg_len = len(msg)
        while i < msg_len:
            next_i = i+4096 if i+4096 < msg_len else msg_len
            try:
                sent = self.socket.send(msg[i:next_i])
                i += sent
            except socket.error as e:
                self.socket.close()
                raise e
        logging.debug("[Server-S] Sent {}/{} bytes to {}".format(i, msg_len, self.addr))
        self.handle_close()


class WazuhClusterServer(asyncore.dispatcher):


    def __init__(self, cluster_config, child_pid):
        asyncore.dispatcher.__init__(self)

        self.bind_addr = '' if cluster_config['bind_addr'] == '0.0.0.0' else cluster_config['bind_addr']
        self.port = int(cluster_config['port'])
        self.key = cluster_config['key']
        self.node_type = cluster_config['node_type']
        self.socket_timeout = 100 #int(cluster_config['socket_timeout'])
        self.child_pid = child_pid

        remote_connections = set(cluster_config['nodes']) - set(get_localhost_ips())
        self.requests_queue = dict([(node_ip, False) for node_ip in remote_connections])


        # Create socket
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(self.socket_timeout)
        self.set_reuse_addr()

        try:
            self.bind((self.bind_addr, self.port))
        except socket.error as e:
            logging.error("Can't bind socket: {0}".format(str(e)))
            raise e

        self.listen(50)

        logging.info("[Server] Starting cluster {0}".format(cluster_config['name']))
        logging.info("[Server] Listening on port {0}.".format(self.port))
        logging.info("[Server] {0} nodes found in configuration".format(len(cluster_config['nodes'])))
        logging.info("[Server] Synchronization interval: {0}".format(cluster_config['interval']))


    def handle_accept(self):
        pair = self.accept()

        if pair is not None:
            sock, addr = pair
            logging.info("[Server] Accepted connection from host {0}".format(addr[0]))
            handler = WazuhClusterHandler(sock, addr[0], self.key, self.node_type, self.requests_queue, self.child_pid)

        return

    def handle_error(self):
        nil, t, v, tbinfo = asyncore.compact_traceback()
        self.close()
        raise t(v)


class WazuhClusterClient():
    def __init__(self, host, port, key, data, file, connection_timeout, socket_timeout):
        self.can_close = False
        self.received_data = []
        self.response = ""
        self.f = key
        self.data = data
        self.file = file
        self.addr = host
        self.port = port
        self.terminator = '\n'
        self.chunk = 4096
        self.connection_timeout = 100 #connection_timeout
        self.socket_timeout = 100 #socket_timeout
        self.connect()


    def connect(self):
        # the two exceptions need to be processed separately because the first
        # one doesn't need to close the socket since it creates it but
        # the second one needs to both close the socket and raise the exception
        try:
            self.socket = socket.create_connection((self.addr, self.port),
                                                    self.connection_timeout)
        except socket.error as e:
            raise WazuhException(3010, str(e))

        try:
            self.socket.settimeout(self.socket_timeout)
        except socket.error as e:
            self.can_close = True
            self.socket.close()
            raise WazuhException(3010, str(e))


    def handle_close(self):
        if self.can_close:
            self.close()


    def handle_receive(self):
        data = ""
        self.received_data = []
        try:
            while not self.terminator in data:
                data = self.socket.recv(self.chunk)
                self.received_data.append(data)
        except socket.error as e:
            logging.error("[Server-S] Could not receive data from {}: {}".format(self.addr, str(e)))
            if str(e) == "timed out":
                logging.warning("[Server-S] Try increasing socket_timeout configuration at ossec.conf to solve this issue and check your firewall is properly configured")
            raise e
        self.found_terminator()

    def found_terminator(self):
        logging.debug("[Server-S] Received {}".format(len(''.join(self.received_data))))

        try:
            self.response = json.loads(self.f.decrypt(''.join(self.received_data)))
        except (InvalidSignature, InvalidToken) as e:
            raise InvalidToken("[Server-S] Could not encrypt message")
        except: # ToDo: Improve this. It shoul be like a cmd?
            response = b''.join(self.received_data)
            self.response = self.f.decrypt(response)

        self.handle_close()

    def handle_write(self):
        try:
            if self.file is not None:
                msg = self.f.encrypt(self.data.encode() + self.file) + '\n\t\t\n'
            else:
                msg = self.f.encrypt(self.data.encode()) + '\n\t\t\n'
        except (InvalidToken, InvalidSignature) as e:
            raise InvalidToken("[Server-S] Could not encrypt message")

        try:
            i = 0
            msg_len = len(msg)
            while i < msg_len:
                next_i = i+self.chunk if i+self.chunk < msg_len else msg_len
                sent = self.socket.send(msg[i:next_i])
                i += sent

            logging.debug("[Server-S] Sent {}/{} bytes to {}".format(i, msg_len, self.addr))
            self.handle_receive()
        except socket.error as e:
            logging.error("[Server-S] Could not send data to {}: {}".format(self.addr, str(e)))
            raise e

def send_request(host, port, key, data, connection_timeout, socket_timeout, file=None):
    error = 0
    try:
        logging.debug("[Server-S] Active connections: {}".format(common.cluster_connections.keys()))
        client = common.cluster_connections.get(host)
        if not client:
            logging.debug("[Server-S] No opened connection with {}".format(host))
            fernet_key = Fernet(key.encode('base64','strict'))
            client = WazuhClusterClient(host, int(port), fernet_key, data, file, connection_timeout, socket_timeout)
            client.handle_write()
            response = client.response
            common.cluster_connections[host] = client
        else:
            connection_status = get_connection_status(common.cluster_connections[host].socket)
            logging.debug("[Server-S] Connection status with {} is {}".format(host, connection_status))
            if connection_status == 'ESTABLISHED':
                client.data = data
                client.file = file
                try:
                    client.handle_write()
                except socket.error as e:
                    # if the error is reported as timed out, remove the connection
                    # and create a new socket on the next iteration. This way,
                    # the socket will not be ESTABLISHED but "disconnected"
                    if str(e) == 'timed out':
                        logging.debug("[Server-S] Closing connection with {}".format(host))
                        common.cluster_connections[host].socket.close()
                        del common.cluster_connections[host]
                    raise e
                response = client.response
            else:
                common.cluster_connections[host].socket.close()
                del common.cluster_connections[host]
                return send_request(host, port, key, data, connection_timeout, socket_timeout, file)

    except NameError as e:
        response = "Error importing cryptography module. Please install it with pip, yum (python-cryptography & python-setuptools) or apt (python-cryptography): {0}".format(e)
        error = 1

    except Exception as e:
        logging.error("[Server-S] Error sending request to {}: {}".format(host, str(e)))
        error = 1
        response = str(e)

    return error, response


def get_connection_status(host_socket):
    # Taken from: http://www.cse.scu.edu/~dclark/am_256_graph_theory/linux_2_6_stack/linux_2tcp_8h-source.html (line 78)
    tcp_states = {
        1: 'ESTABLISHED',
        2: 'SYN_SENT',
        3: 'SYN_RECV',
        4: 'FIN_WAIT1',
        5: 'FIN_WAIT2',
        6: 'TIME_WAIT',
        7: 'CLOSE',
        8: 'CLOSE_WAIT',
        9: 'LAST_ACK',
        10: 'LISTEN',
        11: 'CLOSING'
    }
    # retrieve a struct tcp_info (/usr/include/linux/tcp.h). The first value is
    # the status of the connection
    state = struct.unpack("B"*7+"I"*24, host_socket.getsockopt(socket.SOL_TCP,
                                                    socket.TCP_INFO, 104))[0]
    return tcp_states[state]




########################################################################################

# FixMe: This should be in master

from wazuh.cluster.master import compare_files, update_client_files_in_master


def get_nodes():
    config_cluster = read_config()
    if not config_cluster:
        raise WazuhException(3000, "No config found")

    # list with all the ips the localhost has
    localhost_ips = get_localhost_ips()

    data = []
    error_response = False

    for url in config_cluster["nodes"]:
        try:
            if not url in localhost_ips:
                error, response = send_request(host=url,
                                                port=config_cluster["port"],
                                                key=config_cluster['key'],
                                                connection_timeout=int(config_cluster['connection_timeout']),
                                                socket_timeout=int(config_cluster['socket_timeout']),
                                                data="node {0}".format('-'*(common.cluster_protocol_plain_size - len("node "))))
                if error == 0:
                    if response['error'] == 0:
                        response = response['data']
                        response['localhost'] = False
                    else:
                        logging.warning("Received an error response from {0}: {1}".format(url, response))
                        error_response = True
            else:
                error = 0
                response = get_node()
                response['localhost'] = True

            if error == 1:
                logging.warning("Error connecting with {0}: {1}".format(url, response))
                error_response = True

            if error_response:
                data.append({'error': response, 'node':'unknown', 'type':'unknown', 'status':'disconnected', 'url':url, 'localhost': False})
                error_response = False
                continue

            if config_cluster['node_type'] == 'master' or \
               response['type'] == 'master' or response["localhost"]:
                data.append({'url':url, 'node':response['node'], 'type': response['type'], 'localhost': response['localhost'],
                             'status':'connected', 'cluster':response['cluster']})

        except TypeError as e:
            error_text = "Response from {} is not in JSON format: {} ({})".format(url, str(e), response)
            logging.error(error_text)
            data.append({'url': url, 'node': 'unknown', 'type': 'unknown', 'status': 'connected', 'url':url, 'error': error_text, 'localhost': False})
        except Exception as e:
            error_text = "Error getting information of node {}: {}".format(url, str(e))
            logging.error(error_text)
            data.append({'url': url, 'node': 'unknown', 'type': 'unknown', 'status': 'connected', 'url':url, 'error': error_text, 'localhost': False})

    return {'items': data, 'totalItems': len(data)}

def force_clients_to_start_sync(node_list=None):
    nodes_response = {}

    config_cluster = read_config()
    if not config_cluster:
        raise WazuhException(3000, "No config found")

    # Get nodes
    all_nodes = get_nodes()['items']

    for node in all_nodes:
        if node['type'] == 'master':
            continue

        if node_list and node['node'] not in node_list:
            continue

        if node['status'] == 'connected':

            error, response = send_request( host=node['url'],
                                    port=config_cluster["port"],
                                    key=config_cluster['key'],
                                    connection_timeout=100, #int(config_cluster['connection_timeout']),
                                    socket_timeout=100, #int(config_cluster['socket_timeout']),
                                    data="force_sync {0}".format('-'*(common.cluster_protocol_plain_size - len("force_sync ")))
            )

            nodes_response[node['node']] = response['data']
        else:
            nodes_response[node['node']] = 'Disconnected: {0}'.format(node['url'])

    return nodes_response

def req_file_status_to_clients():
    config_cluster = read_config()
    if not config_cluster:
        raise WazuhException(3000, "No config found")

    # Get master files
    master_files = get_files_status('master')

    # Get nodes
    all_nodes = get_nodes()['items']

    nodes_file = {}
    for node in all_nodes:
        if node['type'] == 'master':
            continue

        if node['status'] == 'connected':

            error, response = send_request( host=node['url'],
                                    port=config_cluster["port"],
                                    key=config_cluster['key'],
                                    connection_timeout=100, #int(config_cluster['connection_timeout']),
                                    socket_timeout=100, #int(config_cluster['socket_timeout']),
                                    data="file_status {0}".format('-'*(common.cluster_protocol_plain_size - len("file_status ")))
            )

            client_files_ko = compare_files(master_files, response['data'])
            nodes_file[node['node']] = client_files_ko
        else:
            nodes_file[node['node']] = 'disconnected'

    return nodes_file

def process_files_from_client(data_received):
    logging.info("[Master] [Data received]: Start.")

    # Extract recevied data
    logging.info("[Master] [Data received] [STEP 1]: Analyzing received files.")

    master_files_from_client = {}
    client_files = {}
    for key in data_received:
        if key == 'cluster_control.json':
            json_file = json.loads(data_received['cluster_control.json']['data'])
            master_files_from_client = json_file['master_files']
            client_files_json = json_file['client_files']
        else:
            full_path_key = key.replace('files/', '/')
            client_files[full_path_key] = data_received[key]

    # Get master files
    master_files = get_files_status('master')

    # Compare
    client_files_ko = compare_files(master_files, master_files_from_client)

    logging.info("[Master] [Data received] [STEP 2]: Updating manager files.")
    # Update files
    update_client_files_in_master(client_files_json, client_files)

    # Compress data: master files (only KO shared and missing)
    logging.info("[Master] [Data received] [STEP 3]: Compressing KO files for client.")

    master_files_paths = [item for item in client_files_ko['shared']]
    master_files_paths.extend([item for item in client_files_ko['missing']])

    compressed_data = compress_files('master', master_files_paths, client_files_ko)

    logging.info("[Master] [Data received]: End. Sending KO files to client.")
    # Send KO files
    return compressed_data



##############################################

# FixMe: This should be in client

from wazuh.cluster.client import update_master_files_in_client, process_files_from_master

def get_master_node():
    config_cluster = read_config()
    if not config_cluster:
        raise WazuhException(3000, "No config found")

    # list with all the ips the localhost has
    localhost_ips = get_localhost_ips()

    data = []
    error_response = False

    for url in config_cluster["nodes"]:
        try:
            if not url in localhost_ips:
                error, response = send_request(host=url,
                                                port=config_cluster["port"],
                                                key=config_cluster['key'],
                                                connection_timeout=int(config_cluster['connection_timeout']),
                                                socket_timeout=int(config_cluster['socket_timeout']),
                                                data="node {0}".format('-'*(common.cluster_protocol_plain_size - len("node "))))
                if error == 0:
                    if response['error'] == 0:
                        response = response['data']
                        response['localhost'] = False
                    else:
                        logging.warning("Received an error response from {0}: {1}".format(url, response))
                        error_response = True
            else:
                error = 0
                response = get_node()
                response['localhost'] = True

            if error == 1:
                logging.warning("Error connecting with {0}: {1}".format(url, response))
                error_response = True

            if error_response:
                data.append({'error': response, 'node':'unknown', 'type':'unknown', 'status':'disconnected', 'url':url, 'localhost': False})
                error_response = False
                continue

            if config_cluster['node_type'] == 'master' or \
               response['type'] == 'master' or response["localhost"]:
                data.append({'url':url, 'node':response['node'], 'type': response['type'], 'localhost': response['localhost'],
                             'status':'connected', 'cluster':response['cluster']})

        except TypeError as e:
            error_text = "Response from {} is not in JSON format: {} ({})".format(url, str(e), response)
            logging.error(error_text)
            data.append({'url': url, 'node': 'unknown', 'type': 'unknown', 'status': 'connected', 'url':url, 'error': error_text, 'localhost': False})
        except Exception as e:
            error_text = "Error getting information of node {}: {}".format(url, str(e))
            logging.error(error_text)
            data.append({'url': url, 'node': 'unknown', 'type': 'unknown', 'status': 'connected', 'url':url, 'error': error_text, 'localhost': False})

    master_node = 'unknown'
    for item in data:
        if item['type'] == 'master':
            master_node = item['url']

    return master_node

def send_client_files_to_master(config_cluster, reason=None):
    sync_result = False

    logging.info("[Client] [Sync process]: Start. Reason: '{0}'".format(reason))


    logging.info("[Client] [Sync process] [Step 0]: Finding master.")

    master_node = get_master_node()

    if master_node == 'unknown':
        logging.error("[Client] [Sync process] [Step 0]: Master not found.")
    else:
        logging.info("[Client] [Sync process] [Step 0]: Master: {0}.".format(master_node))

        logging.info("[Client] [Sync process] [Step 1]: Gathering files.")
        # Get master files (path, md5, mtime): client.keys, ossec.conf, groups, ...
        master_files = get_files_status('master')
        client_files = get_files_status('client', get_md5=False)
        cluster_control_json = {'master_files': master_files, 'client_files': client_files}

        # Getting client file paths: agent-info, agent-groups.
        client_files_paths = client_files.keys()

        # Compress data: client files + control json
        compressed_data = compress_files('client', client_files_paths, cluster_control_json)


        # Send compressed file to master
        logging.info("[Client] [Sync process] [Step 2]: Sending files to master.")
        error, response = send_request( host=master_node,
                                        port=config_cluster["port"],
                                        key=config_cluster['key'],
                                        connection_timeout=100, #int(config_cluster['connection_timeout']),
                                        socket_timeout=100, #int(config_cluster['socket_timeout']),
                                        #data="zip {0}".format(str(len(compressed_data)).zfill(common.cluster_protocol_plain_size - len("zip "))),
                                        data="m_c_sync {0}".format(str(len(compressed_data)).zfill(common.cluster_protocol_plain_size - len("m_c_sync "))),
                                        file=compressed_data
        )

        # Update files
        if error == 0:
            if 'error' in response and 'data' in response:
                if response['error'] != 0:
                    logging.error("[Client] [Sync process] [Step 3]: ERROR receiving files from master (1): {}".format(response['data']))
            else:
                try:
                    logging.info("[Client] [Sync process] [Step 3]: KO files received from master.")
                    master_data  = decompress_files(response)
                    sync_result = process_files_from_master(master_data)
                except Exception as e:
                    logging.error("[Client] [Sync process] [Step 3]: ERROR receiving files from master (2): {}".format(str(e)))
        else:
            logging.error("[Client] [Sync process] [Step 3]: ERROR receiving files from master")

    # Send ACK
    # ToDo

    # Log
    logging.info("[Client] [Sync process]: Result - {}.".format(sync_result))

    return sync_result
