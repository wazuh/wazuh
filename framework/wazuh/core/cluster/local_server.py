# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import functools
import json
import random
from typing import Tuple, Union

import uvloop

from wazuh.core import common
from wazuh.core.cluster import common as c_common, server, client, local_client
from wazuh.core.cluster.dapi import dapi
from wazuh.core.cluster.utils import context_tag
from wazuh.core.exception import WazuhClusterError


class LocalServerHandler(server.AbstractServerHandler):
    """
    Handles requests from a local client
    """

    def connection_made(self, transport):
        """
        Defines the process of accepting a connection

        :param transport: socket to write data on
        """
        self.name = str(random.SystemRandom().randint(0, 2 ** 20 - 1))
        self.transport = transport
        self.server.clients[self.name] = self
        self.tag = "Local " + self.name
        # modify filter tags with context vars
        context_tag.set(self.tag)
        self.logger.debug('Connection received in local server.')

    def process_request(self, command: bytes, data: bytes) -> Tuple[bytes, bytes]:
        """
        Defines all available commands in a local server for both worker and master nodes
        :param command: Received command
        :param data: Received payload
        :return: A response
        """
        if command == b'get_config':
            return self.get_config()
        elif command == b'get_nodes':
            return self.get_nodes(data)
        elif command == b'get_health':
            return self.get_health(data)
        elif command == b'send_file':
            path, node_name = data.decode().split(' ')
            return self.send_file_request(path, node_name)
        else:
            return super().process_request(command, data)

    def get_config(self) -> Tuple[bytes, bytes]:
        """
        Handles the get_config request
        :return: The active cluster configuration
        """
        return b'ok', json.dumps(self.server.configuration).encode()

    def get_node(self):
        """
        Handles the request get_node
        """
        return self.server.node.get_node()

    def get_nodes(self, filter_nodes) -> Tuple[bytes, bytes]:
        """
        Handles the request get_nodes. It is implemented differently for master and workers.
        :param filter_nodes: Filters
        :return: A response
        """
        raise NotImplementedError

    def get_health(self, filter_nodes) -> Tuple[bytes, bytes]:
        """
        Handles the request get_health. It is implemented differently for masters and workers.
        :param filter_nodes: Filters
        :return: A response
        """
        raise NotImplementedError

    def send_file_request(self, path, node_name):
        """
        Sends a file from the API to the cluster. Used in API calls to update configuration or manager files.
        It is implemented differently for masters and workers
        :param path: File to send
        :param node_name: node name to send the file
        :return: A response
        """
        raise NotImplementedError

    def get_send_file_response(self, future):
        """
        Forwards the send file response to the API
        :param future: Request result
        :return: None
        """
        result = future.result()
        send_res = asyncio.create_task(self.send_request(command=b'send_f_res', data=result))
        send_res.add_done_callback(self.send_res_callback)

    def send_res_callback(self, future):
        if not future.cancelled():
            exc = future.exception()
            if exc:
                self.logger.error(exc)


class LocalServer(server.AbstractServer):
    """
    Creates the server, manages multiple client connections and it's connected to the cluster TCP transports.
    """
    def __init__(self, node: Union[server.AbstractServer, client.AbstractClientManager], **kwargs):
        """
        Class constructor
        :param node: The server/worker object running in the cluster.
        :param kwargs: Arguments for the parent class constructor.
        """
        super().__init__(**kwargs, tag="Local Server")
        self.node = node
        self.node.local_server = self
        self.handler_class = LocalServerHandler

    async def start(self):
        """
        Starts the server and the necessary asynchronous tasks
        """
        # Get a reference to the event loop as we plan to use
        # low-level APIs.
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        loop = asyncio.get_running_loop()
        loop.set_exception_handler(c_common.asyncio_exception_handler)

        try:
            server = await loop.create_unix_server(protocol_factory=lambda: self.handler_class(server=self, loop=loop,
                                                                                               fernet_key='',
                                                                                               logger=self.logger,
                                                                                               cluster_items=self.cluster_items),
                                                   path='{}/queue/cluster/c-internal.sock'.format(common.ossec_path))
        except OSError as e:
            self.logger.error("Could not create server: {}".format(e))
            raise KeyboardInterrupt

        self.logger.info('Serving on {}'.format(server.sockets[0].getsockname()))

        self.tasks.append(server.serve_forever)

        async with server:
            # use asyncio.gather to run both tasks in parallel
            await asyncio.gather(*map(lambda x: x(), self.tasks))


class LocalServerHandlerMaster(LocalServerHandler):
    """
    The local server handler instance that runs in the Master node.
    """
    def process_request(self, command: bytes, data: bytes):
        """
        Defines requests available in the local server

        :param command: Received command
        :param data: Received payload
        :return: A response
        """
        #modify logger filter tag in LocalServerHandlerMaster entry point
        context_tag.set("Local " + self.name)

        if command == b'dapi':
            self.server.dapi.add_request(self.name.encode() + b' ' + data)
            return b'ok', b'Added request to API requests queue'
        elif command == b'dapi_forward':
            node_name, request = data.split(b' ', 1)
            node_name = node_name.decode()
            if node_name in self.server.node.clients:
                asyncio.create_task(
                    self.server.node.clients[node_name].send_request(b'dapi', self.name.encode() + b' ' + request))
                return b'ok', b'Request forwarded to worker node'
            else:
                raise WazuhClusterError(3022)
        else:
            return super().process_request(command, data)

    def get_nodes(self, arguments: bytes) -> Tuple[bytes, bytes]:
        """
        Manages the get_nodes command
        :param arguments: Filter arguments from the API
        :return: A encoded dictionary with the response
        """
        return b'ok', json.dumps(self.server.node.get_connected_nodes(**json.loads(arguments.decode()))).encode()

    def get_health(self, filter_nodes: bytes) -> Tuple[bytes, bytes]:
        """
        Manages the get_health command
        :param filter_nodes: Arguments for the get health function
        :return: An encoded dictionary with the response
        """
        return b'ok', json.dumps(self.server.node.get_health(json.loads(filter_nodes))).encode()

    def send_file_request(self, path, node_name):
        """
        Sends a file from the API to the specified cluster node. Used in API calls to update configuration or manager
        files.

        :param path: File to send
        :param node_name: node name to send the file
        :return: A response
        """
        if node_name not in self.server.node.clients:
            raise WazuhClusterError(3022)
        else:
            req = asyncio.create_task(self.server.node.clients[node_name].send_file(path))
            req.add_done_callback(self.get_send_file_response)
            return b'ok', b'Forwarding file to master node'


class LocalServerMaster(LocalServer):
    """
    The LocalServer object running in the master node
    """
    def __init__(self, node: server.AbstractServer, **kwargs):
        super().__init__(node=node, **kwargs)
        self.handler_class = LocalServerHandlerMaster
        self.dapi = dapi.APIRequestQueue(server=self)
        self.sendsync = dapi.SendSyncRequestQueue(server=self)
        self.tasks.extend([self.dapi.run, self.sendsync.run])


class LocalServerHandlerWorker(LocalServerHandler):
    """
    The local server handler instance that runs in worker nodes.
    """
    def process_request(self, command: bytes, data: bytes):
        """
        Defines requests available in the local server

        :param command: Received command
        :param data: Received payload
        :return: A response
        """
        # modify logger filter tag in LocalServerHandlerWorker entry point
        context_tag.set("Local " + self.name)

        self.logger.debug2("Command received: {}".format(command))
        if command == b'dapi':
            if self.server.node.client is None:
                raise WazuhClusterError(3023)
            asyncio.create_task(self.server.node.client.send_request(b'dapi', self.name.encode() + b' ' + data))
            return b'ok', b'Added request to API requests queue'
        elif command == b'sendsync':
            if self.server.node.client is None:
                raise WazuhClusterError(3023)
            asyncio.create_task(self.server.node.client.send_request(b'sendsync', self.name.encode() + b' ' + data))
            return None, None
        elif command == b'sendasync':
            if self.server.node.client is None:
                raise WazuhClusterError(3023)
            asyncio.create_task(self.server.node.client.send_request(b'sendsync', self.name.encode() + b' ' + data))
            return b'ok', b'Added request to sendsync requests queue'
        else:
            return super().process_request(command, data)

    def get_nodes(self, arguments) -> Tuple[bytes, bytes]:
        """
        Manages the get_nodes command. It forwards the request to the master node.
        :param arguments: Filter arguments from the API
        :return: A encoded dictionary with the response
        """
        return self.send_request_to_master(b'get_nodes', arguments)

    def get_health(self, filter_nodes) -> Tuple[bytes, bytes]:
        """
        Manages the get_health command. It forwards the request to the master node.
        :param filter_nodes: Arguments for the get health function
        :return: An encoded dictionary with the response
        """
        return self.send_request_to_master(b'get_health', filter_nodes)

    def send_request_to_master(self, command: bytes, arguments: bytes):
        """
        Forwards a request to the master node.
        :param command: Command to forward
        :param arguments: Payload to forward
        :return: Confirmation message
        """
        if self.server.node.client is None:
            raise WazuhClusterError(3023)
        else:
            request = asyncio.create_task(self.server.node.client.send_request(command, arguments))
            request.add_done_callback(functools.partial(self.get_api_response, command))
            return b'ok', b'Sent request to master node'

    def get_api_response(self, in_command, future):
        """
        Forwards response sent by the master to the local client. Callback of the send_request_to_master method.
        :param in_command: command originally sent to the master
        :param future: Request response
        :return: Nothing
        """
        send_res = asyncio.create_task(self.send_request(command=b'dapi_res' if in_command == b'dapi' else b'control_res',
                                                         data=future.result()))
        send_res.add_done_callback(self.send_res_callback)

    def send_file_request(self, path, node_name):
        """
        Sends a file from the API to the master who will send it to the specified cluster node.
        Used in API calls to update configuration or manager files.

        :param path: File to send
        :param node_name: node name to send the file
        :return: A response
        """
        if self.server.node.client is None:
            raise WazuhClusterError(3023)
        else:
            req = asyncio.create_task(self.server.node.client.send_file(path))
            req.add_done_callback(self.get_send_file_response)
            return b'ok', b'Forwarding file to master node'


class LocalServerWorker(LocalServer):
    """
    The LocalServer object running in worker nodes.
    """
    def __init__(self, node: client.AbstractClientManager, **kwargs):
        super().__init__(node=node, **kwargs)
        self.handler_class = LocalServerHandlerWorker
