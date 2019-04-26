# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import functools
import json
import random
from typing import Tuple, Union

import uvloop
from wazuh import common, exception
from wazuh.cluster import server, common as c_common, client
from wazuh.cluster.dapi import dapi
from wazuh.exception import WazuhClusterError


class LocalServerHandler(server.AbstractServerHandler):

    def connection_made(self, transport):
        """
        Defines the process of accepting a connection

        :param transport: socket to write data on
        """
        self.name = str(random.SystemRandom().randint(0, 2 ** 20 - 1))
        self.transport = transport
        self.server.clients[self.name] = self
        self.tag = "Local " + self.name
        self.logger_filter.update_tag(self.tag)
        self.logger.info('Connection received in local server.')

    def process_request(self, command: bytes, data: bytes) -> Tuple[bytes, bytes]:
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
        return b'ok', json.dumps(self.server.configuration).encode()

    def get_node(self):
        return self.server.node.get_node()

    def get_nodes(self, filter_nodes) -> Tuple[bytes, bytes]:
        raise NotImplementedError

    def get_health(self, filter_nodes) -> Tuple[bytes, bytes]:
        raise NotImplementedError

    def send_file_request(self, path, node_name):
        raise NotImplementedError

    def get_send_file_response(self, future):
        result = future.result()
        send_res = asyncio.create_task(self.send_request(command=b'send_f_res', data=result))
        send_res.add_done_callback(self.send_res_callback)

    def send_res_callback(self, future):
        if not future.cancelled():
            exc = future.exception()
            if exc:
                self.logger.error(exc)


class LocalServer(server.AbstractServer):

    def __init__(self, node: Union[server.AbstractServer, client.AbstractClientManager], **kwargs):
        super().__init__(**kwargs, tag="Local Server")
        self.node = node
        self.node.local_server = self
        self.handler_class = LocalServerHandler

    async def start(self):
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

    def process_request(self, command: bytes, data: bytes):
        if command == b'dapi':
            self.server.dapi.add_request(self.name.encode() + b' ' + data)
            return b'ok', b'Added request to API requests queue'
        elif command == b'dapi_forward':
            node_name, request = data.split(b' ', 1)
            node_name = node_name.decode()
            if node_name == 'fw_all_nodes':
                if len(self.server.node.clients) > 0:
                    for node_name, node in self.server.node.clients.items():
                        asyncio.create_task(node.send_request(b'dapi', self.name.encode() + b' ' + request))
                    return b'ok', b'Request forwarded to all worker nodes'
                else:
                    return b'ok', b'There are no connected worker nodes'
            elif node_name in self.server.node.clients:
                asyncio.create_task(
                    self.server.node.clients[node_name].send_request(b'dapi', self.name.encode() + b' ' + request))
                return b'ok', b'Request forwarded to worker node'
            else:
                raise exception.WazuhException(3022, node_name)
        else:
            return super().process_request(command, data)

    def get_nodes(self, arguments: bytes) -> Tuple[bytes, bytes]:
        return b'ok', json.dumps(self.server.node.get_connected_nodes(**json.loads(arguments.decode()))).encode()

    def get_health(self, filter_nodes: bytes) -> Tuple[bytes, bytes]:
        return b'ok', json.dumps(self.server.node.get_health(json.loads(filter_nodes))).encode()

    def send_file_request(self, path, node_name):
        if node_name not in self.server.node.clients:
            raise WazuhClusterError(3022)
        else:
            req = asyncio.create_task(self.server.node.clients[node_name].send_file(path))
            req.add_done_callback(self.get_send_file_response)
            return b'ok', b'Forwarding file to master node'


class LocalServerMaster(LocalServer):

    def __init__(self, node: server.AbstractServer, **kwargs):
        super().__init__(node=node, **kwargs)
        self.handler_class = LocalServerHandlerMaster
        self.dapi = dapi.APIRequestQueue(server=self)
        self.tasks.append(self.dapi.run)


class LocalServerHandlerWorker(LocalServerHandler):

    def process_request(self, command: bytes, data: bytes):
        self.logger.debug2("Command received: {}".format(command))
        if command == b'dapi':
            if self.server.node.client is None:
                raise WazuhClusterError(3023)
            asyncio.create_task(self.server.node.client.send_request(b'dapi', self.name.encode() + b' ' + data))
            return b'ok', b'Added request to API requests queue'
        else:
            return super().process_request(command, data)

    def get_nodes(self, arguments) -> Tuple[bytes, bytes]:
        return self.send_request_to_master(b'get_nodes', arguments)

    def get_health(self, filter_nodes) -> Tuple[bytes, bytes]:
        return self.send_request_to_master(b'get_health', filter_nodes)

    def send_request_to_master(self, command: bytes, arguments: bytes):
        if self.server.node.client is None:
            raise WazuhClusterError(3023)
        else:
            request = asyncio.create_task(self.server.node.client.send_request(command, arguments))
            request.add_done_callback(functools.partial(self.get_api_response, command))
            return b'ok', b'Sent request to master node'

    def get_api_response(self, in_command, future):
        send_res = asyncio.create_task(self.send_request(command=b'dapi_res' if in_command == b'dapi' else b'control_res',
                                                         data=future.result()))
        send_res.add_done_callback(self.send_res_callback)

    def send_file_request(self, path, node_name):
        if self.server.node.client is None:
            raise WazuhClusterError(3023)
        else:
            req = asyncio.create_task(self.server.node.client.send_file(path))
            req.add_done_callback(self.get_send_file_response)
            return b'ok', b'Forwarding file to master node'


class LocalServerWorker(LocalServer):

    def __init__(self, node: client.AbstractClientManager, **kwargs):
        super().__init__(node=node, **kwargs)
        self.handler_class = LocalServerHandlerWorker
