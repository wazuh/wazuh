# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import functools
import json
import os
import random
from typing import Tuple, Union

import uvloop
from wazuh.core import common
from wazuh.core.cluster import client, server
from wazuh.core.cluster import common as c_common
from wazuh.core.cluster.dapi import dapi
from wazuh.core.cluster.utils import context_tag
from wazuh.core.exception import WazuhClusterError


class LocalServerHandler(server.AbstractServerHandler):
    """Handle requests from a local client."""

    def connection_made(self, transport):
        """Define the process of accepting a connection.

        Parameters
        ----------
        transport : asyncio.Transport
            Socket to write data on.
        """
        self.name = str(random.SystemRandom().randint(0, 2**20 - 1))
        self.transport = transport
        self.server.clients[self.name] = self
        self.tag = 'Local ' + self.name
        # Modify filter tags with context vars.
        context_tag.set(self.tag)
        self.logger.debug('Connection received in local server.')

    def process_request(self, command: bytes, data: bytes) -> Tuple[bytes, bytes]:
        """Define commands for local servers for both worker and master nodes.

        Parameters
        ----------
        command : bytes
            Received command from client.
        data : bytes
            Received payload from client.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
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
        elif command == b'dist_orders':
            return self.distribute_orders(data)
        else:
            return super().process_request(command, data)

    def get_config(self) -> Tuple[bytes, bytes]:
        """Get active cluster configuration.

        Returns
        -------
        bytes
            Result.
        bytes
            JSON-like configuration.
        """
        return b'ok', json.dumps(self.server.configuration).encode()

    def get_node(self):
        """Get basic information about the node.

        Returns
        -------
        dict
            Basic node information.
        """
        return self.server.node.get_node()

    def get_nodes(self, filter_nodes) -> Tuple[bytes, bytes]:
        """Handle the 'get_nodes' request. It is implemented differently for master and workers.

        Parameters
        ----------
        filter_nodes : bytes
            Filters to use in the implemented method.

        Raises
        ------
        NotImplementedError
            If the method is not implemented.
        """
        raise NotImplementedError

    def get_health(self, filter_nodes) -> Tuple[bytes, bytes]:
        """Handle the 'get_health' request. It is implemented differently for masters and workers.

        Parameters
        ----------
        filter_nodes : bytes
            Filters to use in the implemented method.

        Raises
        ------
        NotImplementedError
            If the method is not implemented.
        """
        raise NotImplementedError

    def send_file_request(self, path, node_name):
        """Send a file from the API to the cluster.

        Used in API calls to update configuration or manager files. It is implemented
        differently for masters and workers.

        Parameters
        ----------
        path : str
            Path of the file to send.
        node_name : str
            Node name to send the file.

        Raises
        ------
        NotImplementedError
            If the method is not implemented.
        """
        raise NotImplementedError

    def get_send_file_response(self, future):
        """Forward the 'send_file' response to the API.

        Parameters
        ----------
        future : asyncio.Future object
            Request result.
        """
        result = future.result()
        send_res = asyncio.create_task(self.send_request(command=b'send_f_res', data=result))
        send_res.add_done_callback(self.send_res_callback)

    def send_res_callback(self, future):
        """Log result as exception if any.

        Parameters
        ----------
        future : asyncio.Future object
            Request result.
        """
        if not future.cancelled():
            exc = future.exception()
            if exc:
                self.logger.error(exc, exc_info=False)

    def distribute_orders(self, orders: bytes):
        """Send orders to the communications API unix server and to other nodes.

        Parameters
        ----------
        orders : bytes
            Orders encoded to bytes.

        Returns
        -------
        NotImplementedError
            Error indicating the method is not implemented.
        """
        raise NotImplementedError


class LocalServer(server.AbstractServer):
    """Create the server, manage multiple client connections. It's connected to the cluster TCP transports."""

    def __init__(self, node: Union[server.AbstractServer, client.AbstractClientManager], **kwargs):
        """Class constructor.

        Parameters
        ----------
        node : AbstractServer, AbstractClientManager object
            The server/worker object running in the cluster.
        kwargs
            Arguments for the parent class constructor.
        """
        super().__init__(**kwargs, tag='Local Server')
        self.node = node
        self.node.local_server = self
        self.handler_class = LocalServerHandler

    async def start(self):
        """Start the server and the necessary asynchronous tasks."""
        # Get a reference to the event loop as we plan to use low-level APIs.
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        loop = asyncio.get_running_loop()
        loop.set_exception_handler(c_common.asyncio_exception_handler)
        socket_path = common.LOCAL_SERVER_SOCKET_PATH

        try:
            local_server = await loop.create_unix_server(
                protocol_factory=lambda: self.handler_class(
                    server=self, loop=loop, logger=self.logger, server_config=self.server_config
                ),
                path=socket_path,
            )
            os.chmod(socket_path, 0o660)
        except OSError as e:
            self.logger.error(f'Could not create server: {e}')
            raise KeyboardInterrupt

        self.logger.info(f'Serving on {local_server.sockets[0].getsockname()}')

        self.tasks.append(local_server.serve_forever)

        async with local_server:
            # Use asyncio.gather to run both tasks in parallel.
            await asyncio.gather(*map(lambda x: x(), self.tasks))


class LocalServerHandlerMaster(LocalServerHandler):
    """The local server handler instance that runs in the Master node."""

    def process_request(self, command: bytes, data: bytes):
        """Define requests available in the local server.

        Parameters
        ----------
        command : bytes
            Received command from client.
        data : bytes
            Received command from client.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
        """
        context_tag.set('Local ' + self.name)

        if command == b'dapi':
            self.server.dapi.add_request(self.name.encode() + b' ' + data)
            return b'ok', b'Added request to API requests queue'
        elif command == b'dapi_fwd':
            node_name, request = data.split(b' ', 1)
            node_name = node_name.decode()
            if node_name in self.server.node.clients:
                asyncio.create_task(
                    self.log_exceptions(
                        self.server.node.clients[node_name].send_request(b'dapi', self.name.encode() + b' ' + request)
                    )
                )
                return b'ok', b'Request forwarded to worker node'
            else:
                raise WazuhClusterError(3022)
        else:
            return super().process_request(command, data)

    def get_nodes(self, arguments: bytes) -> Tuple[bytes, bytes]:
        """Implement and handles the 'get_nodes' request.

        Parameters
        ----------
        arguments : bytes
            Filter arguments from the API.

        Returns
        -------
        bytes
            Result.
        bytes
            JSON-like string containing nodes information.
        """
        return b'ok', json.dumps(self.server.node.get_connected_nodes(**json.loads(arguments.decode()))).encode()

    def get_health(self, filter_nodes: bytes) -> Tuple[bytes, bytes]:
        """Process 'get_health' request.

        Parameters
        ----------
        filter_nodes : bytes
            Whether to filter by a node or return all health information.

        Returns
        -------
        bytes
            Result.
        dict
            Dict object containing nodes information.
        """
        return b'ok', json.dumps(self.server.node.get_health(json.loads(filter_nodes))).encode()

    def send_file_request(self, path, node_name):
        """Send a file from the API to the cluster.

        Used in API calls to update configuration or manager files.

        Parameters
        ----------
        path : str
            Path of the file to send.
        node_name : str
            Node name to send the file.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
        """
        if node_name not in self.server.node.clients:
            raise WazuhClusterError(3022)
        else:
            req = asyncio.create_task(self.server.node.clients[node_name].send_file(path))
            req.add_done_callback(self.get_send_file_response)
            return b'ok', b'Forwarding file to master node'

    def distribute_orders(self, orders: bytes):
        """Send orders to the communications API unix server and to other nodes.

        Parameters
        ----------
        orders : bytes
            Orders encoded to bytes.

        Returns
        -------
        bytes
            Result.
        bytes
            JSON containing local file paths and their hash.
        """
        # Send orders to the local Comms API unix server
        asyncio.create_task(self.log_exceptions(self.send_orders(orders)))

        # Distribute orders to other nodes
        self.logger.info('Sending orders to the other nodes')
        for cl in self.server.node.clients:
            asyncio.create_task(self.log_exceptions(self.server.node.clients[cl].send_request(b'dist_orders', orders)))

        return b'ok', b'Orders forwarded to other nodes'


class LocalServerMaster(LocalServer):
    """The LocalServer object running in the master node."""

    def __init__(self, node: Union[server.AbstractServer, client.AbstractClientManager], **kwargs):
        """Class constructor.

        Parameters
        ----------
        node : AbstractServer, AbstractClientManager object
            The server/worker object running in the cluster.
        kwargs
            Arguments for the parent class constructor.
        """
        super().__init__(node=node, **kwargs)
        self.handler_class = LocalServerHandlerMaster
        self.dapi = dapi.APIRequestQueue(server=self)

        self.tasks.extend([self.dapi.run])


class LocalServerHandlerWorker(LocalServerHandler):
    """The local server handler instance that runs in worker nodes."""

    def process_request(self, command: bytes, data: bytes):
        """Define available requests in the local server.

        Parameters
        ----------
        command : bytes
            Received command from client.
        data : bytes
            Received payload from client.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
        """
        # Modify logger filter tag in LocalServerHandlerWorker entry point.
        context_tag.set('Local ' + self.name)

        self.logger.debug2(f'Command received: {command}')
        if command == b'dapi':
            if self.server.node.client is None:
                raise WazuhClusterError(3023)
            asyncio.create_task(
                self.log_exceptions(self.server.node.client.send_request(b'dapi', self.name.encode() + b' ' + data))
            )
            return b'ok', b'Added request to API requests queue'
        else:
            return super().process_request(command, data)

    def get_nodes(self, arguments) -> Tuple[bytes, bytes]:
        """Forward 'get_nodes' request to the master node.

        Parameters
        ----------
        arguments : bytes
            Filter arguments from the API.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
        """
        return self.send_request_to_master(b'get_nodes', arguments)

    def get_health(self, filter_nodes) -> Tuple[bytes, bytes]:
        """Forward 'get_health' request to the master node.

        Parameters
        ----------
        filter_nodes : bytes
             Arguments for the get health function.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
        """
        return self.send_request_to_master(b'get_health', filter_nodes)

    def send_request_to_master(self, command: bytes, arguments: bytes):
        """Forward a request to the master node.

        Parameters
        ----------
        command : bytes
            Command to forward.
        arguments : bytes
            Payload to forward.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
        """
        if self.server.node.client is None:
            raise WazuhClusterError(3023)
        else:
            request = asyncio.create_task(self.log_exceptions(self.server.node.client.send_request(command, arguments)))
            request.add_done_callback(functools.partial(self.get_api_response, command))
            return b'ok', b'Sent request to master node'

    def get_api_response(self, in_command, future):
        """Forward response sent by the master to the local client.

        Callback of the send_request_to_master method.

        Parameters
        ----------
        in_command : bytes
            Command originally sent to the master.
        future : asyncio.Future object
            Request result.
        """
        send_res = asyncio.create_task(
            self.log_exceptions(
                self.send_request(
                    command=b'dapi_res' if in_command == b'dapi' else b'control_res', data=future.result()
                )
            )
        )
        send_res.add_done_callback(self.send_res_callback)

    def send_file_request(self, path, node_name):
        """Send a file from the API to the master, which will forward it to the specified cluster node.

        Parameters
        ----------
        path : str
            Path of the file to send.
        node_name : str
            Node name to send the file.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
        """
        if self.server.node.client is None:
            raise WazuhClusterError(3023)
        else:
            req = asyncio.create_task(self.server.node.client.send_file(path))
            req.add_done_callback(self.get_send_file_response)
            return b'ok', b'Forwarding file to master node'

    def distribute_orders(self, orders: bytes):
        """Send orders to the communications API unix server and to other nodes.

        Parameters
        ----------
        orders : bytes
            Orders encoded to bytes.

        Returns
        -------
        bytes
            Result.
        bytes
            JSON containing local file paths and their hash.
        """
        # Send orders to the local Comms API unix server
        asyncio.create_task(self.log_exceptions(self.send_orders(orders)))

        if self.server.node.client is None:
            raise WazuhClusterError(3023)

        # Distribute orders to the master node
        self.logger.info('Sending orders to the master node')
        asyncio.create_task(
            self.log_exceptions(
                # Include the worker node name in the request so the server know who not to send the orders
                self.server.node.client.send_request(b'dist_orders', self.name.encode() + b' ' + orders)
            )
        )

        return b'ok', b'Orders forwarded to other nodes'


class LocalServerWorker(LocalServer):
    """The LocalServer object running in worker nodes."""

    def __init__(self, node: client.AbstractClientManager, **kwargs):
        """Class constructor.

        Parameters
        ----------
        node : AbstractClientManager object
            The worker object running in the cluster.
        kwargs
            Arguments for the parent class constructor.
        """
        super().__init__(node=node, **kwargs)
        self.handler_class = LocalServerHandlerWorker
