# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import itertools
import json
import logging
import operator
import os
import random
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from copy import copy, deepcopy
from functools import reduce
from operator import or_
from typing import Callable, Dict, Tuple

import wazuh.core.cluster.cluster
import wazuh.core.cluster.utils
import wazuh.core.manager
import wazuh.core.results as wresults
from wazuh import agent
from wazuh.cluster import get_node_wrapper, get_nodes_info
from wazuh.core import common, exception
from wazuh.core.cluster import local_client, common as c_common
from wazuh.core.exception import WazuhException, WazuhClusterError, WazuhError
from wazuh.core.wazuh_socket import wazuh_sendsync
from sqlalchemy.exc import OperationalError


class DistributedAPI:
    """Represents a distributed API request."""

    def __init__(self, f: Callable, logger: logging.getLogger, f_kwargs: Dict = None, node: c_common.Handler = None,
                 debug: bool = False, request_type: str = 'local_master', current_user: str = '',
                 wait_for_complete: bool = False, from_cluster: bool = False, is_async: bool = False,
                 broadcasting: bool = False, basic_services: tuple = None, local_client_arg: str = None,
                 rbac_permissions: Dict = None, nodes: list = None):
        """Class constructor.

        Parameters
        ----------
        f : callable
            Function to be executed.
        logger : logging.getLogger
            Logging logger to use.
        f_kwargs : dict, optional
            Arguments to be passed to function `f`. Default `None`
        node : c_common.Handler, optional
            Asyncio protocol object to use when sending requests to other nodes. Default `None`
        debug : bool, optional
            Enable debug messages and raise exceptions. Default `False`
        request_type : str, optional
            Default `"local_master"`
        wait_for_complete : bool, optional
            True to disable timeout, false otherwise. Default `False`
        from_cluster : bool, optional
            Default `False`, specify if the request goes from cluster or not
        is_async : bool, optional
            Default `False`, specify if the request is asynchronous or not
        broadcasting : bool, optional
            Default `False`, True if the request need to be executed in all managers
        basic_services : tuple, optional
            Default `None`, services that must be started for correct behaviour
        local_client_arg: str, optional
            Default `None`, LocalClient additional arguments
        rbac_permissions : dict, optional
            Default `None`, RBAC user's permissions
        nodes : list, optional
            Default `None`, list of system nodes
        current_user : str
            User who started the request
        """
        self.logger = logger
        self.f = f
        self.f_kwargs = f_kwargs if f_kwargs is not None else {}
        self.node = node if node is not None else local_client
        self.cluster_items = wazuh.core.cluster.utils.get_cluster_items() if node is None else node.cluster_items
        self.debug = debug
        self.node_info = wazuh.core.cluster.cluster.get_node() if node is None else node.get_node()
        self.request_id = str(random.randint(0, 2 ** 10 - 1))
        self.request_type = request_type
        self.wait_for_complete = wait_for_complete
        self.from_cluster = from_cluster
        self.is_async = is_async
        self.broadcasting = broadcasting
        self.rbac_permissions = rbac_permissions if rbac_permissions is not None else {'rbac_mode': 'black'}
        self.current_user = current_user
        self.nodes = nodes if nodes is not None else list()
        if not basic_services:
            self.basic_services = ('wazuh-modulesd', 'ossec-analysisd', 'ossec-execd', 'wazuh-db')
            if common.install_type != "local":
                self.basic_services += ('ossec-remoted',)
        else:
            self.basic_services = basic_services

        self.local_clients = []
        self.local_client_arg = local_client_arg
        self.threadpool = ThreadPoolExecutor(max_workers=1)

    def debug_log(self, message):
        """Use debug or debug2 depending on the log type.

        Parameters
        ----------
        message : str
            Full log message.
        """
        if self.logger.name == 'wazuh-api':
            self.logger.debug2(message)
        else:
            self.logger.debug(message)

    async def distribute_function(self) -> [Dict, exception.WazuhException]:
        """
        Distribute an API call.

        Returns
        -------
        dict or WazuhException
            Dictionary with API response or WazuhException in case of error.
        """
        try:
            if 'password' in self.f_kwargs:
                self.debug_log(f"Receiving parameters { {**self.f_kwargs, 'password': '****'} }")
            elif 'token_nbf_time' in self.f_kwargs:
                self.logger.debug(f"Decoded token {self.f_kwargs}")
            else:
                self.debug_log(f"Receiving parameters {self.f_kwargs}")

            is_dapi_enabled = self.cluster_items['distributed_api']['enabled']
            # First case: execute the request locally.
            # If the distributed api is not enabled
            # If the cluster is disabled or the request type is local_any
            # if the request was made in the master node and the request type is local_master
            # if the request came forwarded from the master node and its type is distributed_master
            if not is_dapi_enabled or self.request_type == 'local_any' or \
                    (self.request_type == 'local_master' and self.node_info['type'] == 'master') or \
                    (self.request_type == 'distributed_master' and self.from_cluster):

                response = await self.execute_local_request()

            # Second case: forward the request
            # Only the master node will forward a request, and it will only be forwarded if its type is distributed_
            # master
            elif self.request_type == 'distributed_master' and self.node_info['type'] == 'master':
                response = await self.forward_request()

            # Last case: execute the request remotely.
            # A request will only be executed remotely if it was made in a worker node and its type isn't local_any
            else:
                response = await self.execute_remote_request()

            try:
                response = json.loads(response, object_hook=c_common.as_wazuh_object) \
                    if isinstance(response, str) else response
            except json.decoder.JSONDecodeError:
                response = {'message': response}

            return response if isinstance(response, (wresults.AbstractWazuhResult, exception.WazuhException)) \
                else wresults.WazuhResult(response)

        except exception.WazuhError as e:
            e.dapi_errors = self.get_error_info(e)
            return e
        except exception.WazuhInternalError as e:
            e.dapi_errors = self.get_error_info(e)
            if self.debug:
                raise
            self.logger.error(f'{e.message}', exc_info=True)
            return e
        except Exception as e:
            if self.debug:
                raise

            self.logger.error(f'Unhandled exception: {str(e)}', exc_info=True)
            return exception.WazuhInternalError(1000,
                                                dapi_errors=self.get_error_info(e))

    def check_wazuh_status(self):
        """
        There are some services that are required for wazuh to correctly process API requests. If any of those services
        is not running, the API must raise an exception indicating that:
            * It's not ready yet to process requests if services are restarting
            * There's an error in any of those services that must be addressed before using the API if any service is
              in failed status.
            * Wazuh must be started before using the API is the services are stopped.

        The basic services wazuh needs to be running are: wazuh-modulesd, ossec-remoted, ossec-analysisd, ossec-execd
        and wazuh-db
        """
        if self.f == wazuh.core.manager.status:
            return

        status = wazuh.core.manager.status()

        not_ready_daemons = {k: status[k] for k in self.basic_services if status[k] in ('failed',
                                                                                        'restarting',
                                                                                        'stopped')}

        if not_ready_daemons:
            extra_info = {
                'node_name': self.node_info.get('node', 'UNKNOWN NODE'),
                'not_ready_daemons': ', '.join([f'{key}->{value}' for key, value in not_ready_daemons.items()])
            }
            raise exception.WazuhError(1017, extra_message=extra_info)

    async def execute_local_request(self) -> str:
        """Execute an API request locally.

        Returns
        -------
        str
            JSON response.
        """
        def run_local():
            self.debug_log("Starting to execute request locally")
            common.rbac.set(self.rbac_permissions)
            common.broadcast.set(self.broadcasting)
            common.cluster_nodes.set(self.nodes)
            common.current_user.set(self.current_user)
            data = self.f(**self.f_kwargs)
            common.reset_context_cache()
            self.debug_log("Finished executing request locally")
            return data

        try:
            before = time.time()
            self.check_wazuh_status()

            timeout = None if self.wait_for_complete \
                else self.cluster_items['intervals']['communication']['timeout_api_exe']

            # LocalClient only for control functions
            if self.local_client_arg is not None:
                lc = local_client.LocalClient()
                self.f_kwargs[self.local_client_arg] = lc
            else:
                lc = None

            if self.is_async:
                task = run_local()
            else:
                loop = asyncio.get_running_loop()
                task = loop.run_in_executor(self.threadpool, run_local)

            try:
                data = await asyncio.wait_for(task, timeout=timeout)
            except asyncio.TimeoutError:
                raise exception.WazuhInternalError(3021)
            except OperationalError:
                raise exception.WazuhInternalError(2008)

            self.debug_log(f"Time calculating request result: {time.time() - before:.3f}s")
            return data
        except (exception.WazuhError, exception.WazuhResourceNotFound) as e:
            e.dapi_errors = self.get_error_info(e)
            if self.debug:
                raise
            return json.dumps(e, cls=c_common.WazuhJSONEncoder)
        except exception.WazuhInternalError as e:
            e.dapi_errors = self.get_error_info(e)
            self.logger.error(f"{e.message}", exc_info=True)
            if self.debug:
                raise
            return json.dumps(e, cls=c_common.WazuhJSONEncoder)
        except Exception as e:
            self.logger.error(f'Error executing API request locally: {str(e)}', exc_info=True)
            if self.debug:
                raise
            return json.dumps(exception.WazuhInternalError(1000,
                                                           dapi_errors=self.get_error_info(e)),
                              cls=c_common.WazuhJSONEncoder)

    def get_client(self) -> c_common.Handler:
        """
        Create another LocalClient if necessary and stores it to be closed later.

        :return: client. Maybe an instance of LocalClient, WorkerHandler or MasterHandler
        """
        if self.node == local_client:
            client = local_client.LocalClient()
            self.local_clients.append(client)
        else:
            client = self.node

        return client

    def to_dict(self):
        return {"f": self.f,
                "f_kwargs": self.f_kwargs,
                "request_type": self.request_type,
                "wait_for_complete": self.wait_for_complete,
                "from_cluster": self.from_cluster,
                "is_async": self.is_async,
                "local_client_arg": self.local_client_arg,
                "basic_services": self.basic_services,
                "rbac_permissions": self.rbac_permissions,
                "current_user": self.current_user,
                "broadcasting": self.broadcasting,
                "nodes": self.nodes
                }

    def get_error_info(self, e) -> Dict:
        """Build a response given an Exception.

        Parameters
        ----------
        e : Exception

        Returns
        -------
        dict
            Dict where keys are nodes and values are error information.
        """
        try:
            common.rbac.set(self.rbac_permissions)
            node_wrapper = get_node_wrapper()
            node = node_wrapper.affected_items[0]['node']
        except exception.WazuhException as rbac_exception:
            if rbac_exception.code == 4000:
                node = 'unknown-node'
            else:
                raise rbac_exception
        except IndexError:
            raise list(node_wrapper.failed_items.keys())[0]

        error_message = e.message if isinstance(e, exception.WazuhException) else exception.GENERIC_ERROR_MSG
        result = {node: {'error': error_message}
                  }

        # Give log path only in case of WazuhInternalError
        if not isinstance(e, exception.WazuhError):
            log_filename = None
            for h in self.logger.handlers or self.logger.parent.handlers:
                if hasattr(h, 'baseFilename'):
                    log_filename = os.path.join('WAZUH_HOME', os.path.relpath(h.baseFilename, start=common.ossec_path))
            result[node]['logfile'] = log_filename

        return result

    async def send_tmp_file(self, node_name=None):
        # POST/agent/group/:group_id/configuration and POST/agent/group/:group_id/file/:file_name API calls write
        # a temporary file in /var/ossec/tmp which needs to be sent to the master before forwarding the request
        client = self.get_client()
        res = json.loads(await client.send_file(os.path.join(common.ossec_path,
                                                             self.f_kwargs['tmp_file']),
                                                node_name),
                         object_hook=c_common.as_wazuh_object)
        os.remove(os.path.join(common.ossec_path, self.f_kwargs['tmp_file']))

    async def execute_remote_request(self) -> Dict:
        """Execute a remote request. This function is used by worker nodes to execute master_only API requests.

        Returns
        -------
        dict
            JSON response.
        """
        if 'tmp_file' in self.f_kwargs:
            await self.send_tmp_file()

        client = self.get_client()
        node_response = await client.execute(command=b'dapi',
                                             data=json.dumps(self.to_dict(),
                                                             cls=c_common.WazuhJSONEncoder).encode(),
                                             wait_for_complete=self.wait_for_complete)

        return json.loads(node_response,
                          object_hook=c_common.as_wazuh_object)

    async def forward_request(self) -> [wresults.AbstractWazuhResult, exception.WazuhException]:
        """Forward a request to the node who has all available information to answer it.

        This function is called when a distributed_master function is used. Only the master node calls this function.
        An API request will only be forwarded to worker nodes.

        Returns
        -------
        wresults.AbstractWazuhResult or exception.WazuhException
        """

        async def forward(node_name: Tuple) -> [wresults.AbstractWazuhResult, exception.WazuhException]:
            """Forward a request to a node.

            Parameters
            ----------
            node_name : tuple
                Node to forward a request to.

            Returns
            -------
            wresults.AbstractWazuhResult or exception.WazuhException
            """
            node_name, agent_list = node_name
            if agent_list:
                self.f_kwargs['agent_id' if 'agent_id' in self.f_kwargs else 'agent_list'] = agent_list
            if node_name == 'unknown' or node_name == '' or node_name == self.node_info['node']:
                # The request will be executed locally if the the node to forward to is unknown, empty or the master
                # itself
                result = await self.distribute_function()
            else:
                if 'tmp_file' in self.f_kwargs:
                    await self.send_tmp_file(node_name)
                client = self.get_client()
                try:
                    result = json.loads(await client.execute(b'dapi_forward',
                                                             "{} {}".format(node_name,
                                                                            json.dumps(self.to_dict(),
                                                                                       cls=c_common.WazuhJSONEncoder)
                                                                            ).encode(),
                                                             self.wait_for_complete),
                                        object_hook=c_common.as_wazuh_object)
                except WazuhClusterError as e:
                    if e.code == 3022:
                        result = e
                    else:
                        raise e
                # Convert a non existing node into a WazuhError exception
                if isinstance(result, WazuhClusterError) and result.code == 3022:
                    common.rbac.set(self.rbac_permissions)
                    try:
                        await get_nodes_info(client, filter_node=[node_name])
                    except WazuhError as e:
                        if e.code == 4000:
                            result = e
                    dikt = result.to_dict()
                    # Add node ID to error message
                    dikt['ids'] = {node_name}
                    result = WazuhError.from_dict(dikt)

            return result if isinstance(result, (wresults.AbstractWazuhResult, exception.WazuhException)) \
                else wresults.WazuhResult(result)

        # get the node(s) who has all available information to answer the request.
        nodes = await self.get_solver_node()
        self.from_cluster = True
        common.rbac.set(self.rbac_permissions)
        common.cluster_nodes.set(self.nodes)
        common.broadcast.set(self.broadcasting)
        if 'node_id' in self.f_kwargs or 'node_list' in self.f_kwargs:
            # Check cluster:read permissions for each node
            filter_node_kwarg = {'filter_node': list(nodes)} if nodes else {}
            allowed_nodes = await get_nodes_info(self.get_client(), **filter_node_kwarg)

            valid_nodes = list()
            if not nodes:
                nodes = {node_name['name']: [] for node_name in allowed_nodes.affected_items}
            for node in nodes.items():
                if node[0] in [node_name['name'] for node_name in allowed_nodes.affected_items] or node[0] == 'unknown':
                    valid_nodes.append(node)
            del self.f_kwargs['node_id' if 'node_id' in self.f_kwargs else 'node_list']
        else:
            if nodes:
                valid_nodes = list(nodes.items())
            else:
                broadcasted_nodes = await get_nodes_info(self.get_client())
                valid_nodes = [(n['name'], []) for n in broadcasted_nodes.affected_items]
            allowed_nodes = wresults.AffectedItemsWazuhResult()
            allowed_nodes.affected_items = list(nodes)
            allowed_nodes.total_affected_items = len(allowed_nodes.affected_items)
        response = await asyncio.shield(asyncio.gather(*[forward(node) for node in valid_nodes]))

        if allowed_nodes.total_affected_items > 1:
            response = reduce(or_, response)
            if isinstance(response, wresults.AbstractWazuhResult):
                response = response.limit(limit=self.f_kwargs.get('limit', common.database_limit),
                                          offset=self.f_kwargs.get('offset', 0)) \
                    .sort(fields=self.f_kwargs.get('fields', []),
                          order=self.f_kwargs.get('order', 'asc'))
        elif response:
            response = response[0]
        else:
            response = deepcopy(allowed_nodes)

        # It might be a WazuhError after reducing
        if isinstance(response, wresults.AffectedItemsWazuhResult):
            for failed in copy(allowed_nodes.failed_items):
                # Avoid errors coming from 'unknown' node (they are included in the forward)
                if allowed_nodes.failed_items[failed] == {'unknown'}:
                    del allowed_nodes.failed_items[failed]
            response.add_failed_items_from(allowed_nodes)

        return response

    async def get_solver_node(self) -> Dict:
        """Get the node(s) that can solve a request.

        Get the node(s) that have all the necessary information to answer the request. Only called when the request type
        is 'master_distributed' and the node_type is master.

        Returns
        -------
        dict
            Dict with node names with agents.
        """
        select_node = ['node_name']
        if 'agent_id' in self.f_kwargs or 'agent_list' in self.f_kwargs:
            # Group requested agents by node_name
            requested_agents = self.f_kwargs.get('agent_list', None) or [self.f_kwargs['agent_id']]
            # Filter by node_name if we receive a node_id
            if 'node_id' in self.f_kwargs:
                requested_nodes = self.f_kwargs.get('node_list', None) or [self.f_kwargs['node_id']]
                filters = {'node_name': requested_nodes}
            elif requested_agents != '*':
                filters = {'id': requested_agents}
            else:
                filters = None

            system_agents = agent.Agent.get_agents_overview(select=select_node,
                                                            limit=None,
                                                            filters=filters)['items']
            node_name = defaultdict(list)
            for element in system_agents:
                node_name[element.get('node_name', '')].append(element['id'])

            # Update node_name in case it is empty or a node has no agents
            if 'node_id' in self.f_kwargs:
                if self.f_kwargs['node_id'] not in node_name:
                    node_name.update({self.f_kwargs['node_id']: []})

            if requested_agents != '*':  # When all agents are requested cannot be non existent ids
                # Add non existing ids in the master's dictionary entry
                non_existent_ids = list(set(requested_agents) - set(map(operator.itemgetter('id'), system_agents)))
                if non_existent_ids:
                    if self.node_info['node'] in node_name:
                        node_name[self.node_info['node']].extend(non_existent_ids)
                    else:
                        node_name[self.node_info['node']] = non_existent_ids

            return node_name

        elif 'node_id' in self.f_kwargs or ('node_list' in self.f_kwargs and self.f_kwargs['node_list'] != '*'):
            requested_nodes = self.f_kwargs.get('node_list', None) or [self.f_kwargs['node_id']]
            return {node_id: [] for node_id in requested_nodes}

        elif 'group_id' in self.f_kwargs:
            common.rbac.set(self.rbac_permissions)
            agents = agent.get_agents_in_group(group_list=[self.f_kwargs['group_id']], select=select_node,
                                               sort={'fields': ['node_name'], 'order': 'desc'}).affected_items
            if len(agents) == 0:
                raise WazuhError(1755)
            del self.f_kwargs['group_id']
            node_name = {k: list(map(operator.itemgetter('id'), g)) for k, g in
                         itertools.groupby(agents, key=operator.itemgetter('node_name'))}

            return node_name

        else:
            if self.broadcasting:
                node_name = {}
            else:
                # agents, syscheck and syscollector
                # API calls that affect all agents. For example, PUT/agents/restart, etc...
                agents = agent.Agent.get_agents_overview(select=select_node, limit=None,
                                                         sort={'fields': ['node_name'], 'order': 'desc'})['items']
                node_name = {k: [] for k, _ in itertools.groupby(agents, key=operator.itemgetter('node_name'))}
            return node_name


class WazuhRequestQueue:
    """Represents a queue of Wazuh requests"""
    def __init__(self, server):
        self.request_queue = asyncio.Queue()
        self.server = server
        self.pending_requests = {}

    def add_request(self, request: bytes):
        """Add a request to the queue.

        Parameters
        ----------
        request : bytes
            Request to add.
        """
        self.logger.debug(f"Received request: {request}")
        self.request_queue.put_nowait(request.decode())


class APIRequestQueue(WazuhRequestQueue):
    """
    Represents a queue of API requests. This thread will be always in background, it will remain blocked until a
    request is pushed into its request_queue. Then, it will answer the request and get blocked again.
    """

    def __init__(self, server):
        super().__init__(server)
        self.logger = logging.getLogger('wazuh').getChild('dapi')
        self.logger.addFilter(wazuh.core.cluster.utils.ClusterFilter(tag='Cluster', subtag='D API'))

    async def run(self):
        while True:
            names, request = (await self.request_queue.get()).split(' ', 1)
            names = names.split('*', 1)
            # name    -> node name the request must be sent to. None if called from a worker node.
            # id      -> id of the request.
            # request -> JSON containing request's necessary information
            name_2 = '' if len(names) == 1 else names[1] + ' '

            # Get reference to MasterHandler or WorkerHandler
            try:
                node = self.server.client if names[0] == 'master' else self.server.clients[names[0]]
            except KeyError as e:
                self.logger.error(f"Error in DAPI request. The destination node is not connected or does not exist: {e}.")
                continue

            try:
                request = json.loads(request, object_hook=c_common.as_wazuh_object)
                self.logger.info("Receiving request: {} from {}".format(
                    request['f'].__name__, names[0] if not name_2 else '{} ({})'.format(names[0], names[1])))
                result = await DistributedAPI(**request,
                                              logger=self.logger,
                                              node=node).distribute_function()
                task_id = await node.send_string(json.dumps(result, cls=c_common.WazuhJSONEncoder).encode())
            except Exception as e:
                self.logger.error(f"Error in distributed API: {e}", exc_info=True)
                task_id = b'Error in distributed API: ' + str(e).encode()

            if task_id.startswith(b'Error'):
                self.logger.error(task_id.decode())
                result = await node.send_request(b'dapi_err', name_2.encode() + task_id)
            else:
                result = await node.send_request(b'dapi_res', name_2.encode() + task_id)
            if not isinstance(result, WazuhException):
                if result.startswith(b'Error'):
                    self.logger.error(result.decode())
            else:
                self.logger.error(result.message)


class SendSyncRequestQueue(WazuhRequestQueue):
    """
    Represents a queue of SSync requests. This thread will be always in background, it will remain blocked until a
    request is pushed into its request_queue. Then, it will answer the request and get blocked again.
    """

    def __init__(self, server):
        super().__init__(server)
        self.logger = logging.getLogger('wazuh').getChild('sendsync')
        self.logger.addFilter(wazuh.core.cluster.utils.ClusterFilter(tag='Cluster', subtag='SendSync'))

    async def run(self):
        while True:
            names, request = (await self.request_queue.get()).split(' ', 1)
            names = names.split('*', 1)
            # name    -> node name the request must be sent to. None if called from a worker node.
            # id      -> id of the request.
            # request -> JSON containing request's necessary information
            name_2 = '' if len(names) == 1 else names[1] + ' '

            try:
                node = self.server.clients[names[0]]
            except KeyError as e:
                self.logger.error(f"Error in Sendsync. The destination node is not connected or does not exist: {e}.")
                continue

            try:
                request = json.loads(request, object_hook=c_common.as_wazuh_object)
                self.logger.debug(f"Receiving SendSync request ({request['daemon_name']}) from {names[0]} ({names[1]})")
                result = await wazuh_sendsync(**request)
                task_id = await node.send_string(result.encode())
            except Exception as e:
                self.logger.error(f"Error in SendSync: {e}", exc_info=True)
                task_id = b'Error in SendSync: ' + str(e).encode()

            if task_id.startswith(b'Error'):
                self.logger.error(task_id.decode())
                result = await node.send_request(b'sendsync_err', name_2.encode() + task_id)
            else:
                result = await node.send_request(b'sendsync_res', name_2.encode() + task_id)
            if isinstance(result, WazuhException):
                self.logger.error(result.message)
