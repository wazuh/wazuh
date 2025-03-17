# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import contextlib
import itertools
import json
import logging
import operator
import os
import time
from collections import defaultdict
from concurrent.futures import process, ProcessPoolExecutor
from copy import copy, deepcopy
from functools import reduce, partial
from operator import or_
from typing import Callable, Dict, Tuple, List

from sqlalchemy.exc import OperationalError

import api.configuration as aconf
import wazuh.core.cluster.cluster
import wazuh.core.cluster.utils
import wazuh.core.manager
import wazuh.core.results as wresults
from wazuh import agent
from wazuh.cluster import get_node_wrapper, get_nodes_info
from wazuh.core import common, exception
from wazuh.core.cluster import local_client, common as c_common
from wazuh.core.cluster.cluster import check_cluster_status
from wazuh.core.exception import WazuhException, WazuhClusterError, WazuhError
from wazuh.core.wazuh_socket import wazuh_sendsync


authentication_funcs = {'check_token', 'check_user_master', 'get_permissions', 'get_security_conf'}
events_funcs = {'send_event_to_analysisd'}

node_info = wazuh.core.cluster.cluster.get_node()
pools = common.mp_pools.get()
if node_info['type'] == 'master':
    # Suppress exception when the user running Wazuh cannot access /dev/shm.
    with contextlib.suppress(FileNotFoundError, PermissionError):
        pools.update({'authentication_pool': ProcessPoolExecutor(
            max_workers=wazuh.core.cluster.utils.get_cluster_items()['intervals']['master']['authentication_pool_size'],
            initializer=wazuh.core.cluster.utils.init_auth_worker
        )})


class DistributedAPI:
    """Represents a distributed API request."""

    def __init__(self, f: Callable, logger: logging.getLogger, f_kwargs: Dict = None, node: c_common.Handler = None,
                 debug: bool = False, request_type: str = 'local_master', current_user: str = '',
                 wait_for_complete: bool = False, from_cluster: bool = False, is_async: bool = False,
                 broadcasting: bool = False, basic_services: tuple = None, local_client_arg: str = None,
                 rbac_permissions: Dict = None, nodes: list = None, api_timeout: int = None,
                 remove_denied_nodes: bool = False):
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
        api_timeout : int
            Timeout set in source API for the request
        remove_denied_nodes : bool
            Whether to remove denied (RBAC) nodes from response's failed items or not.
        """
        self.logger = logger
        self.f = f
        self.f_kwargs = f_kwargs if f_kwargs is not None else {}
        self.node = node if node is not None else local_client
        self.cluster_items = wazuh.core.cluster.utils.get_cluster_items() if node is None else node.cluster_items
        self.debug = debug
        self.node_info = node_info if node is None else node.get_node()
        self.request_type = request_type
        self.wait_for_complete = wait_for_complete
        self.from_cluster = from_cluster
        self.is_async = is_async
        self.broadcasting = broadcasting
        self.rbac_permissions = rbac_permissions if rbac_permissions is not None else {'rbac_mode': 'black'}
        self.current_user = current_user
        self.origin_module = 'API'
        self.nodes = nodes if nodes is not None else list()
        if not basic_services:
            self.basic_services = ('wazuh-modulesd', 'wazuh-analysisd', 'wazuh-execd', 'wazuh-db', 'wazuh-remoted')
        else:
            self.basic_services = basic_services

        self.local_clients = []
        self.local_client_arg = local_client_arg
        self.api_request_timeout = max(api_timeout, aconf.api_conf['intervals']['request_timeout']) \
            if api_timeout else aconf.api_conf['intervals']['request_timeout']
        self.remove_denied_nodes = remove_denied_nodes

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
            is_cluster_disabled = self.node == local_client and not check_cluster_status()

            # First case: execute the request locally.
            # If the distributed api is not enabled
            # If the cluster is disabled or the request type is local_any
            # if the request was made in the master node and the request type is local_master
            # if the request came forwarded from the master node and its type is distributed_master
            if not is_dapi_enabled or is_cluster_disabled or self.request_type == 'local_any' or \
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

        except json.decoder.JSONDecodeError:
            e = exception.WazuhInternalError(3036)
            e.dapi_errors = self.get_error_info(e)
            if self.debug:
                raise
            self.logger.error(f"{e.message}")
            return e
        except exception.WazuhInternalError as e:
            e.dapi_errors = self.get_error_info(e)
            if self.debug:
                raise
            self.logger.error(f"{e.message}", exc_info=not isinstance(e, exception.WazuhClusterError))
            return e
        except exception.WazuhError as e:
            e.dapi_errors = self.get_error_info(e)
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

        The basic services wazuh needs to be running are: wazuh-modulesd, wazuh-remoted, wazuh-analysisd, wazuh-execd
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
            raise exception.WazuhInternalError(1017, extra_message=extra_info)

    @staticmethod
    def run_local(f, f_kwargs, rbac_permissions, broadcasting, nodes, current_user, origin_module):
        """Run framework SDK function locally in another process."""
        common.rbac.set(rbac_permissions)
        common.broadcast.set(broadcasting)
        common.cluster_nodes.set(nodes)
        common.current_user.set(current_user)
        common.origin_module.set(origin_module)
        data = f(**f_kwargs)
        common.reset_context_cache()
        return data

    async def execute_local_request(self) -> str:
        """Execute an API request locally.

        Returns
        -------
        str
            JSON response.
        """
        try:
            if self.f_kwargs.get('agent_list') == '*':
                del self.f_kwargs['agent_list']

            before = time.time()
            self.check_wazuh_status()

            timeout = self.api_request_timeout if not self.wait_for_complete else None

            # LocalClient only for control functions
            if self.local_client_arg is not None:
                lc = local_client.LocalClient()
                self.f_kwargs[self.local_client_arg] = lc
            try:
                if self.is_async:
                    task = self.run_local(self.f, self.f_kwargs, self.rbac_permissions, self.broadcasting,
                                          self.nodes, self.current_user, self.origin_module)

                else:
                    loop = asyncio.get_event_loop()
                    if 'thread_pool' in pools:
                        pool = pools.get('thread_pool')
                    elif self.f.__name__ in authentication_funcs:
                        pool = pools.get('authentication_pool')
                    elif self.f.__name__ in events_funcs:
                        pool = pools.get('events_pool')
                    else:
                        pool = pools.get('process_pool')

                    task = loop.run_in_executor(pool, partial(self.run_local, self.f, self.f_kwargs,
                                                              self.rbac_permissions, self.broadcasting, self.nodes,
                                                              self.current_user, self.origin_module))
                try:
                    self.debug_log("Starting to execute request locally")
                    data = await asyncio.wait_for(task, timeout=timeout)
                    self.debug_log("Finished executing request locally")
                except asyncio.TimeoutError:
                    raise exception.WazuhInternalError(3021)
                except OperationalError as exc:
                    raise exception.WazuhInternalError(2008, extra_message=str(exc.orig))
                except process.BrokenProcessPool:
                    raise exception.WazuhInternalError(901)
            except json.decoder.JSONDecodeError:
                raise exception.WazuhInternalError(3036)
            except process.BrokenProcessPool:
                raise exception.WazuhInternalError(900)

            self.debug_log(f"Time calculating request ({self.f.__name__}) result: {time.time() - before:.3f}s")
            return data
        except exception.WazuhInternalError as e:
            e.dapi_errors = self.get_error_info(e)
            # Avoid exception info if it is an asyncio timeout error, JSONDecodeError, /proc availability error or
            # WazuhClusterError
            self.logger.error(f"{e.message}",
                              exc_info=e.code not in {3021, 3036, 1913, 1017} and not isinstance(e,
                                                                                           exception.WazuhClusterError))
            if self.debug:
                raise
            return json.dumps(e, cls=c_common.WazuhJSONEncoder)
        except (exception.WazuhError, exception.WazuhResourceNotFound) as e:
            e.dapi_errors = self.get_error_info(e)
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
                "nodes": self.nodes,
                "api_timeout": self.api_request_timeout
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
        if isinstance(e, exception.WazuhInternalError):
            log_filename = None
            for h in self.logger.handlers or self.logger.parent.handlers:
                if hasattr(h, 'baseFilename'):
                    log_filename = os.path.join('WAZUH_HOME', os.path.relpath(h.baseFilename, start=common.WAZUH_PATH))
            result[node]['logfile'] = log_filename

        return result

    async def send_tmp_file(self, node_name=None):
        # POST/agent/group/:group_id/configuration and POST/agent/group/:group_id/file/:file_name API calls write
        # a temporary file in /var/ossec/tmp which needs to be sent to the master before forwarding the request
        client = self.get_client()
        res = json.loads(await client.send_file(os.path.join(common.WAZUH_PATH,
                                                             self.f_kwargs['tmp_file']),
                                                node_name),
                         object_hook=c_common.as_wazuh_object)
        os.remove(os.path.join(common.WAZUH_PATH, self.f_kwargs['tmp_file']))

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
                                                             cls=c_common.WazuhJSONEncoder).encode())
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
            if node_name == self.node_info['node']:
                # The request will be executed locally if the the node to forward to is unknown, empty or the master
                # itself
                if agent_list is not None and set(self.f_kwargs) & {'agent_id', 'agent_list'}:
                    self.f_kwargs['agent_id' if 'agent_id' in self.f_kwargs else 'agent_list'] = agent_list
                result = await self.distribute_function()
            else:
                if 'tmp_file' in self.f_kwargs:
                    await self.send_tmp_file(node_name)
                client = self.get_client()
                try:
                    kcopy = deepcopy(self.to_dict())
                    if agent_list is not None and set(self.f_kwargs) & {'agent_id', 'agent_list'}:
                        kcopy['f_kwargs']['agent_id' if 'agent_id' in kcopy['f_kwargs'] else 'agent_list'] = agent_list

                    result = json.loads(await client.execute(b'dapi_fwd',
                                                             "{} {}".format(node_name,
                                                                            json.dumps(kcopy,
                                                                                       cls=c_common.WazuhJSONEncoder)
                                                                            ).encode()
                                                             ),
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

        async def clean_valid_nodes(nodes_to_clean: List[Tuple]) -> List[Tuple]:
            """Clean nodes response to forward only to real nodes in a single petition for each one.

            Parameters
            ----------
            nodes_to_clean : list
                List of nodes to clean.

            Returns
            -------
            list
                Cleaned list of nodes.
            """
            # We run through the list of nodes to find unknown and '' entries
            indexes_to_delete = set()
            myself_index = None
            for i, node in enumerate(nodes_to_clean):
                if node[0] == 'unknown' or node[0] == '' or node[0] is None:
                    indexes_to_delete.add(i)
                if node[0] == self.node_info['node']:
                    myself_index = i

            # We add found entries to local node and remove them from the list of tuples
            if myself_index is None and indexes_to_delete:
                nodes_to_clean.append((self.node_info['node'], list()))
                for index in indexes_to_delete:
                    nodes_to_clean[-1][1].extend(nodes_to_clean[index][1])
            elif myself_index is not None and indexes_to_delete:
                for index in indexes_to_delete:
                    nodes_to_clean[myself_index][1].extend(nodes_to_clean[index][1])

            return [node for i, node in enumerate(nodes_to_clean) if i not in indexes_to_delete]

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

        cleaned_valid_nodes = await clean_valid_nodes(valid_nodes)

        response = await asyncio.shield(asyncio.gather(*[forward(node) for node in cleaned_valid_nodes]))

        if allowed_nodes.total_affected_items > 1:
            response = reduce(or_, response)
            if isinstance(response, wresults.AbstractWazuhResult):
                response = response.limit(limit=self.f_kwargs.get('limit', common.DATABASE_LIMIT),
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
                if allowed_nodes.failed_items[failed] == {'unknown'} or \
                        (failed.code == 4000 and self.remove_denied_nodes):
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
                self.logger.error(
                    f"Error in DAPI request. The destination node is not connected or does not exist: {e}.")
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
                with contextlib.suppress(Exception):
                    await node.send_request(b"dapi_err", f"{name_2}{str(e)}".encode())
            else:
                try:
                    await node.send_request(b"dapi_res", name_2.encode() + task_id)
                except WazuhException as e:
                    self.logger.error(e.message, exc_info=False)


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
                self.logger.error(f"Error in SendSync (parameters {request}): {str(e)}", exc_info=False)
                with contextlib.suppress(Exception):
                    await node.send_request(b"sendsyn_err", f"{name_2}{str(e)}".encode())
            else:
                try:
                    await node.send_request(b"sendsyn_res", name_2.encode() + task_id)
                except WazuhException as e:
                    self.logger.error(e.message, exc_info=False)
