# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import functools
import itertools
import json
import operator
import random
from typing import Dict, Union, Tuple
from wazuh.cluster import local_client, cluster, common as c_common
from wazuh.cluster.dapi import requests_list as rq
from wazuh import exception, agent, common, utils
from wazuh import manager
import logging
import os
import time
import copy
from wazuh.exception import WazuhException

class DistributedAPI:
    """
    Represents a distributed API request
    """
    def __init__(self, input_json: Dict, logger: logging.Logger, node: c_common.Handler = None, debug: bool = False,
                 pretty: bool = False):
        """
        Class constructor

        :param input_json: JSON containing information/arguments about the request.
        :param logger: Logging logger to use
        :param node: Asyncio protocol object to use when sending requests to other nodes
        :param debug: Enable debug messages and raise exceptions.
        :param pretty: Return request result with pretty indent
        """
        self.logger = logger
        self.input_json = input_json
        self.node = node if node is not None else local_client
        self.cluster_items = cluster.get_cluster_items() if node is None else node.cluster_items
        self.debug = debug
        self.pretty = pretty
        self.node_info = cluster.get_node() if node is None else node.get_node()
        self.request_id = str(random.randint(0, 2**10 - 1))

    async def distribute_function(self) -> str:
        """
        Distributes an API call

        :return: Dictionary with API response
        """
        try:
            request_type = rq.functions[self.input_json['function']]['type']
            is_dapi_enabled = self.cluster_items['distributed_api']['enabled']
            is_cluster_disabled = self.node == local_client and cluster.check_cluster_status()

            if 'wait_for_complete' not in self.input_json['arguments']:
                self.input_json['arguments']['wait_for_complete'] = False

            # if it is a cluster API request and the cluster is not enabled, raise an exception
            if is_cluster_disabled and 'cluster' in self.input_json['function'] and \
                    self.input_json['function'] != '/cluster/status' and \
                    self.input_json['function'] != '/cluster/config' and \
                    self.input_json['function'] != '/cluster/node':
                raise exception.WazuhException(3013)

            # First case: execute the request local.
            # If the distributed api is not enabled
            # If the cluster is disabled or the request type is local_any
            # if the request was made in the master node and the request type is local_master
            # if the request came forwarded from the master node and its type is distributed_master
            if not is_dapi_enabled or is_cluster_disabled or request_type == 'local_any' or \
                    (request_type == 'local_master' and self.node_info['type'] == 'master') or \
                    (request_type == 'distributed_master' and self.input_json['from_cluster']):

                return await self.execute_local_request()

            # Second case: forward the request
            # Only the master node will forward a request, and it will only be forwarded if its type is distributed_
            # master
            elif request_type == 'distributed_master' and self.node_info['type'] == 'master':
                return await self.forward_request()

            # Last case: execute the request remotely.
            # A request will only be executed remotely if it was made in a worker node and its type isn't local_any
            else:
                return await self.execute_remote_request()
        except exception.WazuhException as e:
            if self.debug:
                raise
            return self.print_json(data=e.message, error=e.code)
        except Exception as e:
            if self.debug:
                raise
            return self.print_json(data=str(e), error=1000)

    def check_wazuh_status(self, basic_services=None):
        """
        There are some services that are required for wazuh to correctly process API requests. If any of those services
        is not running, the API must raise an exception indicating that:
            * It's not ready yet to process requests if services are restarting
            * There's an error in any of those services that must be adressed before using the API if any service is
              in failed status.
            * Wazuh must be started before using the API is the services are stopped.

        The basic services wazuh needs to be running are: wazuh-modulesd, ossec-remoted, ossec-analysisd, ossec-execd and wazuh-db
        """
        if self.input_json['function'] == '/manager/status' or self.input_json['function'] == '/cluster/:node_id/status':
            return

        if not basic_services:
            basic_services = ('wazuh-modulesd', 'ossec-analysisd', 'ossec-execd', 'wazuh-db')
            if common.install_type != "local":
                basic_services += ('ossec-remoted', )

        status = manager.status()

        not_ready_daemons = {k: status[k] for k in basic_services if status[k] in ('failed', 'restarting', 'stopped')}

        if not_ready_daemons:
            extra_info = {'node_name': self.node_info.get('node', 'UNKNOWN NODE'),
                          'not_ready_daemons': ', '.join([f'{key}->{value}' for key, value in not_ready_daemons.items()])}
            raise exception.WazuhException(1017, extra_message=extra_info)

    def print_json(self, data: Union[Dict, str], error: int = 0) -> str:
        def encode_json(o):
            try:
                return getattr(o, 'to_dict')()
            except AttributeError as e:
                self.print_json(error=1000, data="Wazuh-Python Internal Error: data encoding unknown ({})".format(e))

        output = {'message' if error else 'data': data, 'error': error}
        return json.dumps(obj=output, default=encode_json, indent=4 if self.pretty else None)

    async def execute_local_request(self) -> str:
        """
        Executes an API request locally.

        :return: a JSON response.
        """
        def run_local(args):
            self.logger.debug("Starting to execute request locally")
            data = rq.functions[self.input_json['function']]['function'](**args)
            self.logger.debug("Finished executing request locally")
            return data
        try:
            before = time.time()

            self.check_wazuh_status(basic_services=rq.functions[self.input_json['function']].get('basic_services',
                                                                                                 None)
                                    )

            timeout = None if self.input_json['arguments']['wait_for_complete'] \
                else self.cluster_items['intervals']['communication']['timeout_api_exe']
            local_args = copy.deepcopy(self.input_json['arguments'])
            del local_args['wait_for_complete']  # local requests don't use this parameter

            if rq.functions[self.input_json['function']]['is_async']:
                task = run_local(local_args)
            else:
                loop = asyncio.get_running_loop()
                task = loop.run_in_executor(None, functools.partial(run_local, local_args))

            try:
                data = await asyncio.wait_for(task, timeout=timeout)
            except asyncio.TimeoutError:
                raise exception.WazuhException(3021)

            after = time.time()
            self.logger.debug("Time calculating request result: {}s".format(after - before))
            return self.print_json(data=data, error=0)
        except exception.WazuhException as e:
            if self.debug:
                raise
            return self.print_json(data=e.message, error=e.code)
        except Exception as e:
            self.logger.error("Error executing API request locally: {}".format(e))
            if self.debug:
                raise
            return self.print_json(data=str(e), error=1000)

    async def send_tmp_file(self, node_name=None):
        # POST/agent/group/:group_id/configuration and POST/agent/group/:group_id/file/:file_name API calls write
        # a temporary file in /var/ossec/tmp which needs to be sent to the master before forwarding the request
        res = await self.node.send_file(os.path.join(common.ossec_path, self.input_json['arguments']['tmp_file']), node_name)
        os.remove(os.path.join(common.ossec_path, self.input_json['arguments']['tmp_file']))
        if res.startswith(b'Error'):
            return self.print_json(data=res.decode(), error=1000)

    async def execute_remote_request(self) -> str:
        """
        Executes a remote request. This function is used by worker nodes to execute master_only API requests.

        :return: JSON response
        """
        if 'tmp_file' in self.input_json['arguments']:
            await self.send_tmp_file()
        return await self.node.execute(command=b'dapi', data=json.dumps(self.input_json).encode(),
                                       wait_for_complete=self.input_json['arguments']['wait_for_complete'])

    async def forward_request(self):
        """
        Forwards a request to the node who has all available information to answer it. This function is called when a
        distributed_master function is used. Only the master node calls this function. An API request will only be
        forwarded to worker nodes.

        :return: a JSON response.
        """
        async def forward(node_name: Tuple) -> str:
            """
            Forwards a request to a node.
            :param node_name: Node to forward a request to.
            :return: a JSON response
            """
            node_name, agent_id = node_name
            if agent_id and ('agent_id' not in self.input_json['arguments'] or isinstance(self.input_json['arguments']['agent_id'], list)):
                self.input_json['arguments']['agent_id'] = agent_id
            if node_name == 'unknown' or node_name == '' or node_name == self.node_info['node']:
                # The request will be executed locally if the the node to forward to is unknown, empty or the master
                # itself
                response = await self.distribute_function()
            else:
                if 'tmp_file' in self.input_json['arguments']:
                    await self.send_tmp_file(node_name)
                response = await self.node.execute(b'dapi_forward',
                                                   "{} {}".format(node_name, json.dumps(self.input_json)).encode(),
                                                   self.input_json['arguments']['wait_for_complete'])
            return response

        # get the node(s) who has all available information to answer the request.
        nodes = self.get_solver_node()
        self.input_json['from_cluster'] = True
        if len(nodes) > 1:
            results = map(json.loads, await asyncio.shield(asyncio.gather(*[forward(node) for node in nodes.items()])))
            final_json = {}
            response = json.dumps(self.merge_results(results, final_json))
        else:
            response = await forward(next(iter(nodes.items())))
        return response

    def get_solver_node(self) -> Dict:
        """
        Gets the node(s) that can solve a request, the node(s) that has all the necessary information to answer it.
        Only called when the request type is 'master_distributed' and the node_type is master.

        :return: node name and whether the result is list or not
        """
        select_node = {'fields': ['node_name']}
        if 'agent_id' in self.input_json['arguments']:
            # the request is for multiple agents
            if isinstance(self.input_json['arguments']['agent_id'], list):
                agents = agent.Agent.get_agents_overview(select=select_node, limit=None,
                                                         filters={'id': self.input_json['arguments']['agent_id']},
                                                         sort={'fields': ['node_name'], 'order': 'desc'})['items']
                node_name = {k: list(map(operator.itemgetter('id'), g)) for k, g in
                             itertools.groupby(agents, key=operator.itemgetter('node_name'))}

                # add non existing ids in the master's dictionary entry
                non_existent_ids = list(set(self.input_json['arguments']['agent_id']) -
                                        set(map(operator.itemgetter('id'), agents)))
                if non_existent_ids:
                    if self.node_info['node'] in node_name:
                        node_name[self.node_info['node']].extend(non_existent_ids)
                    else:
                        node_name[self.node_info['node']] = non_existent_ids

                return node_name
            # if the request is only for one agent
            else:
                # Get the node where the agent 'agent_id' is reporting
                node_name = agent.Agent.get_agent(self.input_json['arguments']['agent_id'],
                                                  select=select_node)['node_name']
                return {node_name: [self.input_json['arguments']['agent_id']]}

        elif 'node_id' in self.input_json['arguments']:
            node_id = self.input_json['arguments']['node_id']
            del self.input_json['arguments']['node_id']
            return {node_id: []}
        elif 'group_id' in self.input_json['arguments']:
            agents = agent.Agent.get_agents_overview(
                select=select_node, filters={'group': self.input_json['arguments']['group_id']})['items']
            if len(agents) == 0:
                raise WazuhException(1751)
            del self.input_json['arguments']['group_id']
            node_name = {k: list(map(operator.itemgetter('id'), g)) for k, g in
                         itertools.groupby(agents, key=operator.itemgetter('node_name'))}

            return node_name
        else:
            if 'cluster' in self.input_json['function']:
                node_name = {'fw_all_nodes': [], self.node_info['node']: []}
            else:
                # agents, syscheck, rootcheck and syscollector
                # API calls that affect all agents. For example, PUT/agents/restart, DELETE/rootcheck, etc...
                agents = agent.Agent.get_agents_overview(select=select_node, limit=None,
                                                         sort={'fields': ['node_name'], 'order': 'desc'})['items']
                node_name = {k: [] for k, _ in itertools.groupby(agents, key=operator.itemgetter('node_name'))}
            return node_name

    def merge_results(self, responses, final_json):
        """
        Merge results from an API call.
        To do the merging process, the following is considered:
            1.- If the field is a list, append items to it
            2.- If the field is a message (msg), only replace it if the new message has more priority.
            3.- If the field is a integer:
                * if it's totalItems, sum
                * if it's an error, only replace it if its value is higher
        The priorities are defined in a list of tuples. The first item of the tuple is the element which has more priority.
        :param responses: list of results from each node
        :param final_json: JSON to return.
        :return: single JSON with the final result
        """
        priorities = {
            ("Some agents were not restarted", "All selected agents were restarted"),
            ("KO", "OK")
        }

        for local_json in responses:
            for key, field in local_json.items():
                field_type = type(field)
                if field_type == dict:
                    final_json[key] = self.merge_results([field], {} if key not in final_json else final_json[key])
                elif field_type == list:
                    if key in final_json:
                        final_json[key].extend([elem for elem in field if elem not in final_json[key]])
                    else:
                        final_json[key] = field
                elif field_type == int:
                    if key in final_json:
                        if key == 'totalItems':
                            final_json[key] += field
                        elif key == 'error' and final_json[key] < field:
                            final_json[key] = field
                    else:
                        final_json[key] = field
                else:  # str
                    if key in final_json:
                        if (field, final_json[key]) in priorities:
                            final_json[key] = field
                    else:
                        final_json[key] = field

        if 'data' in final_json and 'items' in final_json['data'] and isinstance(final_json['data']['items'], list):
            if 'offset' not in self.input_json['arguments']:
                self.input_json['arguments']['offset'] = 0
            if 'limit' not in self.input_json['arguments']:
                self.input_json['arguments']['limit'] = common.database_limit

            if 'sort' in self.input_json['arguments']:
                final_json['data']['items'] = utils.sort_array(final_json['data']['items'],
                                                               self.input_json['arguments']['sort']['fields'],
                                                               self.input_json['arguments']['sort']['order'])

            offset, limit = self.input_json['arguments']['offset'], self.input_json['arguments']['limit']
            final_json['data']['items'] = final_json['data']['items'][offset:offset+limit]

        if 'error' in final_json and final_json['error'] > 0 and 'data' in final_json:
            del final_json['data']

        return final_json


class APIRequestQueue:
    """
    Represents a queue of API requests. This thread will be always in background, it will remain blocked until a
    request is pushed into its request_queue. Then, it will answer the request and get blocked again.
    """
    def __init__(self, server):
        self.request_queue = asyncio.Queue()
        self.server = server
        self.logger = logging.getLogger('wazuh').getChild('dapi')
        self.logger.addFilter(cluster.ClusterFilter(tag='Cluster', subtag='D API'))
        self.pending_requests = {}

    async def run(self):
        while True:
            # name    -> node name the request must be sent to. None if called from a worker node.
            # id      -> id of the request.
            # request -> JSON containing request's necessary information
            names, request = (await self.request_queue.get()).split(' ', 1)
            request = json.loads(request)
            names = names.split('*', 1)
            name_2 = '' if len(names) == 1 else names[1] + ' '
            node = self.server.client if names[0] == 'master' else self.server.clients[names[0]]
            self.logger.info("Receiving request: {} from {}".format(
                request['function'], names[0] if not name_2 else '{} ({})'.format(names[0], names[1])))
            try:
                result = await DistributedAPI(input_json=request, logger=self.logger, node=node).distribute_function()
                task_id = await node.send_string(result.encode())
            except Exception as e:
                self.logger.error("Error in distributed API: {}".format(e))
                task_id = b'Error in distributed API: ' + str(e).encode()

            if task_id.startswith(b'Error'):
                self.logger.error(task_id.decode())
                result = await node.send_request(b'dapi_err', name_2.encode() + task_id, b'dapi_err')
            else:
                result = await node.send_request(b'dapi_res', name_2.encode() + task_id, b'dapi_err')
            if result.startswith(b'Error'):
                self.logger.error(result.decode())

    def add_request(self, request: bytes):
        """
        Adds request to the queue

        :param request: Request to add
        """
        self.logger.debug("Received request: {}".format(request))
        self.request_queue.put_nowait(request.decode())
