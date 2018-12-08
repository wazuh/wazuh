# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import copy
import itertools
import json
import operator
from typing import Dict, Union
from wazuh.cluster import local_client, cluster
from wazuh.cluster.dapi import requests_list as rq
from wazuh import exception, agent, common, utils
import logging
import time

logger = logging.getLogger('wazuh')


async def distribute_function(input_json: Dict, debug: bool = False, pretty: bool = False) -> str:
    """
    Distributes an API call

    :param input_json: Dictionary describing API call to execute
    :param debug: whether to raise exceptions or just return error messages
    :param pretty: Whether to do pretty print or not
    :return: Dictionary with API response
    """
    try:
        node_info = cluster.get_node()
        request_type = rq.functions[input_json['function']]['type']
        is_dapi_enabled = cluster.get_cluster_items()['distributed_api']['enabled']

        if 'wait_for_complete' not in input_json['arguments']:
            input_json['arguments']['wait_for_complete'] = False

        # First case: execute the request local.
        # If the distributed api is not enabled
        # If the cluster is disabled or the request type is local_any
        # if the request was made in the master node and the request type is local_master
        # if the request came forwarded from the master node and its type is distributed_master
        if not is_dapi_enabled or not cluster.check_cluster_status() or request_type == 'local_any' or \
                (request_type == 'local_master' and node_info['type'] == 'master') or \
                (request_type == 'distributed_master' and input_json['from_cluster']):

            del input_json['arguments']['wait_for_complete']  # local requests don't use this parameter
            return execute_local_request(input_json, debug, pretty)

        # Second case: forward the request
        # Only the master node will forward a request, and it will only be forwarded if its type is distributed_master
        elif request_type == 'distributed_master' and node_info['type'] == 'master':
            return await forward_request(input_json, node_info['node'], debug, pretty)

        # Last case: execute the request remotely.
        # A request will only be executed remotely if it was made in a worker node and its type isn't local_any
        else:
            return await execute_remote_request(input_json)
    except exception.WazuhException as e:
        return print_json(data=e.message, error=e.code, pretty=pretty)
    except Exception as e:
        if debug:
            raise
        return print_json(data=str(e), error=1000, pretty=pretty)


def print_json(data: Union[Dict, str], error: int = 0, pretty = False) -> str:
    def encode_json(o):
        try:
            return getattr(o, 'to_dict')()
        except AttributeError as e:
            print_json(error=1000, data="Wazuh-Python Internal Error: data encoding unknown ({})".format(e))

    output = {'message' if error else 'data': data, 'error': error}
    return json.dumps(obj=output, default=encode_json, indent=4 if pretty else None)


def execute_local_request(input_json: Dict, debug: bool, pretty: bool) -> str:
    """
    Executes an API request locally.
    :param input_json: API request to execute.
    :param debug: whether to raise an exception or return it.
    :param pretty: Whether to do pretty print or not
    :return: a JSON response.
    """
    try:
        before = time.time()
        if 'arguments' in input_json and input_json['arguments']:
            data = rq.functions[input_json['function']]['function'](**input_json['arguments'])
        else:
            data = rq.functions[input_json['function']]['function']()

        after = time.time()
        logger.debug("[Cluster] [D API        ] Time calculating request result: {}s".format(after - before))
        return print_json(data=data, error=0, pretty=pretty)
    except exception.WazuhException as e:
        if debug:
            raise
        return print_json(data=e.message, error=e.code, pretty=pretty)
    except Exception as e:
        if debug:
            raise
        return print_json(data=str(e), error=1000, pretty=pretty)


async def execute_remote_request(input_json: Dict) -> str:
    """
    Executes a remote request. This function is used by worker nodes to execute master_only API requests.
    :param input_json: API request to execute. Example: {"function": "/agents", "arguments":{"limit":5}, "ossec_path": "/var/ossec", "from_cluster":false}
    :param pretty: Whether to do pretty print or not
    :return: JSON response
    """
    return await local_client.execute(command=b'dapi', data=json.dumps(input_json).encode())


async def forward_request(input_json, master_name, debug, pretty):
    """
    Forwards a request to the node who has all available information to answer it. This function is called when a
    distributed_master function is used. Only the master node calls this function. An API request will only be forwarded
    to worker nodes.
    :param input_json: API request: Example: {"function": "/agents", "arguments":{"limit":5}, "ossec_path": "/var/ossec", "from_cluster":false}
    :param master_name: Name of the master node. Necessary to check whether to forward it to a worker node or not.
    :param debug: Debug
    :param pretty: Whether to do pretty print or not
    :return: a JSON response.
    """
    async def forward(node_name: str) -> str:
        """
        Forwards a request to a node.
        :param node_name: Node to forward a request to.
        :return: a JSON response
        """
        if node_name == 'unknown' or node_name == '' or node_name == master_name:
            # The request will be executed locally if the the node to forward to is unknown, empty or the master itself
            response = distribute_function(copy.deepcopy(input_json), debug, pretty)
        else:
            response = await local_client.execute(b'dapi_forward',
                                                  "{} {}".format(node_name, json.dumps(input_json)).encode())

        return response

    # get the node(s) who has all available information to answer the request.
    nodes = get_solver_node(input_json, master_name)
    input_json['from_cluster'] = True
    if len(nodes) > 1:
        results = await asyncio.gather(*[forward(node) for node in nodes])
        final_json = {}
        response = merge_results(results, final_json, input_json)
    else:
        response = await forward(nodes[0])
    return response


def get_solver_node(input_json, master_name):
    """
    Gets the node(s) that can solve a request, the node(s) that has all the necessary information to answer it.
    Only called when the request type is 'master_distributed' and the node_type is master.
    :param input_json: API request parameters and description
    :param master_name: name of the master node
    :return: node name and whether the result is list or not
    """
    select_node = {'fields': ['node_name']}
    if 'agent_id' in input_json['arguments']:
        # the request is for multiple agents
        if isinstance(input_json['arguments']['agent_id'], list):
            agents = agent.Agent.get_agents_overview(select=select_node, limit=None,
                                                     filters={'id': input_json['arguments']['agent_id']},
                                                     sort={'fields': ['node_name'], 'order': 'desc'})['items']
            node_name = {k: list(map(operator.itemgetter('id'), g)) for k, g in
                         itertools.groupby(agents, key=operator.itemgetter('node_name'))}

            # add non existing ids in the master's dictionary entry
            non_existent_ids = list(set(input_json['arguments']['agent_id']) -
                                    set(map(operator.itemgetter('id'), agents)))
            if non_existent_ids:
                if master_name in node_name:
                    node_name[master_name].extend(non_existent_ids)
                else:
                    node_name[master_name] = non_existent_ids

            return node_name
        # if the request is only for one agent
        else:
            # Get the node where the agent 'agent_id' is reporting
            node_name = agent.Agent.get_agent(input_json['arguments']['agent_id'], select=select_node)['node_name']
            return [node_name]

    elif 'node_id' in input_json['arguments']:
        node_id = input_json['arguments']['node_id']
        del input_json['arguments']['node_id']
        return [node_id]

    else:  # agents, syscheck, rootcheck and syscollector
        # API calls that affect all agents. For example, PUT/agents/restart, DELETE/rootcheck, etc...
        agents = agent.Agent.get_agents_overview(select=select_node, limit=None,
                                                 sort={'fields': ['node_name'], 'order': 'desc'})['items']
        node_name = {k: [] for k, _ in itertools.groupby(agents, key=operator.itemgetter('node_name'))}
    return node_name


def merge_results(responses, final_json, input_json):
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
    :param input_json: Initial request data
    :return: single JSON with the final result
    """
    priorities = {
        ("Some agents were not restarted", "All selected agents were restarted")
    }

    for local_json in responses:
        for key, field in local_json.items():
            field_type = type(field)
            if field_type == dict:
                final_json[key] = merge_results([field], {} if key not in final_json else final_json[key], input_json)
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

    if 'data' in final_json and 'items' in final_json['data'] and isinstance(final_json['data']['items'],list):
        if 'offset' not in input_json['arguments']:
            input_json['arguments']['offset'] = 0
        if 'limit' not in input_json['arguments']:
            input_json['arguments']['limit'] = common.database_limit

        if 'sort' in input_json['arguments']:
            final_json['data']['items'] = utils.sort_array(final_json['data']['items'],
                                                           input_json['arguments']['sort']['fields'],
                                                           input_json['arguments']['sort']['order'])

        offset, limit = input_json['arguments']['offset'], input_json['arguments']['limit']
        final_json['data']['items'] = final_json['data']['items'][offset:offset+limit]

    return final_json


class APIRequestQueue:
    """
    Represents a queue of API requests. This thread will be always in background, it will remain blocked until a
    request is pushed into its request_queue. Then, it will answer the request and get blocked again.
    """
    def __init__(self, server):
        self.request_queue = asyncio.Queue()
        self.server = server

    async def run(self):
        while True:
            # name    -> node name the request must be sent to. None if called from a worker node.
            # id      -> id of the request.
            # request -> JSON containing request's necessary information
            names, request = (await self.request_queue.get()).split(' ', 1)
            names = names.split('*', 1)
            result = await distribute_function(json.loads(request))
            name_2 = '' if len(names) == 1 else names[1]
            if names[0] == 'None':
                result = await self.server.client.send_request(b'dapi_res', "{} {}".format(name_2, result).encode())
            else:
                result = await self.server.clients[names[0]].send_request(b'dapi_res', "{} {}".format(name_2,
                                                                                                      result).encode())
            if result.startswith(b'Error'):
                self.server.logger.error(result)

    def add_request(self, request: bytes):
        """
        Adds request to the queue

        :param request: Request to add
        """
        self.server.logger.info("Receiving request: {}".format(request))
        self.request_queue.put_nowait(request.decode())
