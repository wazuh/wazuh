#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import wazuh.cluster.dapi.requests_list as rq
import wazuh.cluster.cluster as cluster
import wazuh.cluster.internal_socket as i_s
import wazuh.cluster.communication as communication
from wazuh import common
from wazuh.agent import Agent
from wazuh.exception import WazuhException
import json
from itertools import groupby
from operator import itemgetter
from multiprocessing.dummy import Pool as ThreadPool
import logging
import time
try:
    from Queue import Queue
except ImportError:
    from queue import Queue

logger = logging.getLogger(__name__)

def distribute_function(input_json, pretty=False, debug=False, from_master=False):
    try:
        node_info = cluster.get_node()
        request_type = rq.functions[input_json['function']]['type']

        if not cluster.check_cluster_status() or request_type == 'local_any' or\
                (request_type == 'local_master' and node_info['type'] == 'master')   or\
                (request_type == 'distributed_master' and input_json['from_cluster']):

            return execute_local_request(input_json, pretty, debug)

        elif request_type == 'distributed_master' and node_info['type'] == 'master':
            return forward_request(input_json, node_info['node'], pretty, from_master)
        else:
            return execute_remote_request(input_json, pretty)
    except WazuhException as e:
        return print_json(data=e.message, error=e.code, pretty=pretty)
    except Exception as e:
        return print_json(data=str(e), error=1000, pretty=pretty)


def get_functions():
    return rq.functions.keys()


def encode_json(o):
    try:
        return getattr(o, 'to_dict')()
    except AttributeError as e:
        print_json(error=1000, data="Wazuh-Python Internal Error: data encoding unknown ({})".format(e))


def print_json(data, error=0, pretty=False):
    output = {'message' if error else 'data': data, 'error': error}
    return json.dumps(obj=output, default=encode_json, indent=4 if pretty else None)


def execute_local_request(input_json, pretty, debug):
    try:
        before = time.time()
        if 'arguments' in input_json and input_json['arguments']:
            data = rq.functions[input_json['function']]['function'](**input_json['arguments'])
        else:
            data = rq.functions[input_json['function']]['function']()

        after = time.time()
        logger.debug("[DistributedAPI] Time calculating request result: {}s".format(after - before))
        return print_json(data=data, pretty=pretty, error=0)
    except WazuhException as e:
        if debug:
            raise
        return print_json(data=e.message, error=e.code, pretty=pretty)
    except Exception as e:
        if debug:
            raise
        return print_json(data=str(e), error=1000, pretty=pretty)


def __split_response_data(response):
    if response.get('err'):
        raise WazuhException(3018, response['err'])

    error = response['error']
    data = response['data' if not error else 'message']
    return data, error


def execute_remote_request(input_json, pretty):
    response = i_s.execute('dapi {}'.format(json.dumps(input_json)))
    data, error = __split_response_data(response)
    return print_json(data=data, pretty=pretty, error=error)


def forward_request(input_json, master_name, pretty, from_master):
    """
    Forwards a request to the node who has all available information to answer it. This function is called when a
    distributed_master function is used. Only the master node calls this function. An API request will only be forwarded
    to worker nodes.

    :param input_json: API request: Example: {"function": "/agents", "arguments":{"limit":5}, "ossec_path": "/var/ossec", "from_cluster":false}
    :param master_name: Name of the master node. Necessary to check whether to forward it to a worker node or not.
    :param pretty: JSON pretty print
    :param from_master: whether the request was already forwarded from a master node or not.
    :return: a JSON response.
    """
    def forward(node_name, return_none=False):
        """
        Forwards a request to a node.
        :param node_name: Node to forward a request to.
        :param return_none: Whether to return an error message or nothing (if there's an error forwarding the request).
        :return: a JSON response
        """
        if node_name == 'unknown' or node_name == '':
            # if the agent is never connected or pending (i.e. its node name is unknown or empty), do the request locally
            response = json.loads(distribute_function(input_json))
        else:
            # if not, check if the node the request is being forwarded to is the master or a worker.
            command = 'dapi_forward {}'.format(node_name) if node_name != master_name else 'dapi'
            if command == 'dapi' and from_master:
                # if it's the master, execute the request directly
                response = json.loads(distribute_function(input_json))
            else:
                # if it's a worker, forward it
                response = i_s.execute('{} {}'.format(command, json.dumps(input_json)))
                if not isinstance(response, dict):
                    # If there's an error and the flag return_none is not set, return a dictionary with the response.
                    response = {'error':3016, 'message':str(WazuhException(3016,response))} if not return_none else None
        return response

    def forward_list(item):
        """
        Function called when there are multiple nodes to forward a request to.
        :param item: A dictionary with {node_name: [list of agents ids]}
        :return: JSON response of a single node
        """
        name, agent_ids = item
        if agent_ids:
            input_json['arguments']['agent_id'] = agent_ids
        return forward(name, agent_ids == [])


    # get the node(s) who has all available information to answer the request.
    node_name, is_list = get_solver_node(input_json, master_name)
    input_json['from_cluster'] = True

    if is_list:
        # if there are multiple nodes to forward the request, create a ThreadPool and forward it in parallel.
        pool = ThreadPool(len(node_name))
        responses = list(filter(lambda x: x is not None, pool.map(forward_list, node_name.items())))
        pool.close()
        pool.join()
        final_json = {}
        response = merge_results(responses, final_json, input_json)
    else:
        response = forward(node_name)

    data, error = __split_response_data(response)
    return print_json(data=data, pretty=pretty, error=error)


def get_solver_node(input_json, master_name):
    """
    Gets the node that can solve a request.
    Only called when the request type is 'master_distributed' and the node_type is master.

    :param input_json: API request parameters and description
    :param master_name: name of the master node
    :return: node name and whether the result is list or not
    """
    select_node = {'fields':['node_name']}
    if 'agent_id' in input_json['arguments']:
        # the request is for multiple agents
        if isinstance(input_json['arguments']['agent_id'], list):
            agents = Agent.get_agents_overview(select=select_node, limit=None, filters={'id':input_json['arguments']['agent_id']},
                                                  sort={'fields':['node_name'], 'order':'desc'})['items']
            node_name = {k:list(map(itemgetter('id'), g)) for k,g in groupby(agents, key=itemgetter('node_name')) if k != 'unknown'}

            # add non existing ids in the master's dictionary entry
            non_existent_ids = list(set(input_json['arguments']['agent_id']) - set(map(itemgetter('id'), agents)))
            if non_existent_ids:
                if master_name in node_name:
                    node_name[master_name].extend(non_existent_ids)
                else:
                    node_name[master_name] = non_existent_ids

            return node_name, True
        # if the request is only for one agent
        else:
            # Get the node where the agent 'agent_id' is reporting
            node_name = Agent.get_agent(input_json['arguments']['agent_id'], select=select_node)['node_name']
            return node_name, False

    elif 'node_id' in input_json['arguments']:
        node_id = input_json['arguments']['node_id']
        del input_json['arguments']['node_id']
        return node_id, False

    else: # agents, syscheck, rootcheck and syscollector
        agents = Agent.get_agents_overview(select=select_node, limit=None, sort={'fields': ['node_name'], 'order': 'desc'})['items']
        node_name = {k:[] for k, _ in groupby(agents, key=itemgetter('node_name')) if k != 'unknown'}
        return node_name, True


def merge_results(responses, final_json, input_json):
    """
    Merge results from an API call.

    To do the merging process, the following is considered:
        1.- If the field is a list, append items to it
        2.- If the field is a message (msg), only replace it if the new message has more priority.

    The priorities are defined in a list of tuples. The first item of the tuple is the element which has more priority.

    :param responses: list of results from each node
    :param final_json: JSON to return.
    :return: single JSON with the final result
    """
    priorities = {
        ("Some agents were not restarted", "All selected agents were restarted")
    }

    for local_json in responses:
        for key,field in local_json.items():
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
            else: # str
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

        offset,limit = input_json['arguments']['offset'], input_json['arguments']['limit']
        final_json['data']['items'] = final_json['data']['items'][offset:offset+limit]

    return final_json


class APIRequestQueue(communication.ClusterThread):
    def __init__(self, server, stopper):
        communication.ClusterThread.__init__(self, stopper=stopper)
        self.server = server
        self.request_queue = Queue()
        self.tag = "[DistributedAPI]"


    def run(self):
        while not self.stopper.is_set() and self.running:
            name, id, request = self.request_queue.get(block=True).split(' ', 2)
            result = distribute_function(json.loads(request), from_master=True)
            try:
                self.send_string(result, id, name)
            except Exception as e:
                self.send_request(command='err-is', data=str(e), id=id, name=name)


    def send_string(self, result, id, name):
        if name == 'None':
            self.server.send_string(reason='dapi_res', string_data=result, new_req="fwd_new", upd_req="fwd_upd",
                                    end_req="fwd_end", extra_data=id)
        else:
            self.server.send_string(worker_name=name, reason='dapi_res', string_to_send=result, new_req="fwd_new",
                                    upd_req="fwd_upd", end_req="fwd_end", extra_data=id)


    def send_request(self, command, data, id, name):
        if name == 'None':
            self.server.send_request(command=command, data=id + ' ' + data)
        else:
            self.server.send_request(worker_name=name, command=command, data=id + ' ' + data)


    def set_request(self, request):
        logger.debug("{} Receiving request: {}".format(self.tag, request))
        self.request_queue.put(request)
