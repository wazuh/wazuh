#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import wazuh.cluster.dapi.requests_list as rq
import wazuh.cluster.cluster as cluster
import wazuh.cluster.internal_socket as i_s
from wazuh.agent import Agent
from wazuh.exception import WazuhException
import json

def distribute_function(input_json, pretty=False, debug=False):
    node_type = cluster.get_node()['type']
    request_type = rq.functions[input_json['function']]['type']

    if not cluster.check_cluster_status() or request_type == 'local_any' or\
            (request_type == 'local_master' and node_type == 'master')   or\
            (request_type == 'distributed_master' and input_json['from_cluster']):

        return execute_local_request(input_json, pretty, debug)

    elif request_type == 'distributed_master' and node_type == 'master':
        return forward_request(input_json, pretty)
    else:
        return execute_remote_request(input_json, pretty)


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
        if 'arguments' in input_json and input_json['arguments']:
            data = rq.functions[input_json['function']]['function'](**input_json['arguments'])
        else:
            data = rq.functions[input_json['function']]['function']()

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
    error = response['error']
    data = response['data' if not error else 'message']
    return data, error


def execute_remote_request(input_json, pretty):
    response = i_s.execute('dapi {}'.format(json.dumps(input_json)))
    data, error = __split_response_data(response)
    return print_json(data=data, pretty=pretty, error=error)


def forward_request(input_json, pretty):
    node_name = get_solver_node(input_json)
    input_json['from_cluster'] = True
    response = i_s.execute('dapi_forward {} {}'.format(node_name, json.dumps(input_json)))
    data, error = __split_response_data(response)
    return print_json(data=data, pretty=pretty, error=error)


def get_solver_node(input_json):
    """
    Gets the node that can solve a request.
    Only called when the request type is 'master_distributed' and the node_type is master.

    :param input_json: API request parameters and description
    :return: node name
    """
    if 'agent_id' in input_json['arguments']:
        # Get the node where the agent 'agent_id' is reporting
        node_name = Agent.get_agent(input_json['arguments']['agent_id'], select={'fields':['node_name']})['node_name']
        return node_name
