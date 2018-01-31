#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.cluster.management import send_request, read_config, check_cluster_status, get_node, get_nodes, get_status_json, get_name_from_ip, get_ip_from_name, get_actual_master
from wazuh.cluster.protocol_messages import *
from wazuh.exception import WazuhException
from wazuh import common
import threading
from sys import version
import logging
import re

is_py2 = version[0] == '2'
if is_py2:
    from Queue import Queue as queue
else:
    from queue import Queue as queue


def send_request_to_node(node, config_cluster, request_type, args, cluster_depth, result_queue):
    error, response = send_request(host=node, port=config_cluster["port"], key=config_cluster['key'],
                        data="{1} {2} {0}".format('a'*(common.cluster_protocol_plain_size - len(request_type + " " + str(cluster_depth) + " ")), request_type, str(cluster_depth)),
                         file=args)

    if error != 0 or response['error'] != 0:
        logging.debug(response)
        result_queue.put({'node': node, 'reason': "{0} - {1}".format(error, response), 'error': 1})
    else:
        result_queue.put(response)


def append_node_result_by_type(node, result_node, request_type, current_result=None):
    if current_result == None:
        current_result = {}
    if request_type == list_requests_agents['RESTART_AGENTS']:
        if isinstance(result_node.get('data'), dict):
            if result_node.get('data').get('affected_agents') != None:
                if current_result.get('affected_agents') is None:
                    current_result['affected_agents'] = []
                current_result['affected_agents'].extend(result_node['data']['affected_agents'])

            if result_node.get('data').get('failed_ids'):
                if current_result.get('failed_ids') is None:
                    current_result['failed_ids'] = []
                current_result['failed_ids'].extend(result_node['data']['failed_ids'])

            if result_node.get('data').get('failed_ids') != None and result_node.get('data').get('msg') != None:
                current_result['msg'] = result_node['data']['msg']
            if current_result.get('failed_ids') == None and result_node.get('data').get('msg') != None:
                current_result['msg'] = result_node['data']['msg']
            if current_result.get('failed_ids') != None and current_result.get('affected_agents') != None:
                current_result['msg'] = "Some agents were not restarted"
        else:
            if current_result.get('data') == None:
                current_result = result_node

    elif request_type in list_requests_managers.values() or request_type == list_requests_cluster['CLUSTER_CONFIG']:
        if current_result.get('items') == None:
            current_result['items'] = {}
        current_result['items'][get_name_from_ip(node)] = result_node
        if current_result.get('totalItems') == None:
            current_result['totalItems'] = 0
        current_result['totalItems'] += 1
    else:
        if result_node.get('data') != None:
            current_result = result_node['data']
        elif result_node.get('message') != None:
            current_result['message'] = result_node['message']
            current_result['error'] = result_node['error']
    return current_result


def send_request_to_nodes(remote_nodes, config_cluster, request_type, args, cluster_depth=1):
    threads = []
    result = {}
    result_node = {}
    result_nodes = {}
    result_queue = queue()
    local_node = get_node()['node']
    remote_nodes_addr = []
    msg = None

    if remote_nodes == None or len(remote_nodes) == 0:
        remote_nodes_addr = list(map(lambda x: x['url'], get_nodes()['items']))
    else:
        remote_nodes_addr = remote_nodes.keys()

    args_str = " ".join(args)

    for node_id in remote_nodes_addr:
        if node_id != None:
            logging.info("Sending {2} request from {0} to {1}".format(local_node, node_id, request_type))

            # Put agents id
            if remote_nodes.get(node_id) != None and len(remote_nodes[node_id]) > 0:
                agents = "-".join(remote_nodes[node_id])
                msg = agents
                if args_str > 0:
                    msg = msg + " " + args_str
            else:
                msg = args_str
            t = threading.Thread(target=send_request_to_node, args=(str(node_id), config_cluster, request_type, msg, cluster_depth, result_queue))
            threads.append(t)
            t.start()
            result_node = result_queue.get()
        else:
            result_node['data'] = {}
            result_node['data']['failed_ids'] = []
            for id in remote_nodes[node_id]:
                node = {}
                node['id'] = id
                node['error'] = {'message':"Agent not found",'code':-1}
                result_node['data']['failed_ids'].append(node)
        result_nodes[node_id] = result_node
    for t in threads:
        t.join()
    for node, result_node in result_nodes.iteritems():
        result = append_node_result_by_type(node, result_node, request_type, result)
    return result


def is_a_local_request():
    config_cluster = read_config()
    return not config_cluster or not check_cluster_status() or config_cluster['node_type'] == 'client'


def is_cluster_running():
    return get_status_json()['running'] == 'yes'


def distributed_api_request(request_type, agent_id={}, args=[], cluster_depth=1, affected_nodes=[]):
    config_cluster = read_config()

    if agent_id != None:
        node_agents = agent_id
    else:
        node_agents = {}

    if affected_nodes is None:
        affected_nodes = []
    if affected_nodes != None and not isinstance(affected_nodes, list):
        affected_nodes = [affected_nodes]

    # Redirect request to elected master
    '''
    if not from_cluster and get_actual_master()['name'] != config_cluster["node_name"]:
        node_agents = {get_actual_master()['url']: agent_id}
        args = [request_type] + args
        request_type = list_requests_cluster['MASTER_FORW']
    '''

    if len(affected_nodes) > 0:
        affected_nodes_addr = []
        for node in affected_nodes:
            # Is name or addr?
            if not re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$").match(node):
                addr = get_ip_from_name(node)
                if addr != None:
                    affected_nodes_addr.append(addr)
            else:
                affected_nodes_addr.append(node)
        if len(affected_nodes_addr) == 0:
            return {}
        #filter existing dict
        if len(node_agents) > 0:
            node_agents_filter = {node: node_agents[node] for node in affected_nodes_addr}
            node_agents = node_agents_filter
        else: #There aren't nodes with agents, set affected nodes
            node_agents = {node: None for node in affected_nodes_addr}

    return send_request_to_nodes(node_agents, config_cluster, request_type, args, cluster_depth)


def get_config_distributed(node_id=None, cluster_depth=1):
    if is_a_local_request() or cluster_depth <= 0 :
        return read_config()
    else:
        if not is_cluster_running():
            raise WazuhException(3015)

        request_type = list_requests_cluster['CLUSTER_CONFIG']
        return distributed_api_request(request_type=request_type, cluster_depth=cluster_depth, affected_nodes=node_id)
