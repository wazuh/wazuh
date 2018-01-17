#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.cluster.management import send_request, read_config, check_cluster_status, get_node, get_status_json
import threading
from sys import version

is_py2 = version[0] == '2'
if is_py2:
    from Queue import Queue as queue
else:
    from queue import Queue as queue

# API Messages
list_request_type = []
RESTART_AGENTS = "restart"
list_request_type.append(RESTART_AGENTS)
AGENTS_UPGRADE_RESULT = "agents_upg_result"
list_request_type.append(AGENTS_UPGRADE_RESULT)
AGENTS_UPGRADE = "agents_upg"
list_request_type.append(AGENTS_UPGRADE)
AGENTS_UPGRADE_CUSTOM = "agents_upg_custom"
list_request_type.append(AGENTS_UPGRADE_CUSTOM)
SYSCHECK_LAST_SCAN = "syscheck_last"
list_request_type.append(SYSCHECK_LAST_SCAN)
SYSCHECK_RUN = "syscheck_run"
list_request_type.append(SYSCHECK_RUN)
SYSCHECK_CLEAR = "syscheck_clear"
list_request_type.append(SYSCHECK_CLEAR)
ROOTCHECK_PCI = "rootcheck_pci"
list_request_type.append(ROOTCHECK_PCI)
ROOTCHECK_CIS = "rootcheck_cis"
list_request_type.append(ROOTCHECK_CIS)
ROOTCHECK_LAST_SCAN = "rootcheck_last"
list_request_type.append(ROOTCHECK_LAST_SCAN)
ROOTCHECK_RUN = "rootcheck_run"
list_request_type.append(ROOTCHECK_RUN)
ROOTCHECK_CLEAR = "rootcheck_clear"
list_request_type.append(ROOTCHECK_CLEAR)


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
    if request_type == RESTART_AGENTS:
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
    else:
        if result_node.get('data') != None:
            current_result = result_node['data']
        elif result_node.get('message') != None:
            current_result['message'] = result_node['message']
            current_result['error'] = result_node['error']
        #current_result[node] = result_node
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
    if len(remote_nodes) == 0:
        remote_nodes_addr = list(map(lambda x: x['url'], get_nodes()['items']))
    else:
        remote_nodes_addr = remote_nodes.keys()

    args_str = " ".join(args)

    for node_id in remote_nodes_addr:
        if node_id != None:
            logging.info("Sending {2} request from {0} to {1}".format(local_node, node_id, request_type))

            # Push agents id
            if remote_nodes.get(node_id) != None:
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


def distributed_api_request(request_type, node_agents, args=[], cluster_depth=1):
    config_cluster = read_config()
    return send_request_to_nodes(node_agents, config_cluster, request_type, args, cluster_depth)
