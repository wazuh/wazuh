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
import ast

is_py2 = version[0] == '2'
if is_py2:
    from Queue import Queue as queue
else:
    from queue import Queue as queue


def send_request_to_node(node, config_cluster, request_type, args, cluster_depth, result_queue):
    error, response = send_request(host=node, port=config_cluster["port"], key=config_cluster['key'],
                        data="{1} {2} {0}".format('a'*(common.cluster_protocol_plain_size - len(request_type + " " + str(cluster_depth) + " ")), request_type, str(cluster_depth)),
                         file=args)

    if error != 0 or (isinstance(response, dict) and response.get('error') != None and response['error'] != 0):
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

    elif request_type in list_requests_managers.values() or request_type in list_requests_wazuh.values() or request_type in list_requests_stats.values() or request_type == list_requests_cluster['CLUSTER_CONFIG']:
        if current_result.get('items') == None:
            current_result['items'] = {}
        current_result['items'][get_name_from_ip(node)] = result_node
        if current_result.get('totalItems') == None:
            current_result['totalItems'] = 0
        current_result['totalItems'] += 1
    else:
        if isinstance(result_node, dict):
            if result_node.get('data') != None:
                current_result = result_node['data']
            elif result_node.get('message') != None:
                current_result['message'] = result_node['message']
                current_result['error'] = result_node['error']
        else:
            current_result = result_node
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
                agents = parse_node_agents_to_str(remote_nodes[node_id])
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


def parse_node_agents_to_str(node_agents):
    '''
    :param node_agents: dic or list with node-agents or agents
     {
            '192.168.56.102': ['003', 004],
            '192.168.56.105': ['003']
     }
     or
     ['003', '004']
     :return:
     192.168.56.102*003-004_192.168.56.105*003
     or
     "003-004"
    '''
    result = ""
    if isinstance(node_agents, dict):
        for node in node_agents:
            result = str(result) + str(node) + "*" + str("-".join(node_agents[node])) + "_"
        if result == "":
            result = None
        else:
            result = result[:-1]
    elif isinstance(node_agents, list):
        result = "-".join(node_agents)
    return result


def parse_node_agents_to_dic(node_agents_str):
    '''
    :param node_agents: 192.168.56.102*003-004_192.168.56.105*003
    :return:
            {
                   '192.168.56.102': ['003', '004'],
                   '192.168.56.105': ['003']
            }
    '''
    result = {}
    nodes =  node_agents_str.split("_")
    for node in nodes:
        node_agents = node.split("*")
        result[node_agents[0]] = node_agents[1].split("-")
    return result


def distributed_api_request(request_type, agent_id={}, args=[], cluster_depth=1, affected_nodes=[], from_cluster=False, instance=None):

    config_cluster = read_config()

    if agent_id != None and isinstance(agent_id, dict):
        node_agents = agent_id
    else:
        node_agents = {}

    if affected_nodes is None:
        affected_nodes = []
    if affected_nodes != None and not isinstance(affected_nodes, list):
        affected_nodes = [affected_nodes]

    # Redirect request to elected master
    if not from_cluster and get_actual_master()['name'] != config_cluster["node_name"]:
        if len(node_agents) == 0 and len(affected_nodes) == 0:
            affected_nodes = list(map(lambda x: x['url'], get_nodes()['items']))

        node_agents = {get_actual_master()['url']: node_agents}
        if len(affected_nodes) == 0:
            args = [request_type, "-"] + args
        else:
            args = [request_type, "-".join(affected_nodes)] + args
        request_type = list_requests_cluster['MASTER_FORW']
        logging.info("Redirecting request to elected master. args=" + str(args))

    # Put affected nodes in node_agents (not in MASTER_FORW)
    if len(affected_nodes) > 0 and request_type != list_requests_cluster['MASTER_FORW']:
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
            node_agents_filter = {node: node_agents.get(node) for node in affected_nodes_addr}
            node_agents = node_agents_filter
        else: #There aren't nodes with agents, set affected nodes
            node_agents = {node: None for node in affected_nodes_addr}

    # Resolve his request in local (only for elected master)
    result_local = None
    if instance != None and get_actual_master()['name'] == config_cluster["node_name"] and get_ip_from_name(config_cluster["node_name"]) in node_agents:
        logging.warning("distributed_api_request: local ")#TODO remove
        try:
            result_local = {'data':api_request(request_type=request_type, args=args, cluster_depth=0, instance=instance), 'error':0}
        except Exception as e:
            result_local = {'data':str(e), 'error':1}
        del node_agents[get_ip_from_name(config_cluster["node_name"])]

    #logging.warning("distributed_api_request: result_local: --> " + str(result_local)) #TODO remove

    result = None
    if len(node_agents) != 0:

        logging.warning("distributed_api_request: distributed ")#TODO remove
        logging.warning("distributed_api_request: Sending ----> node_agents->" + str(node_agents) + " || request_type->" + str(request_type) + " || args->" + str(args))#TODO remove

        result = send_request_to_nodes(node_agents, config_cluster, request_type, args, cluster_depth)
        #logging.warning("distributed_api_request: result_distributed: --> " + str(result)) #TODO remove
        if result_local != None:
            result = append_node_result_by_type(get_ip_from_name(config_cluster["node_name"]), result_local, request_type, current_result=result)
    else:
        result = result_local

    return result


def get_config_distributed(node_id=None, cluster_depth=1):
    if is_a_local_request() or cluster_depth <= 0:
        return read_config()
    else:
        if not is_cluster_running():
            raise WazuhException(3015)

        request_type = list_requests_cluster['CLUSTER_CONFIG']
        return distributed_api_request(request_type=request_type, cluster_depth=cluster_depth, affected_nodes=node_id)


def api_request(request_type, args, cluster_depth, instance=None):
    res = ""

    if request_type == list_requests_agents['RESTART_AGENTS']:
        if (len(args) == 2):
            agents = args[0].split("-")
            restart_all = ast.literal_eval(args[1])
        else:
            agents = None
            restart_all = ast.literal_eval(args[0])
        res = instance.restart_agents(agents, restart_all, cluster_depth)

    elif request_type == list_requests_agents['AGENTS_UPGRADE_RESULT']:
        try:
            agent = args[0]
            timeout = args[1]
            res = instance.get_upgrade_result(agent, timeout)
        except Exception as e:
            res = str(e)

    elif request_type == list_requests_agents['AGENTS_UPGRADE']:
        agent_id = args[0]
        wpk_repo = ast.literal_eval(args[1])
        version = ast.literal_eval(args[2])
        force = ast.literal_eval(args[3])
        chunk_size = ast.literal_eval(args[4])
        try:
            res = instance.upgrade_agent(agent_id, wpk_repo, version, force, chunk_size)
        except Exception as e:
            res = str(e)

    elif request_type == list_requests_agents['AGENTS_UPGRADE_CUSTOM']:
        agent_id = args[0]
        file_path = ast.literal_eval(args[1])
        installer = ast.literal_eval(args[2])
        try:
            res = instance.upgrade_agent_custom(agent_id, file_path, installer)
        except Exception as e:
            res = str(e)

    elif request_type == list_requests_syscheck['SYSCHECK_LAST_SCAN']:
        res = instance.last_scan(agent[0])

    elif request_type == list_requests_syscheck['SYSCHECK_RUN']:
        if (len(args) == 2):
            agents = args[0]
            all_agents = ast.literal_eval(args[1])
        else:
            agents = None
            all_agents = ast.literal_eval(args[0])
        res = instance.run(agents, all_agents, cluster_depth)

    elif request_type == list_requests_syscheck['SYSCHECK_CLEAR']:
        if (len(args) == 2):
            agents = args[0]
            all_agents = ast.literal_eval(args[1])
        else:
            agents = None
            all_agents = ast.literal_eval(args[0])
        res = instance.clear(agents, all_agents, cluster_depth)

    elif request_type == list_requests_rootcheck['ROOTCHECK_PCI']:
        index = 0
        agents = None
        if (len(args) == 5):
            agents = args[0]
            index = index + 1
        offset = ast.literal_eval(args[index])
        index = index + 1
        limit = ast.literal_eval(args[index])
        index = index + 1
        sort = ast.literal_eval(args[index])
        index = index + 1
        search = ast.literal_eval(args[index])
        res = args
        res = instance.get_pci(agents, offset, limit, sort, search)

    elif request_type == list_requests_rootcheck['ROOTCHECK_CIS']:
        index = 0
        agents = None
        if (len(args) == 5):
            agents = args[0]
            index = index + 1
        offset = ast.literal_eval(args[index])
        index = index + 1
        limit = ast.literal_eval(args[index])
        index = index + 1
        sort = ast.literal_eval(args[index])
        index = index + 1
        search = ast.literal_eval(args[index])
        res = args
        res = instance.get_cis(agents, offset, limit, sort, search)

    elif request_type == list_requests_rootcheck['ROOTCHECK_LAST_SCAN']:
        res = instance.last_scan(agent[0])

    elif request_type == list_requests_rootcheck['ROOTCHECK_RUN']:
        args = args.split(" ")
        if (len(args) == 2):
            agents = args[0]
            all_agents = ast.literal_eval(args[1])
        else:
            agents = None
            all_agents = ast.literal_eval(args[0])
        res = instance.run(agents, all_agents, cluster_depth)

    elif request_type == list_requests_rootcheck['ROOTCHECK_CLEAR']:
        if (len(args) == 2):
            agents = args[0]
            all_agents = ast.literal_eval(args[1])
        else:
            agents = None
            all_agents = ast.literal_eval(args[0])
        res = instance.clear(agents, all_agents, cluster_depth)

    elif request_type == list_requests_managers['MANAGERS_STATUS']:
        res = instance.managers_status(cluster_depth=cluster_depth)

    elif request_type == list_requests_managers['MANAGERS_LOGS']:
        type_log = args[0]
        category = args[1]
        months = ast.literal_eval(args[2])
        offset = ast.literal_eval(args[3])
        limit = ast.literal_eval( args[4])
        sort = ast.literal_eval(args[5])
        search = ast.literal_eval(args[6])
        res = instance.managers_ossec_log(type_log=type_log, category=category, months=months, offset=offset, limit=limit, sort=sort, search=search, cluster_depth=cluster_depth)

    elif request_type == list_requests_managers['MANAGERS_LOGS_SUMMARY']:
        months = ast.literal_eval(args[0])
        res = instance.managers_ossec_log_summary(months=months, cluster_depth=cluster_depth)

    elif request_type == list_requests_stats['MANAGERS_STATS_TOTALS']:
        year = ast.literal_eval(args[0])
        month = ast.literal_eval(args[1])
        day = ast.literal_eval(args[2])
        res = instance.totals(year=year, month=month, day=day, cluster_depth=cluster_depth)

    elif request_type == list_requests_stats['MANAGERS_STATS_HOURLY']:
        res = instance.hourly(cluster_depth=cluster_depth)

    elif request_type == list_requests_stats['MANAGERS_STATS_WEEKLY']:
        res = instance.weekly(cluster_depth=cluster_depth)

    elif request_type == list_requests_managers['MANAGERS_OSSEC_CONF']:
        section = args[0]
        field = ast.literal_eval(args[1])
        res = instance.managers_get_ossec_conf(section=section, field=field, cluster_depth=cluster_depth)

    elif request_type == list_requests_wazuh['MANAGERS_INFO']:
        logging.warning("MANAGERS_INFO args --> "+ str(args))#TODO remove
        res = instance.managers_get_ossec_init(cluster_depth=cluster_depth)
        logging.warning("MANAGERS_INFO res --> "+ str(res))#TODO remove

    elif request_type == list_requests_cluster['CLUSTER_CONFIG']:
        res = get_config_distributed(cluster_depth=cluster_depth)
    return res
