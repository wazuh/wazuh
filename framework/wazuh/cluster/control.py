#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import ast
from wazuh.exception import WazuhException
from wazuh import common
from wazuh.cluster.cluster import read_config, check_cluster_config, get_status_json
from wazuh.cluster.communication import send_to_internal_socket
from wazuh.utils import sort_array, search_array

socket_name = "c-internal"

def __execute(request):
    cluster_available, msg = check_cluster_status()
    if not cluster_available:
        raise Exception(msg)

    response = send_to_internal_socket(socket_name=socket_name, message=request)
    response_json = json.loads(response)
    return response_json

def check_cluster_status():
    # Get cluster config
    msg = None
    try:
        cluster_config = read_config()
    except WazuhException:
        cluster_config = None

    if not cluster_config or cluster_config['disabled'] == 'yes':
        msg = "The cluster is disabled"

    # Validate cluster config
    try:
        check_cluster_config(cluster_config)
    except WazuhException as e:
        msg = "Invalid configuration: '{0}'".format(str(e))

    status = get_status_json()
    if status["running"] != "yes":
        msg = "The cluster is not running"

    cluster_available = True if msg is None else False
    return cluster_available, msg


## Requests

def get_nodes(filter_node=None):
    request="get_nodes {}".format(filter_node) if filter_node else "get_nodes"
    return __execute(request)

def get_nodes_api(filter_node=None, offset=0, limit=common.database_limit, sort=None, search=None):
    nodes = get_nodes()
    response = {"items":[], "totalItems":len(nodes)}

    for node, data in nodes.items():
        if filter_node and node not in filter_node:
            continue
        response["items"].append(data)

    if search:
        response["items"] = search_array(response['items'], search['value'], search['negation'], fields=['name','type','version','ip'])
    if sort:
        response["items"] = sort_array(response['items'], sort['fields'], sort['order'])
    if limit:
        response["items"] = response["items"][int(offset):int(limit)]

    return response

def get_healthcheck(filter_node=None):
    request="get_health {}".format(filter_node)
    return __execute(request)

def get_agents(filter_status=None, filter_node=None, offset=1, limit=common.database_limit, sort=None, search=None):
    filter_status_f = None

    if filter_status:
        if isinstance(filter_status, list):
            filter_status = filter_status[0]
        filter_status_f = filter_status.lower().replace(" ", "").replace("-", "")
        if filter_status_f == "neverconnected":
            filter_status_f = "Never connected"
        elif filter_status_f == "active":
            filter_status_f = "Active"
        elif filter_status_f == "disconnected":
            filter_status_f = "Disconnected"
        elif filter_status_f == "pending":
            filter_status_f = "Pending"
        else:
            raise Exception("'{}' is not a valid agent status. Try with 'Active', 'Disconnected', 'NeverConnected' or 'Pending'.".format(''.join(filter_status)))

    request="get_agents {}%--%{}%--%{}%--%{}%--%{}%--%{}".format(filter_status_f, filter_node, offset, limit, sort, search)
    return __execute(request)

def sync(filter_node=None):
    request = "sync {}".format(filter_node) if filter_node else "sync"
    return __execute(request)

def get_files(filter_file_list=None, filter_node_list=None):
    request = "get_files {}".format(filter_file_list) if not filter_node_list else "get_files {}%--%{}".format(filter_file_list, filter_node_list)
    return __execute(request)