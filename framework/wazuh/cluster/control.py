# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
from wazuh.cluster import local_client
import json


async def get_nodes(filter_node=None):
    return json.loads(await local_client.execute(command=b'get_nodes', data=json.dumps(filter_node).encode()))


async def get_health(filter_node=None):
    return json.loads(await local_client.execute(command=b'get_health', data=json.dumps(filter_node).encode()))


async def get_agents(filter_node=None, filter_status=None):
    filter_status = ["all"] if not filter_status else filter_status
    filter_node = ["all"] if not filter_node else filter_node

    input_json = {'function': '/agents', 'from_cluster': False,
                  'arguments': {
                      'filters': {'status': ','.join(filter_status), 'node_name': ','.join(filter_node)},
                      'limit': None,
                      'select': {'fields': ['id', 'ip', 'name', 'status', 'node_name']}}}

    return json.loads(await local_client.execute(command=b'dapi', data=json.dumps(input_json).encode()))
