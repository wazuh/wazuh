# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
from wazuh.cluster import local_client
import json


async def get_nodes(filter_node=None):
    return await local_client.execute(command=b'get_nodes', data=json.dumps(filter_node).encode())


async def get_health(filter_node=None):
    return await local_client.execute(command=b'get_health', data=json.dumps(filter_node).encode())
