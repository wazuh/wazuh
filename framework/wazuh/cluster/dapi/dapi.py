#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import wazuh.cluster.dapi.requests_list as rq
import wazuh.cluster.cluster as cluster
import wazuh.cluster.internal_socket as i_s
from wazuh.exception import WazuhException
import json

def distribute_function(input_json, pretty=False, debug=False):
    try:
        if rq.functions[input_json['function']]['type'] == 'local_any' or cluster.get_node()['type'] == 'master':
            if 'arguments' in input_json and input_json['arguments']:
                data = rq.functions[input_json['function']]['function'](**input_json['arguments'])
            else:
                data = rq.functions[input_json['function']]['function']()
            error = 0
        else:
            response = i_s.execute('dapi {}'.format(json.dumps(input_json)))
            error = response['error']
            data = response['data' if not error else 'message']

        return print_json(data=data, pretty=pretty, error=error)
    except WazuhException as e:
        if debug:
            raise
        return print_json(data=e.message, error=e.code, pretty=pretty)
    except Exception as e:
        if debug:
            raise
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
