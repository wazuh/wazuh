#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import wazuh.cluster.dapi.requests_list as rq

def distribute_function(input_json):
    if 'arguments' in input_json and input_json['arguments']:
        return rq.functions[input_json['function']](**input_json['arguments'])
    else:
        return rq.functions[input_json['function']]()

def get_functions():
    return rq.functions.keys()