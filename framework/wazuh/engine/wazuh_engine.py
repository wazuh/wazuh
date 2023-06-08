# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from typing import Dict, Any
from wazuh.engine.commands import MetricCommand

HARDCODED_DUMP_RESPONSE = [{
    'scope': 'CountExample',
    'schema': '',
    'version': '',
    'records': [{
        'start_time': 'Tue Mar  7 14:46:09 2023',
        'instrument_name': 'CountExample_counter',
        'instrument_description': 'some description',
        'unit': 'some unit',
        'attributes': [{'type': 'SumPointData', 'value': 1}],
        }],
    }]

HARDCODED_GET_RESPONSE = {
    'scope': 'ConnectedSockets',
    'records': [{
        'unit': '',
        'instrument_name': 'ConnectedSockets',
        'start_time': 'Tue Apr  4 20:29:16 2023',
        'instrument_description': '',
        'attributes': [{'type': 'SumPointData', 'value': 0}],
        'type': 'UpDownCounter',
        }],
    'version': '',
    'schema': '',
    }

HARDCODED_TEST_RESPONSE = [{
    'scope': 'CountExample',
    'schema': '',
    'version': '',
    'records': [{
        'start_time': 'Tue Mar  7 14:46:09 2023',
        'instrument_name': 'CountExample_counter',
        'instrument_description': 'some description',
        'unit': 'some unit',
        'attributes': [{'type': 'SumPointData', 'value': 1}],
        'type': 'UpDownCounter',
        }],
    }]

HARDCODED_LIST_RESPONSE = [
    {"scope": "kvdb", "name": "databeseCounter", "type": "counter", "status": "enable"},
    {"scope": "kvdb", "name": "databeseCounter", "type": "counter", "status": "enable"},
]

HARDCODED_ENABLE_RESPONSE = {"scope": "kvdb", "name": "databeseCounter", "type": "counter", "status": "enable"}


class WazuhMockedEngine:
    def __init__(self, socket_path: str):
        self.socket_path = socket_path

    def send_command(self, command: Dict[str, Any]):
        response = {"status": "OK", "value": None}

        if command['command'] == MetricCommand.LIST:
            response["value"] = HARDCODED_LIST_RESPONSE
        elif command['command'] == MetricCommand.DUMP:
            response["value"] = HARDCODED_DUMP_RESPONSE
        elif command['command'] == MetricCommand.GET:
            response["value"] = HARDCODED_GET_RESPONSE
        elif command['command'] == MetricCommand.TEST:
            response["value"] = HARDCODED_TEST_RESPONSE
        elif command['command'] == MetricCommand.ENABLE:
            response["value"] = HARDCODED_ENABLE_RESPONSE

        return response
