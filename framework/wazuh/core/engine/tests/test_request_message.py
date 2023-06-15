# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.core.engine import request_message
from wazuh.core.engine import commands


def test_initial_msg_only_have_version():
    """Test that the initial message only contains the version field."""

    version = 1
    msg = request_message.EngineRequestMessage(version).to_dict()

    assert msg == {'version': version}


def test_adds_origin_correctly():
    """Test that the origin is added correctly to the message."""

    version = 1
    origin_name = 'example'
    module_name = 'some_module'

    msg = request_message.EngineRequestMessage(version)
    msg.add_origin(origin_name, module_name)

    assert msg.to_dict() == {
        'version': version,
        'origin': {
            'name': origin_name,
            'module': module_name
        }
    }


def test_adds_command_correctly():
    """Test that the command is added correctly to the message."""

    version = 1
    command = commands.MetricCommand.TEST

    msg = request_message.EngineRequestMessage(version)
    msg.add_command(command)
    assert msg.to_dict() == {'version': version, 'command': command.value}


def test_adds_parameters_correctly():
    """Test that the parameters are added correctly to the message."""

    version = 1
    parameters = {'first': 1, 'second': '2'}

    msg = request_message.EngineRequestMessage(version)
    msg.add_parameters(parameters)
    assert msg.to_dict() == {'version': version, 'parameters': parameters}


def test_format_msg_correctly():
    """Test that the message is formatted correctly with origin, command, and parameters."""

    version = 1
    origin_name = 'example'
    module_name = 'some_module'
    command = commands.MetricCommand.TEST
    parameters = {'first': 1, 'second': '2'}

    msg = request_message.EngineRequestMessage(version)
    msg.create_message(origin_name, module_name, command, parameters)

    assert msg.to_dict() == {
        'version': version,
        'origin': {'name': origin_name, 'module': module_name},
        'command': command.value,
        'parameters': parameters
    }
