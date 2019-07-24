#!/usr/bin/env python
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch

import pytest

from wazuh import active_response
from wazuh.exception import WazuhException


@patch('wazuh.active_response.OssecQueue')
@patch('wazuh.active_response.Agent')
@patch('wazuh.active_response.get_commands', return_value=['valid_cmd', 'another_valid_cmd', 'one_more'])
@pytest.mark.parametrize('expected_exception, agent_id, command, arguments, custom', [
    (1650, '000', None, [], False),
    (1652, None, 'random', [], False),
    (1652, '000', 'invalid_cmd', [], False),
    (1651, '001', 'valid_cmd', [], False),
    (None, '001', 'valid_cmd', [], False),
    (None, '001', 'valid_cmd', ["arg1", "arg2"], False)
])
def test_run_command(cmd_patch, agent_patch, queue_patch, expected_exception, agent_id, command, arguments, custom):
    """
    Tests run_command function
    """
    agent_patch.return_value.get_basic_information.return_value = {
        'status': 'disconnected' if expected_exception else 'active'}
    queue_patch.return_value.send_msg_to_agent.return_value = "success"
    queue_patch.AR_TYPE = "AR"

    if expected_exception is not None:
        with pytest.raises(WazuhException, match=f'.* {expected_exception} .*'):
            active_response.run_command(agent_id=agent_id, command=command, arguments=arguments, custom=custom)
    else:
        ret = active_response.run_command(agent_id=agent_id, command=command, arguments=arguments, custom=custom)
        assert ret == {'message': 'success'}
        handle = queue_patch()
        msg = f'{"!" if custom else ""}{command} {"- -" if not arguments else " ".join(arguments)}'
        handle.send_msg_to_agent.assert_called_with(agent_id=agent_id, msg=msg, msg_type='AR')


@patch('wazuh.active_response.OssecQueue')
@patch('wazuh.active_response.get_commands', return_value=['valid_cmd', 'another_valid_cmd', 'one_more'])
@pytest.mark.parametrize('expected_exception, command, arguments, custom', [
    (1650, None, [], False),
    (1652, 'random', [], False),
    (1652, 'invalid_cmd', [], False),
    (None, 'valid_cmd', [], False),
    (None, 'valid_cmd', ["arg1", "arg2"], False)
])
def test_run_command_all(cmd_patch, queue_patch, expected_exception, command, arguments, custom):
    """
    Tests run_command_all function
    """
    queue_patch.AR_TYPE = "AR"

    if expected_exception is not None:
        with pytest.raises(WazuhException, match=f'.* {expected_exception} .*'):
            active_response.run_command_all(command=command, arguments=arguments, custom=custom)
    else:
        ret = active_response.run_command_all(command=command, arguments=arguments, custom=custom)
        assert ret == {'message': 'Command sent to all agents.'}
        handle = queue_patch()
        msg = f'{"!" if custom else ""}{command} {"- -" if not arguments else " ".join(arguments)}'
        handle.send_msg_to_agent.assert_called_with(agent_id=None, msg=msg, msg_type='AR')
