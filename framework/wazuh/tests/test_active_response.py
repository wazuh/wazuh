#!/usr/bin/env python
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from unittest.mock import patch

import pytest

with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        from wazuh.exception import WazuhError
        from wazuh import active_response

# all necessary params
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


@pytest.mark.parametrize('rbac, expected_exception, agent_id, command, arguments, custom', [
    (1650, '000', None, [], False),
    (1652, '000', 'random', [], False),
    (1652, '000', 'invalid_cmd', [], False),
    (1651, '001', 'restart-ossec0', [], False),
    (None, '001', 'restart-ossec0', [], False),
    (None, '001', 'restart-ossec0', [], True),
    (None, '001', 'restart-ossec0', ["arg1", "arg2"], False),
    (None, '000', 'restart-ossec0', [], False),
])
def test_run_command(rbac, expected_exception, agent_id, command, arguments, custom):
    """
    Tests run_command function
    """
    if expected_exception is not None:
        with pytest.raises(WazuhError, match=f'.* {expected_exception} .*'):
            active_response.run_command(agent_id=agent_id, command=command, arguments=arguments, custom=custom)
    else:
        ret = active_response.run_command(agent_id=agent_id, command=command, arguments=arguments, custom=custom)
        assert ret == {'message': 'Command sent.'}


@pytest.mark.parametrize('rbac, expected_exception, command, arguments, custom', [
    (1650, None, [], False),
    (1652, 'random', [], False),
    (1652, 'invalid_cmd', [], False),
    (None, 'restart-ossec0', [], False),
    (None, 'restart-ossec0', ["arg1", "arg2"], False)
])
def test_run_command_all(expected_exception, command, arguments, custom):
    """
    Tests run_command function
    """

    if expected_exception is not None:
        with pytest.raises(WazuhError, match=f'.* {expected_exception} .*'):
            active_response.run_command(command=command, arguments=arguments, custom=custom)
    else:
        ret = active_response.run_command(command=command, arguments=arguments, custom=custom)
        assert ret == {'message': 'Command sent.'}
