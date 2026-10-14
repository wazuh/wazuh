# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch

import pytest

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        from wazuh.core.logtest import send_logtest_msg, validate_dummy_logtest
        from wazuh.core.common import LOGTEST_SOCKET
        from wazuh.core.exception import WazuhError


@pytest.mark.parametrize('params', [
    {'command': 'random_command', 'parameters': {'param1': 'value1'}},
    {'command': None, 'parameters': None}
])
@patch('wazuh.core.logtest.WazuhSocketJSON.__init__', return_value=None)
@patch('wazuh.core.logtest.WazuhSocketJSON.send')
@patch('wazuh.core.logtest.WazuhSocketJSON.close')
@patch('wazuh.core.logtest.create_wazuh_socket_message')
def test_send_logtest_msg(create_message_mock, close_mock, send_mock, init_mock, params):
    """Test `send_logtest_msg` function from module core.logtest.

    Parameters
    ----------
    params : dict
        Params that will be sent to the logtest socket.
    """
    with patch('wazuh.core.logtest.WazuhSocketJSON.receive',
               return_value={'data': {'response': True, 'output': {'timestamp': '1970-01-01T00:00:00.000000-0200'}}}):
        response = send_logtest_msg(**params)
        init_mock.assert_called_with(LOGTEST_SOCKET)
        create_message_mock.assert_called_with(origin={'name': 'Logtest', 'module': 'framework'}, **params)
        assert response == {'data': {'response': True, 'output': {'timestamp': '1970-01-01T02:00:00.000000Z'}}}


RULE_TREE_LIMIT_ERROR = ("(5108): Rule '100116' in 'etc/rules/custom.xml' exceeds the rule tree node limit "
                         "(1000000 nodes in the tree, 76766 added by this rule, limit 1000000). "
                         "Ruleset loading aborted.")
SESSION_ERROR = 'ERROR: (7311): Failure to initializing session'


@pytest.mark.parametrize('messages, expected_code, expected_message', [
    # No detail from analysisd
    (None, 1113, 'XML syntax error'),
    # Other analysisd errors are added to the generic error, without the session error
    (['WARNING: (7617): Signature ID \'1\' was not found and will be ignored in the \'if_sid\' option of rule \'2\'.',
      "ERROR: (5101): Invalid root element: 'metadata'.", SESSION_ERROR],
     1113, "XML syntax error: (5101): Invalid root element: 'metadata'."),
    # The rule tree node limit has its own error
    (['WARNING: (7621): The rule tree exceeded the warning threshold of 500000 nodes while adding rule \'100115\' '
      'from \'etc/rules/custom.xml\'.', f'ERROR: {RULE_TREE_LIMIT_ERROR}', SESSION_ERROR],
     1132, f'The ruleset exceeds the rule tree node limit: {RULE_TREE_LIMIT_ERROR}'),
    # In debug mode, analysisd prepends the source location to each message
    ([f'ERROR: analysisd/rules.c:1932 at Rules_OP_ReadRules(): {RULE_TREE_LIMIT_ERROR}',
      'ERROR: analysisd/logtest.c:1100 at w_logtest_process_log(): (7311): Failure to initializing session'],
     1132, 'The ruleset exceeds the rule tree node limit: '
           f'analysisd/rules.c:1932 at Rules_OP_ReadRules(): {RULE_TREE_LIMIT_ERROR}'),
])
@patch('wazuh.core.logtest.WazuhSocketJSON.__init__', return_value=None)
@patch('wazuh.core.logtest.WazuhSocketJSON.send')
@patch('wazuh.core.logtest.WazuhSocketJSON.close')
@patch('wazuh.core.logtest.create_wazuh_socket_message')
def test_validate_dummy_logtest(create_message_mock, close_mock, send_mock, init_mock, messages, expected_code,
                                expected_message):
    """Test that `validate_dummy_logtest` reports the analysisd errors of a failed ruleset load.

    Parameters
    ----------
    messages : list
        Messages of the logtest response.
    expected_code : int
        Expected error code.
    expected_message : str
        Expected error message.
    """
    data = {'codemsg': -1}
    if messages is not None:
        data['messages'] = messages

    with patch('wazuh.core.logtest.WazuhSocketJSON.receive', return_value={'data': data, 'error': 0}):
        with pytest.raises(WazuhError) as err_info:
            validate_dummy_logtest()

        assert err_info.value.code == expected_code
        assert err_info.value.message == expected_message


@pytest.mark.parametrize('data', [
    {'codemsg': 0},
    # Warnings do not reject the ruleset
    {'codemsg': 1, 'messages': ['WARNING: (7621): The rule tree exceeded the warning threshold of 500000 nodes '
                                'while adding rule \'100115\' from \'etc/rules/custom.xml\'.']},
])
@patch('wazuh.core.logtest.WazuhSocketJSON.__init__', return_value=None)
@patch('wazuh.core.logtest.WazuhSocketJSON.send')
@patch('wazuh.core.logtest.WazuhSocketJSON.close')
@patch('wazuh.core.logtest.create_wazuh_socket_message')
def test_validate_dummy_logtest_ok(create_message_mock, close_mock, send_mock, init_mock, data):
    """Test that `validate_dummy_logtest` accepts a ruleset that loads, with or without warnings.

    Parameters
    ----------
    data : dict
        Data of the logtest response.
    """
    with patch('wazuh.core.logtest.WazuhSocketJSON.receive', return_value={'data': data, 'error': 0}):
        validate_dummy_logtest()
