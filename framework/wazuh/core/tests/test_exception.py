# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
from wazuh.core.exception import WazuhError, WazuhException


@pytest.mark.parametrize(
    'code, extra_message, extra_remediation, cmd_error, dapi_errors, title, type, exc_string',
    [
        # code not found in ERRORS - use extra_message
        (9999, 'External exception', None, None, None, None, None, 'Error 9999 - External exception'),
        # code found in ERRORS - cmd_error True
        (999, 'Code found with cmd_error', None, True, None, None, None, 'Error 999 - Code found with cmd_error'),
        # code found in ERRORS - dictionary entry of string type
        (999, None, None, None, None, None, None, 'Error 999 - Incompatible version of Python'),
        # code found in ERRORS - dictionary entry of dictionary type - without remediation key
        (
            3050,
            None,
            None,
            None,
            None,
            None,
            None,
            'Error 3050 - Error while sending orders to the Communications API unix server',
        ),
        # code found in ERRORS - dictionary entry of dictionary type - with remediation key
        (4000, None, None, None, None, None, None, 'Error 4000 - Permission denied'),
        # code found in ERRORS - extra_message parameter of string type
        (
            4027,
            {'entity': 'User'},
            None,
            None,
            None,
            None,
            None,
            'Error 4027 - User does not exist',
        ),
        # code found in ERRORS - extra_message parameter of dictionary type
        (
            1017,
            {'node_name': 'Node Name', 'not_ready_daemons': 'not ready daemons'},
            None,
            None,
            None,
            None,
            None,
            'Error 1017 - Some Wazuh daemons are not ready yet in node "Node Name" (not ready daemons)',
        ),
    ],
)
def test_wazuh_exception_to_string(
    code, extra_message, extra_remediation, cmd_error, dapi_errors, title, type, exc_string
):
    """Check object constructor."""
    exc = WazuhException(code, extra_message, extra_remediation, cmd_error, dapi_errors, title, type)
    assert str(exc) == exc_string


def test_wazuh_exception__or__():
    """Check that WazuhException's | operator performs the join of dapi errors properly."""
    excp1 = WazuhException(1307)
    excp1._dapi_errors = {'test1': 'test error'}
    excp2 = WazuhException(1307)
    excp2._dapi_errors = {'test2': 'test error'}
    excp3 = excp2 | excp1
    assert excp3._dapi_errors == {'test1': 'test error', 'test2': 'test error'}


def test_wazuh_exception__deepcopy__():
    """Check that WazuhException's __deepcopy__ magic method works properly."""
    excp1 = WazuhException(1307)
    excp2 = excp1.__deepcopy__()
    assert excp1 == excp2 and excp1 is not excp2


def test_wazuh_error__or__():
    """Check that WazuhError's | operator performs the union of id sets properly."""
    error1 = WazuhError(1307, ids={1, 2, 3})
    error2 = WazuhError(1307, ids={4, 5, 6})
    error3 = error2 | error1
    assert error3.ids == {1, 2, 3, 4, 5, 6}
