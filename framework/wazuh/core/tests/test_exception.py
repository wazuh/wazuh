# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.core.exception import WazuhException, WazuhError

def test_wazuh_exception__or__():
    """Check that WazuhException's | operator performs the join of dapi errors properly."""
    excp1 = WazuhException(1308)
    excp1._dapi_errors = {'test1': 'test error'}
    excp2 = WazuhException(1308)
    excp2._dapi_errors = {'test2': 'test error'}
    excp3 = excp2 | excp1
    assert excp3._dapi_errors == {'test1': 'test error', 'test2': 'test error'}


def test_wazuh_exception__deepcopy__():
    """Check that WazuhException's __deepcopy__ magic method works properly."""
    excp1 = WazuhException(1308)
    excp2 = excp1.__deepcopy__()
    assert excp1 == excp2 and excp1 is not excp2


def test_wazuh_error__or__():
    """Check that WazuhError's | operator performs the union of id sets properly."""
    error1 = WazuhError(1309, ids={1, 2, 3})
    error2 = WazuhError(1309, ids={4, 5, 6})
    error3 = error2 | error1
    assert error3.ids == {1, 2, 3, 4, 5, 6}
