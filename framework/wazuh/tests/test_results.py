#!/usr/bin/env python
# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from copy import deepcopy
from unittest.mock import patch

import pytest

with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        from wazuh.results import WazuhResult


@pytest.mark.parametrize('dikt, priority', [
    ({"data": {"items": [{"item1": "data1"}, {"item2": "OK"}], "message": "Everything ok"}}, ['KO', 'OK']),
    ({"data": {"items": [{"item1": "data1"}, {"item2": "data2"}], "message": "Everything ok"}}, None),
])
def test_results_WazuhResult(dikt, priority):
    wazuh_result = WazuhResult(deepcopy(dikt), str_priority=priority)
    assert isinstance(wazuh_result, WazuhResult)
    # assert wazuh_result._merge_str(wazuh_result.dikt['data']['items'][1]['item2'], 'KO') == priority[0]
    item2 = wazuh_result.dikt['data']['items'][1]['item2']
    merge_result = wazuh_result._merge_str(item2, 'KO')
    assert merge_result == priority[0] if priority else '{}|{}'.format(item2, 'KO')
    assert wazuh_result.to_dict() == {'str_priority': priority, 'result': dikt}
    assert wazuh_result.render() == dikt
    decode_result = wazuh_result.decode_json({'result': {'resultado': 1}, 'str_priority': ['prioridad']})
    assert (key in decode_result.dikt for key in ['dikt', 'priority'])
    assert isinstance(decode_result, WazuhResult)
