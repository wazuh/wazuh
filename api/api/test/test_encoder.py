# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
from unittest.mock import patch

import pytest

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        from api.encoder import prettify, dumps
        from wazuh.core.results import WazuhResult


def custom_hook(dct):
    if 'key' in dct:
        return {'key': dct['key']}
    elif 'error' in dct:
        return WazuhResult.decode_json({'result': dct, 'str_priority': 'v2'})
    else:
        return dct


@pytest.mark.parametrize('o', [{'key': 'v1'},
                               WazuhResult({'k1': 'v1'}, str_priority='v2')
                               ]
                         )
def test_encoder_dumps(o):
    """Test dumps method from API encoder using WazuhAPIJSONEncoder."""
    encoded = dumps(o)
    decoded = json.loads(encoded, object_hook=custom_hook)
    assert decoded == o


def test_encoder_prettify():
    """Test prettify method from API encoder using WazuhAPIJSONEncoder."""
    assert prettify({'k1': 'v1'}) == '{\n   "k1": "v1"\n}'
