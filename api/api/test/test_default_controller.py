# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from unittest.mock import patch, mock_open

from api.controllers.default_controller import default_info

test_path = os.path.dirname(os.path.realpath(__file__))
test_data_path = os.path.join(test_path, 'data')

spec_contents_yaml = '''
info:
  version: 4.0.0
  x-revision: 'UNK'
  title: "Wazuh API"
  license:
    name: GPL 2.0
    url: 'https://github.com/wazuh/wazuh/blob/master/LICENSE'
    '''

spec_contents = {
    'info': {
        'title': 'Wazuh API',
        'version': '4.0.0',
        'x-revision': 'UNK',
        'license' : {
            'name': 'GPL 2.0',
            'url': 'https://github.com/wazuh/wazuh/blob/master/LICENSE'
            }
    }
}


@patch('api.controllers.default_controller.socket.gethostname', return_value="wazuh")
@patch('api.controllers.default_controller.yaml.load', return_value=spec_contents)
def test_default_info(mocked_yaml, mocked_hostname):
    m = mock_open(read_data=spec_contents_yaml)
    with patch('builtins.open', m):
        data, code = default_info()
        assert data['title'] == 'Wazuh API'
        assert data['api_version'] == '4.0.0'
        assert data['revision'] == 'UNK'
        assert data['license_name'] == 'GPL 2.0'
        assert data['license_url'] == 'https://github.com/wazuh/wazuh/blob/master/LICENSE'
        assert data['hostname'] == 'wazuh'
        assert code == 200




