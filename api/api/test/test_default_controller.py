# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import re
from unittest.mock import patch, mock_open

from api.controllers.default_controller import default_info


@patch('api.controllers.default_controller.time.strftime', return_value='2019-04-04T07:38:09+0000')
@patch('api.controllers.default_controller.socket.gethostname', return_value='wazuh')
def test_default_info(mocked_hostname, mocked_time):

        data, code = default_info()
        assert isinstance(data, dict)
        assert 'title' in data.keys()
        assert isinstance(data['title'], str)
        assert 'api_version' in data.keys()
        assert isinstance(data['api_version'], str)
        version_regex = re.compile(r'^\d+\.+\d+\.+\d+$')
        assert version_regex.fullmatch(data['api_version'])
        assert 'revision' in data.keys()
        assert isinstance(data['revision'], int)
        assert 'license_name' in data.keys()
        assert isinstance(data['license_name'], str)
        assert 'license_url' in data.keys()
        assert isinstance(data['license_url'], str)
        url_regex = re.compile(r'^(https?:\/\/(?:www\.|(?!www))[^\s\.]+\.[^\s]{2,}|www\.[^\s]+\.[^\s]{2,})$')
        assert url_regex.fullmatch(data['license_url'])
        assert data['hostname'] == 'wazuh'
        assert data['timestamp'] == '2019-04-04T07:38:09+0000'
        assert code == 200
