# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import re

from api.controllers.default_controller import default_info
from api.models.basic_info import BasicInfo


def test_default_info():

        res, code = default_info()
        assert isinstance(res, BasicInfo)
        data = BasicInfo.to_dict(res)
        assert 'title' in data.keys()
        assert isinstance(data['title'], str)
        assert 'api_version' in data.keys()
        assert isinstance(data['api_version'], str)
        version_regex = re.compile(r'^\d+\.\d+\.\d+$')
        assert version_regex.fullmatch(data['api_version'])
        assert 'revision' in data.keys()
        assert isinstance(data['revision'], int)
        assert 'license_name' in data.keys()
        assert isinstance(data['license_name'], str)
        assert 'license_url' in data.keys()
        assert isinstance(data['license_url'], str)
        assert 'hostname' in data.keys()
        assert isinstance(data['hostname'], str)
        assert 'timestamp' in data.keys()
        assert isinstance(data['timestamp'], str)
        assert code == 200
