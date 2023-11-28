"""
 Copyright (C) 2015-2023, Wazuh Inc.
 Created by Wazuh, Inc. <info@wazuh.com>.
 This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""

import pytest

from wazuh_testing.utils import services
from wazuh_testing.utils.services import check_all_daemon_status
from time import sleep

@pytest.fixture
def restart_wazuh_expect_error() -> None:
    try:
        sleep(1)
        if any(v == True for _, v in check_all_daemon_status().items()) :
            services.control_service('restart')
        else:
            services.control_service('start')
    except:
        pass

    yield

    services.control_service('stop')


'''
    description: gets 'elements' configuration parameters  from 'sections' field and converts it from list to list dict
    return  configuration parameters
'''
@pytest.fixture
def get_real_configuration(test_configuration):
    config_data = test_configuration.get('sections', {})[0]['elements']
    real_config = dict()

    for I in config_data:
        for key in I:
            real_config[key] = I[key]

    if real_config.get('protocol'):
        real_config['protocol']['value'] = real_config['protocol']['value'].split(',')

    real_config_list = list()
    real_config_list.append(real_config)
    return real_config_list
