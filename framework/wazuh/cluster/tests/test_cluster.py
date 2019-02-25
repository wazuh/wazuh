# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch
from wazuh.exception import WazuhException
from wazuh.cluster import cluster
import pytest

# Valid configurations
default_cluster_configuration = {
    'disabled': 'yes',
    'node_type': 'master',
    'name': 'wazuh',
    'node_name': 'node01',
    'key': '',
    'port': 1516,
    'bind_addr': '0.0.0.0',
    'nodes': ['NODE_IP'],
    'hidden': 'no'
}

custom_cluster_configuration = {
    'disabled': 'no',
    'node_type': 'master',
    'name': 'wazuh',
    'node_name': 'node01',
    'key': 'a'*32,
    'port': 1516,
    'bind_addr': '0.0.0.0',
    'nodes': ['172.10.0.100'],
    'hidden': False
}

custom_incomplete_configuration = {
    'key': 'a'*32,
    'node_name': 'master'
}


def test_read_empty_configuration():
    """
    Tests reading an empty cluster configuration
    """
    with patch('wazuh.cluster.cluster.get_ossec_conf') as m:
        m.side_effect = WazuhException(1106)
        configuration = cluster.read_config()
        configuration['disabled'] = 'yes' if configuration['disabled'] else 'no'
        assert configuration == default_cluster_configuration


@pytest.mark.parametrize('read_config', [
    default_cluster_configuration,
    custom_cluster_configuration,
    custom_incomplete_configuration
])
def test_read_configuration(read_config):
    """
    Tests reading the cluster configuration from ossec.conf
    """
    with patch('wazuh.cluster.cluster.get_ossec_conf') as m:
        m.return_value = read_config.copy()
        configuration = cluster.read_config()
        configuration['disabled'] = 'yes' if configuration['disabled'] else 'no'
        for k in read_config.keys():
            assert configuration[k] == read_config[k]

        # values not present in the read user configuration will be filled with default values
        if 'disabled' not in read_config and read_config != {}:
            default_cluster_configuration['disabled'] = 'no'
        for k in default_cluster_configuration.keys() - read_config.keys():
            assert configuration[k] == default_cluster_configuration[k]


@pytest.mark.parametrize('read_config', [
    {'disabled': 'yay'},
    {'key': ''},
    {'key': 'a'*15},
    {'port': 'string'},
    {'node_type': 'random'},
    {'nodes': ['NODE_IP']},
    {'nodes': ['localhost']},
    {'nodes': ['0.0.0.0']},
    {'nodes': ['172.0.1.1']}
])
def test_checking_configuration(read_config):
    """
    Checks wrong configurations to check the proper exceptions are raised
    """
    with patch('wazuh.cluster.cluster.get_ossec_conf') as m:
        m.return_value = read_config.copy()
        with pytest.raises(WazuhException, match=r'3004'):
            configuration = cluster.read_config()
            cluster.check_cluster_config(configuration)
