# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import time
from datetime import datetime
from unittest.mock import patch, mock_open
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
    {'key': '', 'nodes': ['192.158.35.13']},
    {'key': 'a'*15, 'nodes': ['192.158.35.13']},
    {'port': 'string', 'key': 'a'*32, 'nodes': ['192.158.35.13']},
    {'port': 90, 'key': 'a'*32, 'nodes': ['192.158.35.13']},
    {'port': 70000, 'key': 'a'*32, 'nodes': ['192.158.35.13']},
    {'node_type': 'random', 'key': 'a'*32, 'nodes': ['192.158.35.13']},
    {'nodes': ['NODE_IP'], 'key': 'a'*32},
    {'nodes': ['localhost'], 'key': 'a'*32},
    {'nodes': ['0.0.0.0'], 'key': 'a'*32},
    {'nodes': ['127.0.1.1'], 'key': 'a'*32}
])
def test_checking_configuration(read_config):
    """
    Checks wrong configurations to check the proper exceptions are raised
    """
    with patch('wazuh.cluster.cluster.get_ossec_conf') as m:
        m.return_value = read_config.copy()
        with pytest.raises(WazuhException, match=r'.* 3004 .*'):
            configuration = cluster.read_config()
            cluster.check_cluster_config(configuration)


agent_info = """Linux |agent1 |3.10.0-862.el7.x86_64 |#1 SMP Fri Apr 20 16:44:24 UTC 2018 |x86_64 [CentOS Linux|centos: 7 (Core)] - Wazuh v3.7.2 / d10d46b48c280384e8773a5fa24ecacb
5b458d5fa953a391de1130a2625f3df2 merged.mg


#"manager_hostname":centos
#"node_name":worker-1
"""


@patch('os.listdir', return_value=['agent1-any', 'agent2-any'])
@patch('wazuh.cluster.cluster.stat')
def test_merge_agent_info(stat_mock, listdir_mock):
    """
    Tests merge agent info function
    """
    stat_mock.return_value.st_mtime = time.time()
    stat_mock.return_value.st_size = len(agent_info)

    with patch('builtins.open', mock_open(read_data=agent_info)) as m:
        cluster.merge_agent_info('agent-info', 'worker1')
        m.assert_any_call('/var/ossec/queue/cluster/worker1/agent-info.merged', 'w')
        m.assert_any_call('/var/ossec/queue/agent-info/agent1-any', 'r')
        m.assert_any_call('/var/ossec/queue/agent-info/agent2-any', 'r')
        handle = m()
        handle.write.assert_any_call(f'{len(agent_info)} agent1-any '
                                     f'{datetime.utcfromtimestamp(stat_mock.return_value.st_mtime)}\n{agent_info}')


@pytest.mark.parametrize('agent_info, exception', [
    (f"258 agent1-any 2019-03-29 14:57:29.610934\n{agent_info}".encode(), None),
    (f"2i58 agent1-any 2019-03-29 14:57:29.610934\n{agent_info}".encode(), ValueError)
])
@patch('wazuh.cluster.cluster.stat')
def test_unmerge_agent_info(stat_mock, agent_info, exception):
    stat_mock.return_value.st_size = len(agent_info)
    with patch('builtins.open', mock_open(read_data=agent_info)) as m:
        agent_infos = list(cluster.unmerge_agent_info('agent-info', '/random/path', 'agent-info.merged'))
        assert len(agent_infos) == (1 if exception is None else 0)
