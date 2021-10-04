# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


import logging
import sys
import zipfile
from datetime import datetime
from time import time
from unittest import mock
from unittest.mock import MagicMock, mock_open, patch

import pytest
from wazuh.core import common

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators

        del sys.modules['wazuh.rbac.orm']
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        import wazuh.core.cluster.cluster as cluster
        import wazuh.core.cluster.utils as utils
        from wazuh import WazuhException
        from wazuh.core.exception import WazuhError, WazuhInternalError

# Valid configurations
default_cluster_configuration = {
    'cluster': {
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
}

custom_cluster_configuration = {
    'cluster': {
        'disabled': 'no',
        'node_type': 'master',
        'name': 'wazuh',
        'node_name': 'node01',
        'key': 'a' * 32,
        'port': 1516,
        'bind_addr': '0.0.0.0',
        'nodes': ['172.10.0.100'],
        'hidden': False
    }
}

custom_incomplete_configuration = {
    'cluster': {
        'key': 'a' * 32,
        'node_name': 'master'
    }
}


def test_get_localhost_ips():
    """
    Test to check the correct output from the get_localhost_ips function
    """
    assert type(cluster.get_localhost_ips()) is set


@pytest.mark.parametrize('read_config', [
    {'cluster': {'key': ''}},
    {'cluster': {'key': 'a' * 15}},
    {'cluster': {'node_type': 'random', 'key': 'a' * 32}},
    {'cluster': {'port': 'string', 'node_type': 'master'}},
    {'cluster': {'port': 90}},
    {'cluster': {'port': 70000}},
    {'cluster': {'port': 1516}},
    {'cluster': {'nodes': ['NODE_IP'], 'key': 'a' * 32, 'node_type': 'master'}},
    {'cluster': {'nodes': ['localhost'], 'key': 'a' * 32, 'node_type': 'master'}},
    {'cluster': {'nodes': ['0.0.0.0'], 'key': 'a' * 32, 'node_type': 'master'}},
    {'cluster': {'nodes': ['127.0.1.1'], 'key': 'a' * 32, 'node_type': 'master'}},
    {'cluster': {'nodes': ['127.0.1.1', '127.0.1.2'], 'key': 'a' * 32, 'node_type': 'master'}}
])
def test_check_cluster_config_ko(read_config):
    """
    Checks wrong configurations to check the proper exceptions are raised
    """
    with patch('wazuh.core.cluster.utils.get_ossec_conf') as m:
        m.return_value = read_config.copy()
        with pytest.raises(WazuhException, match=r'.* 3004 .*'):
            configuration = wazuh.core.cluster.utils.read_config()

            for key in m.return_value["cluster"]:
                if key in configuration:
                    configuration[key] = m.return_value["cluster"][key]

            cluster.check_cluster_config(configuration)


def test_get_cluster_items_master_intervals():
    """
    Test to check the correct output of the get_cluster_items_master_intervals function
    """
    assert isinstance(cluster.get_cluster_items_master_intervals(), dict)


def test_get_cluster_items_communication_intervals():
    """
    Test to check the correct output of the get_cluster_items_communication_intervals function
    """
    assert isinstance(cluster.get_cluster_items_communication_intervals(), dict)


def test_get_cluster_items_worker_intervals():
    """
    Test to check the correct output of the get_cluster_items_worker_intervals function
    """
    assert isinstance(cluster.get_cluster_items_worker_intervals(), dict)


def test_get_node():
    """
    Test to check the correct output of the get_node function
    """
    test_dict = {"node_name": "master", "name": "master", "node_type": "master"}

    with patch('wazuh.core.cluster.cluster.read_config', return_value=test_dict):
        get_node = cluster.get_node()
        assert isinstance(get_node, dict)
        assert get_node["node"] == test_dict["node_name"]
        assert get_node["cluster"] == test_dict["name"]
        assert get_node["type"] == test_dict["node_type"]


def test_check_cluster_status():
    """
    Test to check the correct output of the check_cluster_status function
    """
    assert isinstance(cluster.check_cluster_status(), bool)


@patch('wazuh.core.common.cluster_integrity_mtime')
def test_walk_files(mock_cluster_integrity_mtime):
    """
    Test to check the different outputs of the walk_files function
    """
    
    with patch('os.path.join', return_value = '/some/path/'):
        with patch('wazuh.core.cluster.cluster.walk') as w:
            w.return_value = [('/foo/', ('bar',), ('baz',)),
                                ('/foo/bar', (), ('spam', 'eggs', '.merged')),]
            cluster.walk_dir("/var/ossec/etc/shared/", False, ["all"], ["ar.conf"], [".xml", ".txt"], "", True)
            with patch('os.path.getmtime', return_value = 45):
                mock_cluster_integrity_mtime.return_value = {"/some/path/": {"mod_time": 45}}
                cluster.walk_dir("/var/ossec/etc/shared/", True, ["all"], ["ar.conf"], [".xml", ".txt"], "", True)

            # with pytest.raises(KeyError):
            #     mock_cluster_integrity_mtime.return_value = 5
            #     cluster.walk_dir("/var/ossec/etc/shared/", True, ["all"], ["ar.conf"], [".xml", ".txt"], "", True)
                
            with patch('os.path.getmtime', return_value = mock_cluster_integrity_mtime.get()["/some/path"]['mod_time']):
                cluster.walk_dir("/var/ossec/etc/shared/", True, ["all"], ["ar.conf"], [".xml", ".txt"], "", True)

            with patch('os.path.getmtime', side_effect = PermissionError):
                cluster.walk_dir("/var/ossec/etc/shared/", True, ["all"], ["ar.conf"], [".xml", ".txt"], "", True)

        with patch('wazuh.core.cluster.cluster.walk', side_effect = OSError):
            with pytest.raises(WazuhInternalError, match=r'.* 3015 .*'):
                cluster.walk_dir("/var/ossec/etc/shared/", True, ["all"], ["ar.conf"], [".xml", ".txt"], "", True)



@patch('wazuh.core.cluster.cluster.get_cluster_items', return_value={
    "files": {
        "etc/": {
            "permissions": 416,
            "source": "master",
            "files": [
                "client.keys"
            ],
            "recursive": False,
            "restart": False,
            "remove_subdirs_if_empty": False,
            "extra_valid": False,
            "description": "client keys file database"
        },
        "excluded_files": [
            "ar.conf",
            "ossec.conf"
        ],
        "excluded_extensions": [
            "~",
            ".tmp",
            ".lock",
            ".swp"
        ]
    }
})
def test_get_files_status(mock_get_cluster_items):
    """
    Test to check the different outputs of the get_files_status function
    """

    test_dict = {"path": "metadata"}

    with patch('wazuh.core.cluster.cluster.walk_dir', return_value=test_dict):
        assert isinstance(cluster.get_files_status(), dict)
        assert cluster.get_files_status()["path"] == test_dict["path"]

    with patch('wazuh.core.cluster.cluster.walk_dir', side_effect = Exception):
        cluster.get_files_status()


def test_update_cluster_control_with_failed():
    """
    Check if cluster_control json is updated as expected
    """
    ko_files = {
        'missing': {'/test_file0': 'test',
                    '/test_file3': 'ok'},
        'shared': {'/test_file1': 'test'},
        'extra': {'/test_file2': 'test'}
    }
    cluster.update_cluster_control_with_failed(['/test_file0', '/test_file1', 'test_file2'],
                                               ko_files)

    assert ko_files == {'missing': {'/test_file3': 'ok'},
                        'shared': {},
                        'extra': {'/test_file2': 'test', '/test_file1': 'test'}
                        }


@patch('wazuh.core.cluster.cluster.mkdir_with_mode')
@patch('wazuh.core.cluster.cluster.path.dirname', return_value = '/some/path')
def test_compress_files(mock_path_dirname,mock_mkdir_with_mode):
    """
    Test to check if the compressing function is working properly
    """
    with patch('wazuh.core.cluster.cluster.path.exists', return_value = False):
        cluster.compress_files("some_name", ["some/path", "another/path"], {"ko_file": "file"})
        mock_mkdir_with_mode.assert_called_once_with('/some/path')

        with patch('zipfile.ZipFile.write', side_effect = zipfile.LargeZipFile):
            with pytest.raises(WazuhError, match=r'.* 3001 .*'):
                cluster.compress_files("some_name", ["some/path", "another/path"])

        with patch('zipfile.ZipFile.writestr', side_effect = zipfile.LargeZipFile):
            with pytest.raises(WazuhError, match=r'.* 3001 .*'):
                cluster.compress_files("some_name", ["some/path", "another/path"])


def test_decompress_files():
    """
    Test to check if the decompressing function is working properly
    """


@patch('wazuh.core.cluster.cluster.get_cluster_items')
def test_compare_files(mock_get_cluster_items):
    """
    Test to check the different outputs of the compare_files function
    """
    mock_get_cluster_items.return_value = {'files': {'key': {'extra_valid': True}}}

    with patch('wazuh.core.cluster.cluster.merge_info', return_values = [1, "random/path/"]):
        cluster.compare_files({'some/path3/': {'cluster_item_key': 'key', 'md5': 'md5 value'}, 
                               'some/path2/': {'cluster_item_key': "key", 'md5': 'md5 value'}}, 
                              {'some/path2/': {'cluster_item_key': 'key', 'md5': 'md5 def value'},
                               'some/path4/': {'cluster_item_key': "key", 'md5': 'md5 value'}}, 'worker1')
                    
    cluster.compare_files({'some/path3/': {'cluster_item_key': 'key', 'md5': 'md5 value'}, 
                           'some/path2/': {'cluster_item_key': "key", 'md5': 'md5 value'}}, 
                          {'some/path2/': {'cluster_item_key': 'key', 'md5': 'md5 value'},
                           'some/path4/': {'cluster_item_key': "key", 'md5': 'md5 value'}}, 'worker1')


    #with patch('wazuh.core.common.wazuh_path', return_value = "/var/ossec/"):
#     assert cluster.walk_dir("/var/ossec/etc/shared/", False, ["all"], ["ar.conf"], [".xml", ".txt"], "", True) == {}
#     print("\n2 assert")
#     assert cluster.walk_dir("/var/ossec/etc/shared/", True, ["all"], ["ar.conf"], [".xml", ".txt"], "etc/shared/", True) == {}


def test_clean_up():
    """
    Test to check if the cleaning function is working properly
    """

    with patch('os.path.join') as path_join_mock:
        path_join_mock.return_value = Exception
        cluster.clean_up("worker1")

        path_join_mock.return_value = "some/path/"
        with patch('os.path.exists') as path_exists_mock:
            path_exists_mock.return_value = False
            cluster.clean_up("worker1")

        with patch('os.path.exists') as path_exists_mock:
            path_exists_mock.return_value = True
            with patch('wazuh.core.cluster.cluster.listdir') as listdir_mock:
                listdir_mock.return_value = ["c-internal.sock","other_file.txt"]
                cluster.clean_up("worker1")

                with patch('os.path.isdir', return_value = True):
                    cluster.clean_up("worker1")

                with patch('wazuh.core.cluster.cluster.rmtree', side_effect = Exception):
                    cluster.clean_up("worker1")


@patch('wazuh.core.cluster.cluster.listdir', return_value=['005', '006'])
@patch('wazuh.core.cluster.cluster.stat')
def test_merge_info(stat_mock, listdir_mock):
    """
    Tests merge agent info function
    """
    stat_mock.return_value.st_mtime = time()
    stat_mock.return_value.st_size = len(agent_groups)

    with patch('builtins.open', mock_open(read_data=agent_groups)) as m:
        cluster.merge_info('agent-groups', 'worker1', file_type='-shared')
        m.assert_any_call(common.wazuh_path + '/queue/cluster/worker1/agent-groups-shared.merged', 'wb')
        m.assert_any_call(common.wazuh_path + '/queue/agent-groups/005', 'rb')
        m.assert_any_call(common.wazuh_path + '/queue/agent-groups/006', 'rb')
        handle = m()
        expected = f'{len(agent_groups)} 005 ' \
                   f'{datetime.utcfromtimestamp(stat_mock.return_value.st_mtime)}\n'.encode() + agent_groups
        handle.write.assert_any_call(expected)


agent_groups = b"default,windows-servers"
@pytest.mark.parametrize('agent_info, exception', [
    (f"23 005 2019-03-29 14:57:29.610934\n{agent_groups}".encode(), None),
    (f"2i58 006 2019-03-29 14:57:29.610934\n{agent_groups}".encode(), ValueError)
])
@patch('wazuh.core.cluster.cluster.stat')
def test_unmerge_info(stat_mock, agent_info, exception):
    """
    Tests unmerge agent info function
    """
    stat_mock.return_value.st_size = len(agent_info)
    with patch('builtins.open', mock_open(read_data=agent_info)):
        agent_groups = list(
            cluster.unmerge_info('agent-groups', '/random/path', 'agent-groups-shared.merged'))
        assert len(agent_groups) == (1 if exception is None else 0)













def test_read_empty_configuration():
    """
    Test reading an empty cluster configuration
    """
    with patch('wazuh.core.cluster.utils.get_ossec_conf') as m:
        wazuh.core.cluster.utils.read_config.cache_clear()
        m.side_effect = WazuhException(1106)
        configuration = wazuh.core.cluster.utils.read_config()
        configuration['disabled'] = 'yes' if configuration['disabled'] else 'no'
        assert configuration == default_cluster_configuration['cluster']


@pytest.mark.parametrize('read_config', [
    default_cluster_configuration,
    custom_cluster_configuration,
    custom_incomplete_configuration
])
def test_read_configuration(read_config):
    """
    Tests reading the cluster configuration from ossec.conf
    """
    with patch('wazuh.core.cluster.utils.get_ossec_conf') as m:
        m.return_value = read_config.copy()
        configuration = wazuh.core.cluster.utils.read_config()
        configuration['disabled'] = 'yes' if configuration['disabled'] else 'no'
        wazuh.core.cluster.utils.read_config.cache_clear()
        for k in read_config['cluster'].keys():
            assert configuration[k] == read_config['cluster'][k]

        # values not present in the read user configuration will be filled with default values
        if 'disabled' not in read_config and read_config != {}:
            default_cluster_configuration['disabled'] = 'no'
        for k in default_cluster_configuration.keys() - read_config.keys():
            assert configuration[k] == default_cluster_configuration[k]



    # with patch('wazuh.core.cluster.cluster.walk_dir', side_effect=Exception('test_error')):
    #     with patch('wazuh.core.cluster.cluster.logging.getLogger') as logger_mock:
    #         cluster.get_files_status()
    #         print(logger_mock)
    #         # import pydevd_pycharm
    #         # pydevd_pycharm.settrace('172.17.0.1', port=12345, stdoutToServer=True, stderrToServer=True)
    #         logger_mock.warning.assert_called_once_with("Error getting file status: test_error.")
    #     # mock_walk_dir.side_effect = Exception
    #     # with pytest.raises(Exception):
    #     #     cluster.get_files_status()


# @patch('files', return_value=["all"])
# def test_walk_dir(mock_files, value):
#     """
#     Test to check if the expected exceptions are raised
#     """
#     with patch('previous_status', return_value={}):
#         with pytest.raises(KeyError):
#             pass





# def test_remove_directory_contents():
#     """
#     Test to check the correct performance of the remove_directory_function
#     """

#     logger = logging.getLogger('wazuh.core.cluster.cluster.')

#     with patch('rm_path', return_value = "/silly/path"):
#         assert cluster.clean_up()



# @pytest.mark.asyncio
# async def test_decompress_files():
#     cluster.decompress_files("/some/path")








