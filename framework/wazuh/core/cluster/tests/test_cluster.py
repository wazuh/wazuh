# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it
# under the terms of GPLv2
import io
import sys
import zipfile
from contextvars import ContextVar
from datetime import datetime
from time import time
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
        from wazuh import WazuhException
        from wazuh.core.exception import WazuhError, WazuhInternalError

agent_groups = b"default,windows-servers"

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
    """Check the correct output from the get_localhost_ips function."""
    with patch("wazuh.core.cluster.cluster.check_output", return_value=b"172.19.0.1 172.17.0.1 172.18.0.1") as mock_output:
        result = cluster.get_localhost_ips()
        mock_output.assert_called_with(['hostname', '--all-ip-addresses'])
        assert isinstance(result, set)
        assert result == {"172.19.0.1", "172.17.0.1"}


@pytest.mark.parametrize('read_config, message', [
    ({'cluster': {'key': ''}}, "Unspecified key"),
    ({'cluster': {'key': 'a' * 15}}, "Key must be"),
    ({'cluster': {'node_type': 'random', 'key': 'a' * 32}}, "Invalid node type"),
    ({'cluster': {'port': 'string', 'node_type': 'master'}}, "Port has to"),
    ({'cluster': {'port': 90}}, "Port must be"),
    ({'cluster': {'port': 70000}}, "Port must be"),
    ({'cluster': {'port': 1516, 'nodes': ['NODE_IP'], 'key': 'a' * 32, 'node_type': 'master'}}, "Invalid elements"),
    ({'cluster': {'nodes': ['localhost'], 'key': 'a' * 32, 'node_type': 'master'}}, "Invalid elements"),
    ({'cluster': {'nodes': ['0.0.0.0'], 'key': 'a' * 32, 'node_type': 'master'}}, "Invalid elements"),
    ({'cluster': {'nodes': ['127.0.1.1'], 'key': 'a' * 32, 'node_type': 'master'}}, "Invalid elements"),
    ({'cluster': {'nodes': ['127.0.1.1', '127.0.1.2'], 'key': 'a' * 32, 'node_type': 'master'}}, "Invalid elements"),
])
def test_check_cluster_config_ko(read_config, message):
    """Check wrong configurations to check the proper exceptions are raised."""
    with patch('wazuh.core.cluster.utils.get_ossec_conf', return_value=read_config) as m:
        with pytest.raises(WazuhException, match=rf'.* 3004 .* {message}'):
            configuration = wazuh.core.cluster.utils.read_config()

            for key in m.return_value["cluster"]:
                if key in configuration:
                    configuration[key] = m.return_value["cluster"][key]

            cluster.check_cluster_config(configuration)


def test_get_cluster_items_master_intervals():
    """Check the correct output of the get_cluster_items_master_intervals function."""
    assert isinstance(cluster.get_cluster_items_master_intervals(), dict)


def test_get_cluster_items_communication_intervals():
    """Check the correct output of the get_cluster_items communication_intervals function."""
    assert isinstance(cluster.get_cluster_items_communication_intervals(), dict)


def test_get_cluster_items_worker_intervals():
    """Check the correct output of the get_cluster_items_worker_intervals function."""
    assert isinstance(cluster.get_cluster_items_worker_intervals(), dict)


def test_get_node():
    """Check the correct output of the get_node function."""
    test_dict = {"node_name": "master", "name": "master",
                 "node_type": "master"}

    with patch('wazuh.core.cluster.cluster.read_config', return_value=test_dict):
        get_node = cluster.get_node()
        assert isinstance(get_node, dict)
        assert get_node["node"] == test_dict["node_name"]
        assert get_node["cluster"] == test_dict["name"]
        assert get_node["type"] == test_dict["node_type"]


def test_check_cluster_status():
    """Check the correct output of the check_cluster_status function."""
    assert isinstance(cluster.check_cluster_status(), bool)


@patch('wazuh.core.cluster.cluster.common.cluster_integrity_mtime',
       ContextVar('cluster_integrity_mtime', default={"/foo/bar": {"mod_time": 45}}))
@patch('wazuh.core.cluster.cluster.walk', return_value=[('/foo/bar', (), ('spam', 'eggs', '.merged'))])
@patch('os.path.join', return_value='/foo/bar')
@patch('wazuh.core.cluster.cluster.md5', return_value="some hash")
def test_walk_dir(mock_md5, mock_path_join, mock_walk):
    """Check the different outputs of the walk_files function."""

    with patch('os.path.getmtime', return_value=45):
        walk_dir = cluster.walk_dir("/foo/bar", True, ["all"], ["ar.conf"], [".xml", ".txt"], "", True)
        assert isinstance(walk_dir, dict)
        assert walk_dir == {"/foo/bar": {"mod_time": 45}}

    with patch('os.path.getmtime', return_value=35):
        # Check that the output is a dictionary and also has the key "md5"
        walk_md5 = cluster.walk_dir("/foo/bar", True, ["all"], ["ar.conf"], [".xml", ".txt"], "", True)
        assert isinstance(walk_md5, dict)
        assert "md5" in walk_md5["/foo/bar"].keys()
        assert walk_md5["/foo/bar"]["md5"] == "some hash"

        # Check that the output is a dictionary and does not have the key "md5"
        walk_no_md5 = cluster.walk_dir("/foo/bar", True, ["all"], ["ar.conf"], [".xml", ".txt"], "", False)
        assert isinstance(walk_no_md5, dict)
        assert "md5" not in walk_no_md5["/foo/bar"].keys()

    with patch('os.path.join', return_value='/foo/bar/testing'):
        walk_no_recursive = cluster.walk_dir("/foo/bar", False, ["all"], ["ar.conf"], [".xml", ".txt"], "", True)
        assert isinstance(walk_no_recursive, dict)
        assert len(walk_no_recursive.keys()) == 0


@patch('wazuh.core.cluster.cluster.common.cluster_integrity_mtime',
       ContextVar('cluster_integrity_mtime', default={"/foo/bar": {"mod_time_wrong": 45}}))
@patch('wazuh.core.cluster.cluster.walk', return_value=[('/foo/bar', (), ['spam'])])
@patch('os.path.join', return_value='/foo/bar')
def test_walk_dir_ko(mock_path_join, mock_walk):
    """Check all errors that can be raised by the function walk_dir."""
    with patch.object(wazuh.core.cluster.cluster.logger, "debug") as mock_logger:
        with patch('os.path.getmtime', side_effect=FileNotFoundError):
            cluster.walk_dir("/foo/bar", True, ["all"], ["ar.conf"], [".xml", ".txt"], "", True)
            mock_logger.assert_called_with("File spam was deleted in previous iteration: ")

    with patch.object(wazuh.core.cluster.cluster.logger, "error") as mock_logger:
        with patch('os.path.getmtime', side_effect=PermissionError):
            cluster.walk_dir("/foo/bar", True, ["all"], ["ar.conf"], [".xml", ".txt"], "", True)
            mock_logger.assert_called_with("Can't read metadata from file spam: ")

    with patch('wazuh.core.cluster.cluster.walk', side_effect=OSError):
        with pytest.raises(WazuhInternalError, match=r'.* 3015 .*'):
            cluster.walk_dir("/foo/bar", True, ["all"], ["ar.conf"], [".xml", ".txt"], "", True)

    with patch('os.path.getmtime', return_value=35):
        cluster.walk_dir("/foo/bar", True, ["all"], ["ar.conf"], [".xml", ".txt"], "", False)


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
    """Check the different outputs of the get_files_status function."""

    test_dict = {"path": "metadata"}

    with patch('wazuh.core.cluster.cluster.walk_dir', return_value=test_dict):
        assert isinstance(cluster.get_files_status(), dict)
        assert cluster.get_files_status()["path"] == test_dict["path"]

    with patch('wazuh.core.cluster.cluster.walk_dir', side_effect=Exception):
        with patch.object(wazuh.core.cluster.cluster.logger, "warning") as logger_mock:
            cluster.get_files_status()
            logger_mock.assert_called_once_with(f"Error getting file status: .")


def test_update_cluster_control_with_failed():
    """Check if cluster_control json is updated as expected."""
    ko_files = {
        'missing': {'/test_file0': 'test',
                    '/test_file3': 'ok'},
        'shared': {'/test_file1': 'test'},
        'extra': {'/test_file2': 'test'}
    }
    cluster.update_cluster_control_with_failed(['/test_file0', '/test_file1', 'test_file2'], ko_files)

    assert ko_files == {'missing': {'/test_file3': 'ok'}, 'shared': {},
                        'extra': {'/test_file2': 'test', '/test_file1': 'test'}}


@patch('wazuh.core.cluster.cluster.mkdir_with_mode')
@patch('wazuh.core.cluster.cluster.path.dirname', return_value='/some/path')
@patch('wazuh.core.cluster.cluster.path.exists', return_value=False)
def test_compress_files_ok(mock_path_exists, mock_path_dirname, mock_mkdir_with_mode):
    """Check if the compressing function is working properly."""
    with patch("zipfile.ZipFile.write"):
        with patch('zipfile.ZipFile', return_value=zipfile.ZipFile(io.BytesIO(b"Testing"), 'x')):
            assert isinstance(cluster.compress_files("some_name", ["some/path", "another/path"],
                                                     {"ko_file": "file"}), str)


@patch('wazuh.core.cluster.cluster.mkdir_with_mode')
@patch('wazuh.core.cluster.cluster.path.dirname', return_value='/some/path')
@patch('wazuh.core.cluster.cluster.path.exists', return_value=False)
def test_compress_files_ko(mock_path_exists, mock_path_dirname, mock_mkdir_with_mode):
    """Check if the compressing function is raising every exception."""
    with patch("zipfile.ZipFile.write", side_effect=Exception):
        with patch('zipfile.ZipFile', return_value=zipfile.ZipFile(io.BytesIO(b"Testing"), 'x')):
            with patch.object(wazuh.core.cluster.cluster.logger, "debug") as mock_logger:
                cluster.compress_files("some_name", ["some/path", "another/path"], {"ko_file": "file"})
                mock_logger.assert_called_with(f"[Cluster] {str(WazuhException(3001))}")

    with patch("zipfile.ZipFile.write", side_effect=zipfile.LargeZipFile):
        with patch('zipfile.ZipFile', return_value=zipfile.ZipFile(io.BytesIO(b"Testing"), 'x')):
            with pytest.raises(WazuhError, match=r'.* 3001 .*'):
                cluster.compress_files("some_name", ["some/path"])

    with patch("zipfile.ZipFile.writestr", side_effect=Exception):
        with patch('zipfile.ZipFile', return_value=zipfile.ZipFile(io.BytesIO(b"Testing"), 'x')):
            with pytest.raises(WazuhError, match=r'.* 3001 .*'):
                cluster.compress_files("some_name", ["some/path"])


async def test_decompress_files_ok():
    """Check if the decompressing function is working properly."""

    with patch('wazuh.core.cluster.cluster.mkdir_with_mode'):
        with patch('zipfile.ZipFile'):
            # Mock the 'os-path.exists' in order to enter the condition
            with patch('os.path.exists', return_value=True):
                # Mocking the 'open' function as well
                with patch('builtins.open'):
                    with patch('json.loads', return_value="some string with files"):
                        with patch('wazuh.core.cluster.cluster.remove'):
                            ko_files, zip_dir = await cluster.decompress_files('/some/path')
                            assert ko_files == "some string with files"
                            assert zip_dir == "/some/pathdir"


async def test_decompress_files_ko():
    """Check if the decompressing function raising the necessary exceptions."""

    with patch('wazuh.core.cluster.cluster.mkdir_with_mode'):
        with patch('zipfile.ZipFile', return_value=Exception):
            # Raising the expected Exception
            with pytest.raises(Exception):
                with patch('os.path.exists', return_value=True):
                    with patch('shutil.rmtree'):
                        assert await cluster.decompress_files('/some/path') == "some string with files", "/some/pathdir"


@patch('wazuh.core.cluster.cluster.get_cluster_items')
def test_compare_files(mock_get_cluster_items):
    """Check the different outputs of the compare_files function."""
    mock_get_cluster_items.return_value = {'files': {'key': {'extra_valid': True}}}

    seq = {'some/path3/': {'cluster_item_key': 'key', 'md5': 'md5 value'},
           'some/path2/': {'cluster_item_key': "key", 'md5': 'md5 value'}}
    condition = {'some/path2/': {'cluster_item_key': 'key', 'md5': 'md5 def value'},
                 'some/path4/': {'cluster_item_key': "key", 'md5': 'md5 value'}}

    # First condition
    with patch('wazuh.core.cluster.cluster.merge_info', return_values=[1, "random/path/"]):
        files, count = cluster.compare_files(seq, condition, 'worker1')
        assert count["missing"] == 1
        assert count["extra"] == 0
        assert count["extra_valid"] == 1
        assert count["shared"] == 1

    # Second condition
    condition = {'some/path5/': {'cluster_item_key': 'key', 'md5': 'md5 def value'},
                 'some/path4/': {'cluster_item_key': "key", 'md5': 'md5 value'}}

    files, count = cluster.compare_files(seq, condition, 'worker1')
    assert count["missing"] == 2
    assert count["extra"] == 0
    assert count["extra_valid"] == 2
    assert count["shared"] == 0


def test_clean_up_ok():
    """Check if the cleaning function is working properly."""

    with patch('os.path.join', return_value="some/path/"):
        with patch.object(wazuh.core.cluster.cluster.logger, "debug") as mock_logger:
            with patch('os.path.exists', return_value=False) as path_exists_mock:
                cluster.clean_up("worker1")
                mock_logger.assert_any_call("Removing 'some/path/'.")
                mock_logger.assert_any_call("Nothing to remove in 'some/path/'.")
                mock_logger.assert_called_with("Removed 'some/path/'.")

                path_exists_mock.return_value = True
                with patch('wazuh.core.cluster.cluster.listdir',
                           return_value=["c-internal.sock", "other_file.txt"]):
                    with patch('os.path.isdir', return_value=True) as is_dir_mock:
                        with patch('wazuh.core.cluster.cluster.rmtree'):
                            cluster.clean_up("worker1")
                            mock_logger.assert_any_call("Removing 'some/path/'.")
                            mock_logger.assert_called_with("Removed 'some/path/'.")

                        is_dir_mock.return_value = False
                        with patch('wazuh.core.cluster.cluster.remove'):
                            cluster.clean_up("worker1")
                            mock_logger.assert_any_call("Removing 'some/path/'.")
                            mock_logger.assert_called_with("Removed 'some/path/'.")


def test_clean_up_ko():
    """Check if the cleaning function raising the exceptions properly."""
    error_cleaning = "Error cleaning up: stat: path should be string, bytes, os.PathLike or integer, not type."
    error_removing = f"Error removing '{Exception}': " \
                     f"'stat: path should be string, bytes, os.PathLike or integer, not type'."

    with patch('os.path.join') as path_join_mock:
        with patch.object(wazuh.core.cluster.cluster.logger, "error") as mock_error_logger:
            with patch.object(wazuh.core.cluster.cluster.logger, "debug") as mock_debug_logger:
                path_join_mock.return_value = Exception
                cluster.clean_up("worker1")
                mock_debug_logger.assert_any_call(f"Removing '{Exception}'.")
                mock_error_logger.assert_called_once_with(error_cleaning)

                with patch('os.path.exists', return_value=True):
                    with patch('wazuh.core.cluster.cluster.listdir',
                               return_value=["c-internal.sock", "other_file.txt"]):
                        with patch('wazuh.core.cluster.cluster.rmtree', side_effect=Exception):
                            cluster.clean_up("worker1")
                            mock_debug_logger.assert_any_call(f"Removing '{Exception}'.")
                            mock_error_logger.assert_any_call(error_removing)
                            mock_debug_logger.assert_called_with(f"Removed '{Exception}'.")


@patch('wazuh.core.cluster.cluster.listdir', return_value=['005', '006'])
@patch('wazuh.core.cluster.cluster.stat')
def test_merge_info(stat_mock, listdir_mock):
    """Test merge agent info function."""
    stat_mock.return_value.st_mtime = time()
    stat_mock.return_value.st_size = len(agent_groups)

    with patch('builtins.open', mock_open(read_data=agent_groups)) as open_mock:
        files_to_send, output_file = cluster.merge_info('agent-groups', 'worker1', file_type='-shared')
        open_mock.assert_any_call(common.wazuh_path + '/queue/cluster/worker1/agent-groups-shared.merged', 'wb')
        open_mock.assert_any_call(common.wazuh_path + '/queue/agent-groups/005', 'rb')
        open_mock.assert_any_call(common.wazuh_path + '/queue/agent-groups/006', 'rb')

        assert files_to_send == 2
        assert output_file == "queue/cluster/worker1/agent-groups-shared.merged"

        handle = open_mock()
        expected = f'{len(agent_groups)} 005 ' \
                   f'{datetime.utcfromtimestamp(stat_mock.return_value.st_mtime)}\n'.encode() + agent_groups
        handle.write.assert_any_call(expected)

        files_to_send, output_file = cluster.merge_info('agent-groups', 'worker1', files=["one", "two"],
                                                        file_type='-shared')

        assert files_to_send == 0


def test_unmerge_info():
    """Tests unmerge agent info function."""
    agent_info = f"23 005 2019-03-29 14:57:29.610934\n{agent_groups}".encode()

    with patch('builtins.open', mock_open(read_data=agent_info)):
        with patch('wazuh.core.cluster.cluster.stat') as stat_mock:
            # Make sure that the function is running correctly
            stat_mock.return_value.st_size = len(agent_info) - 5
            assert list(cluster.unmerge_info("destination/directory/", "path/file/", "filename")) == [
                ('queue/destination/directory/005', b"b'default,windows-serve", '2019-03-29 14:57:29.610934')]

            # Make sure that the Exception is being properly called
            stat_mock.return_value.st_size = len(agent_info)
            with patch.object(wazuh.core.cluster.cluster.logger, "warning") as mock_logger:
                list(cluster.unmerge_info("destination/directory/", "path/file/", "filename"))
                mock_logger.assert_called_once_with("Malformed file (not enough values to unpack "
                                                    "(expected 3, got 1)). Parsed line: rs'. "
                                                    "Some files won't be synced")
